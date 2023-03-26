// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicdns

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	upnp "gitlab.com/NebulousLabs/go-upnp"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SimpleHTTP{})
	caddy.RegisterModule(UPnP{})
	caddy.RegisterModule(StaticSource{})
}

type RecordTargetSource interface {
	GetTargets(context.Context, IPVersions) ([]libdns.Record, error)
}

// IPSource is a type that can get IP addresses.
type IPSource interface {
	GetIPs(context.Context, IPVersions) ([]net.IP, error)
}

// SimpleHTTP is an IP source that looks up the public IP addresses by
// making HTTP(S) requests to the specified endpoints; it will try each
// endpoint with IPv4 and IPv6 until at least one returns a valid value.
// It is OK if an endpoint doesn't support both IP versions; returning
// a single valid IP address is sufficient.
//
// The endpoints must return HTTP status 200 and the response body must
// contain only the IP address in plain text.
type SimpleHTTP struct {
	// The list of endpoints to query. If empty, a default list will
	// be used:
	//
	// - https://api64.ipify.org
	// - https://myip.addr.space
	// - https://ifconfig.me
	// - https://icanhazip.com
	// - https://ident.me
	// - https://ipecho.net/plain
	Endpoints []string `json:"endpoints,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SimpleHTTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.simple_http",
		New: func() caddy.Module { return new(SimpleHTTP) },
	}
}

func (sh *SimpleHTTP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	var (
		unused   string
		endpoint string
	)
	if !d.AllArgs(&unused, &endpoint) {
		return d.ArgErr()
	}
	sh.Endpoints = append(sh.Endpoints, endpoint)
	return nil
}

// Provision sets up the module.
func (sh *SimpleHTTP) Provision(ctx caddy.Context) error {
	sh.logger = ctx.Logger(sh)
	if len(sh.Endpoints) == 0 {
		sh.Endpoints = defaultHTTPIPServices
	}
	return nil
}

func (sh SimpleHTTP) GetTargets(ctx context.Context, versions IPVersions) ([]libdns.Record, error) {
	var ips, err = sh.GetIPs(ctx, versions)
	return makeRecords(ips), err
}

// GetIPs gets the public addresses of this machine.
func (sh SimpleHTTP) GetIPs(ctx context.Context, versions IPVersions) ([]net.IP, error) {
	out := []net.IP{}

	getForVersion := func(network string, name string) net.IP {
		client := sh.makeClient(network)
		for _, endpoint := range sh.Endpoints {
			ip, err := sh.lookupIP(ctx, client, endpoint)
			if err != nil {
				sh.logger.Debug("lookup failed",
					zap.String("type", name),
					zap.String("endpoint", endpoint),
					zap.Error(err))
				continue
			}
			sh.logger.Debug("lookup",
				zap.String("type", name),
				zap.String("endpoint", endpoint),
				zap.String("ip", ip.String()))
			return ip
		}
		sh.logger.Warn("no IP found; consider disabling this IP version",
			zap.String("type", name))
		return nil
	}

	if versions.V4Enabled() {
		ip := getForVersion("tcp4", "IPv4")
		if ip != nil {
			out = append(out, ip)
		}
	}

	if versions.V6Enabled() {
		ip := getForVersion("tcp6", "IPv6")
		if ip != nil {
			out = append(out, ip)
		}
	}

	return out, nil
}

// makeClient makes an HTTP client that forces use of the specified network type (e.g. "tcp6").
func (SimpleHTTP) makeClient(network string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, address)
			},
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func (SimpleHTTP) lookupIP(ctx context.Context, client *http.Client, endpoint string) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: server response was: %d %s", endpoint, resp.StatusCode, resp.Status)
	}

	ipASCII, err := ioutil.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, err
	}
	ipStr := strings.TrimSpace(string(ipASCII))

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("%s: invalid IP address: %s", endpoint, ipStr)
	}

	return ip, nil
}

var defaultHTTPIPServices = []string{
	"https://api64.ipify.org",
	"https://myip.addr.space",
	"https://ifconfig.me",
	"https://icanhazip.com",
	"https://ident.me",
	"https://ipecho.net/plain",
}

// UPnP gets the IP address from UPnP device.
type UPnP struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (UPnP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.upnp",
		New: func() caddy.Module { return new(UPnP) },
	}
}

func (u *UPnP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Provision sets up the module.
func (u *UPnP) Provision(ctx caddy.Context) error {
	u.logger = ctx.Logger(u)
	return nil
}

func (u UPnP) GetTargets(ctx context.Context, versions IPVersions) ([]libdns.Record, error) {
	var ips, err = u.GetIPs(ctx, versions)
	return makeRecords(ips), err
}

// GetIPs gets the public address(es) of this machine.
// This implementation ignores the configured IP versions, since
// we can't really choose whether we're looking for IPv4 or IPv6
// with UPnP, we just get what we get.
func (u UPnP) GetIPs(ctx context.Context, _ IPVersions) ([]net.IP, error) {
	d, err := upnp.DiscoverCtx(ctx)
	if err != nil {
		return nil, err
	}

	ipStr, err := d.ExternalIP()
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}
	u.logger.Debug("lookup",
		zap.String("ip", ip.String()))

	return []net.IP{ip}, nil
}

type StaticSource struct {
	// The list of endpoints to point to
	Targets []libdns.Record `json:"targets"`
}

func (StaticSource) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.static",
		New: func() caddy.Module { return new(StaticSource) },
	}
}

func (ss *StaticSource) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	var (
		unused  string
		value   string
		dur     string
		dnsType string
	)
	if !d.Args(&unused, &value, &dur) {
		return d.ArgErr()
	}

	ttl, err := caddy.ParseDuration(dur)
	if err != nil {
		return err
	}

	ip := net.ParseIP(value)
	if ip != nil {
		if !d.NextArg() {
			dnsType = recordType(ip)
		} else {
			dnsType = d.Val()
		}
		value = ip.String()
	} else {
		if !d.NextArg() {
			dnsType = "CNAME"
		} else {
			dnsType = d.Val()
		}
	}

	ss.Targets = append(ss.Targets, libdns.Record{
		Type:  dnsType,
		Value: value,
		TTL:   ttl,
	})

	return nil
}

// GetIPs gets the public address(es) of this machine.
func (ss StaticSource) GetTargets(ctx context.Context, _ IPVersions) ([]libdns.Record, error) {
	return ss.Targets, nil
}

// Interface guards
var (
	_ IPSource              = (*SimpleHTTP)(nil)
	_ RecordTargetSource    = (*SimpleHTTP)(nil)
	_ caddy.Provisioner     = (*SimpleHTTP)(nil)
	_ caddyfile.Unmarshaler = (*SimpleHTTP)(nil)

	_ IPSource              = (*UPnP)(nil)
	_ RecordTargetSource    = (*UPnP)(nil)
	_ caddy.Provisioner     = (*UPnP)(nil)
	_ caddyfile.Unmarshaler = (*UPnP)(nil)

	_ RecordTargetSource    = (*StaticSource)(nil)
	_ caddyfile.Unmarshaler = (*StaticSource)(nil)
)
