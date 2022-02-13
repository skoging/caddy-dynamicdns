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
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// App is a Caddy app that keeps your DNS records updated with the public
// IP address of your instance. It updates A and AAAA records.
type App struct {
	// The sources from which to get the server's public IP address.
	// Multiple sources can be specified for redundancy.
	// Default: simple_http
	RecordTargetSourcesRaw []json.RawMessage `json:"ip_sources,omitempty" caddy:"namespace=dynamic_dns.ip_sources inline_key=source"`

	// The configuration for the DNS provider with which the DNS
	// records will be updated.
	DNSProviderRaw json.RawMessage `json:"dns_provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`

	// The record names, keyed by DNS zone, for which to update the A/AAAA records.
	// Record names are relative to the zone. The zone is usually your registered
	// domain name. To refer to the zone itself, use the record name of "@".
	//
	// For example, assuming your zone is example.com, and you want to update A/AAAA
	// records for "example.com" and "www.example.com" so that they resolve to this
	// Caddy instance, configure like so: `"example.com": ["@", "www"]`
	Domains map[string][]string `json:"domains,omitempty"`

	// If enabled, the "http" app's config will be scanned to assemble the list
	// of domains for which to enable dynamic DNS updates.
	DynamicDomains bool `json:"dynamic_domains,omitempty"`

	// The IP versions to enable. By default, both "ipv4" and "ipv6" will be enabled.
	// To disable IPv6, specify {"ipv6": false}.
	Versions IPVersions `json:"versions,omitempty"`

	// How frequently to check the public IP address. Default: 30m
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

	// The TTL to set on DNS records.
	TTL caddy.Duration `json:"ttl,omitempty"`

	targetSources []RecordTargetSource
	dnsProvider   libdns.RecordSetter

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app module.
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger(a)

	// set up the DNS provider module
	if len(a.DNSProviderRaw) == 0 {
		return fmt.Errorf("a DNS provider is required")
	}
	val, err := ctx.LoadModule(a, "DNSProviderRaw")
	if err != nil {
		return fmt.Errorf("loading DNS provider module: %v", err)
	}
	a.dnsProvider = val.(libdns.RecordSetter)

	// set up the IP source module or use a default
	if a.RecordTargetSourcesRaw != nil {
		vals, err := ctx.LoadModule(a, "RecordTargetSourcesRaw")
		if err != nil {
			return fmt.Errorf("loading IP source module: %v", err)
		}
		for _, val := range vals.([]interface{}) {
			a.targetSources = append(a.targetSources, val.(RecordTargetSource))
		}
	}
	if len(a.targetSources) == 0 {
		var sh SimpleHTTP
		if err = sh.Provision(ctx); err != nil {
			return err
		}
		a.targetSources = []RecordTargetSource{sh}
	}

	// make sure a check interval is set
	if a.CheckInterval == 0 {
		a.CheckInterval = caddy.Duration(defaultCheckInterval)
	}
	if time.Duration(a.CheckInterval) < time.Second {
		return fmt.Errorf("check interval must be at least 1 second")
	}

	return nil
}

// Start starts the app module.
func (a App) Start() error {
	go a.checkerLoop()
	return nil
}

// Stop stops the app module.
func (a App) Stop() error {
	return nil
}

// checkerLoop checks the public IP address at every check
// interval. It stops when a.ctx is cancelled.
func (a App) checkerLoop() {
	ticker := time.NewTicker(time.Duration(a.CheckInterval))
	defer ticker.Stop()

	a.checkIPAndUpdateDNS()

	for {
		select {
		case <-ticker.C:
			a.checkIPAndUpdateDNS()
		case <-a.ctx.Done():
			return
		}
	}
}

// checkIPAndUpdateDNS checks public IP addresses and, for any IP addresses
// that are different from before, it updates DNS records accordingly.
func (a App) checkIPAndUpdateDNS() {
	a.logger.Debug("beginning IP address check")

	lastRecordsMu.Lock()
	defer lastRecordsMu.Unlock()

	var err error

	allDomains := a.allDomains()

	// if we don't know current IPs for this domain, look them up from DNS
	if lastRecords == nil {
		lastRecords, err = a.lookupCurrentRecordsFromDNS(allDomains)
		if err != nil {
			// not the end of the world, but might be an extra initial API hit with the DNS provider
			a.logger.Error("unable to lookup current IPs from DNS records", zap.Error(err))
		}
	}

	// look up current address(es) from first successful IP source
	var targets []libdns.Record
	for _, ipSrc := range a.targetSources {
		targets, err = ipSrc.GetTargets(a.ctx, a.Versions)
		if len(targets) == 0 {
			err = fmt.Errorf("no IP addresses returned")
		}
		if err == nil {
			break
		}
		a.logger.Error("looking up IP address",
			zap.String("ip_source", ipSrc.(caddy.Module).CaddyModule().ID.Name()),
			zap.Error(err))
	}

	// make sure the source returns tidy info; duplicates are wasteful
	targets = removeDuplicateRecords(targets)

	// do a simple diff of current and previous IPs to make DNS records to update
	updatedRecsByZone := make(map[string][]libdns.Record)
	for _, record := range targets {
		for zone, domains := range allDomains {
			for _, domain := range domains {
				var currentRecords []libdns.Record
				for _, rec := range lastRecords[zone] {
					if rec.Name == domain && rec.Type == record.Type {
						currentRecords = append(currentRecords, rec)
					}
				}

				if len(currentRecords) > 1 {
					a.logger.Warn("unexpectedly found more than 1 existing record", zap.String("zone", zone), zap.String("name", domain), zap.String("type", record.Type))
					// continue
				}

				var lastRecord libdns.Record
				if len(currentRecords) == 1 {
					lastRecord = currentRecords[0]

					if lastRecord.Value == record.Value {
						continue
					}
				}

				newRecord := libdns.Record{
					ID:    lastRecord.ID,
					Type:  record.Type,
					Name:  domain,
					Value: record.Value,
					TTL:   time.Duration(a.TTL),
				}

				updatedRecsByZone[zone] = append(updatedRecsByZone[zone], newRecord)
			}
		}
	}

	if len(updatedRecsByZone) == 0 {
		a.logger.Debug("no IP address change; no update needed")
		return
	}

	for zone, records := range updatedRecsByZone {
		for _, rec := range records {
			a.logger.Info("updating DNS record",
				zap.String("zone", zone),
				zap.String("type", rec.Type),
				zap.String("name", rec.Name),
				zap.String("value", rec.Value),
				zap.Duration("ttl", rec.TTL),
			)
		}
		newRecs, err := a.dnsProvider.SetRecords(a.ctx, zone, records)
		if err != nil {
			a.logger.Error("failed setting DNS record(s) with new IP address(es)",
				zap.String("zone", zone),
				zap.Error(err),
			)
		}

		for _, newRec := range newRecs {
			if lastRecords[zone] == nil {
				lastRecords[zone] = make(map[string]libdns.Record)
			}

			lastRecords[zone][newRec.ID] = newRec
		}

	}

	a.logger.Info("finished updating DNS")
}

// lookupCurrentRecordsFromDNS looks up the current IP addresses
// from DNS records.
func (a App) lookupCurrentRecordsFromDNS(domains map[string][]string) (map[string]map[string]libdns.Record, error) {

	currentRecords := make(map[string]map[string]libdns.Record)

	if recordGetter, ok := a.dnsProvider.(libdns.RecordGetter); ok {
		for zone, names := range domains {
			recs, err := recordGetter.GetRecords(a.ctx, zone)
			if err != nil {
				return nil, err
			}

			for _, r := range recs {
				if !stringListContains(names, r.Name) {
					continue
				}

				if currentRecords[zone] == nil {
					currentRecords[zone] = make(map[string]libdns.Record)
				}

				currentRecords[zone][r.ID] = r
			}
		}
	}

	return currentRecords, nil
}

func makeRecords(ips []net.IP) []libdns.Record {
	var records []libdns.Record
	for _, ip := range ips {
		records = append(records, libdns.Record{
			Type:  recordType(ip),
			Value: ip.String(),
		})
	}
	return records
}

func (a App) lookupManagedDomains() ([]string, error) {
	cai, err := a.ctx.App("http")
	if err != nil {
		return nil, err
	}
	var hosts []string
	ca := cai.(*caddyhttp.App)
	for _, s := range ca.Servers {
		for _, r := range s.Routes {
			for _, ms := range r.MatcherSets {
				for _, rm := range ms {
					if hs, ok := rm.(caddyhttp.MatchHost); ok {
						for _, h := range hs {
							hosts = append(hosts, h)
						}
					}

				}
			}
		}

	}
	return hosts, nil
}

func (a App) allDomains() map[string][]string {
	if !a.DynamicDomains {
		return a.Domains
	}

	// Read hosts from config.
	m, err := a.lookupManagedDomains()
	if err != nil {
		return a.Domains
	}

	a.logger.Info("Loaded dynamic domains", zap.Strings("domains", m))
	d := make(map[string][]string)
	for zone, domains := range a.Domains {
		d[zone] = domains
		for _, h := range m {
			name, ok := func() (string, bool) {
				if h == zone {
					return "@", true
				}
				suffix := "." + zone
				if n := strings.TrimSuffix(h, suffix); n != h {
					return n, true
				}
				return "", false
			}()
			if !ok {
				// Not in this zone.
				continue
			}
			a.logger.Info("Adding dynamic domain", zap.String("domain", name))
			d[zone] = append(d[zone], name)
		}
	}
	return d
}

// recordType returns the DNS record type associated with the version of ip.
func recordType(ip net.IP) string {
	if ip.To4() == nil {
		return recordTypeAAAA
	}
	return recordTypeA
}

// removeDuplicateRecords returns ips without duplicates.
func removeDuplicateRecords(records []libdns.Record) []libdns.Record {
	var clean []libdns.Record
	for _, record := range records {
		if !recordListContains(clean, record) {
			clean = append(clean, record)
		}
	}
	return clean
}

// recordListContains returns true if list contains ip; false otherwise.
func recordListContains(list []libdns.Record, record libdns.Record) bool {
	for _, recordInList := range list {
		if record.ID != "" && recordInList.ID == record.ID {
			return true
		}

		if recordInList.Value == record.Value && recordInList.Type == record.Type && recordInList.Name == record.Name {
			return true
		}
	}
	return false
}

// ipListContains returns true if list contains ip; false otherwise.
func ipListContains(list []net.IP, ip net.IP) bool {
	for _, ipInList := range list {
		if ipInList.Equal(ip) {
			return true
		}
	}
	return false
}

func stringListContains(list []string, s string) bool {
	for _, val := range list {
		if val == s {
			return true
		}
	}
	return false
}

// IPVersions is the IP versions to enable for dynamic DNS.
// Versions are enabled if true or nil, set to false to disable.
type IPVersions struct {
	IPv4 *bool `json:"ipv4,omitempty"`
	IPv6 *bool `json:"ipv6,omitempty"`
}

// V4Enabled returns true if IPv4 is enabled.
func (ip IPVersions) V4Enabled() bool {
	return ip.IPv4 == nil || *ip.IPv4
}

// V6Enabled returns true if IPv6 is enabled.
func (ip IPVersions) V6Enabled() bool {
	return ip.IPv6 == nil || *ip.IPv6
}

// Remember what the last IPs are so that we
// don't try to update DNS records every
// time a new config is loaded; the IPs are
// unlikely to change very often.
var (
	lastRecords   map[string]map[string]libdns.Record
	lastRecordsMu sync.Mutex

	// Special value indicate there is a new domain to manage.
	nilRecord libdns.Record
)

const (
	recordTypeA    = "A"
	recordTypeAAAA = "AAAA"
)

const defaultCheckInterval = 30 * time.Minute

// Interface guards
var (
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.App         = (*App)(nil)
)
