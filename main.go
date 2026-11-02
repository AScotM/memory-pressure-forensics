package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Metric struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit,omitempty"`
}
type PSIRecord struct {
	Avg10  float64 `json:"avg10"`
	Avg60  float64 `json:"avg60"`
	Avg300 float64 `json:"avg300"`
	Total  uint64  `json:"total_us"`
}
type PSI struct {
	Some      PSIRecord `json:"some"`
	Full      PSIRecord `json:"full"`
	Available bool      `json:"available"`
}
type Process struct {
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	RSSKB    uint64 `json:"rss_kb"`
	SwapKB   uint64 `json:"swap_kb"`
	VMKB     uint64 `json:"vm_kb"`
	OOMScore int    `json:"oom_score"`
	OOMAdj   int    `json:"oom_score_adj"`
}
type Cgroup struct {
	Path        string            `json:"path"`
	Current     uint64            `json:"current_bytes"`
	Peak        uint64            `json:"peak_bytes,omitempty"`
	Max         string            `json:"max"`
	High        string            `json:"high"`
	SwapCurrent uint64            `json:"swap_current_bytes"`
	SwapMax     string            `json:"swap_max"`
	Events      map[string]uint64 `json:"events"`
	LocalEvents map[string]uint64 `json:"events_local,omitempty"`
	Stat        map[string]uint64 `json:"stat"`
	PSI         PSI               `json:"psi"`
	Error       string            `json:"error,omitempty"`
}
type NUMANode struct {
	Name     string            `json:"name"`
	Mem      map[string]uint64 `json:"mem_kb"`
	VM       map[string]uint64 `json:"vmstat"`
	Distance []int             `json:"distance,omitempty"`
}
type Zone struct {
	Node      string            `json:"node"`
	Name      string            `json:"name"`
	FreePages map[string]uint64 `json:"free_pages_by_order"`
}
type Finding struct {
	Severity string  `json:"severity"`
	Code     string  `json:"code"`
	Message  string  `json:"message"`
	Value    float64 `json:"value,omitempty"`
}
type Snapshot struct {
	Time      time.Time         `json:"time"`
	Host      string            `json:"host"`
	Kernel    string            `json:"kernel"`
	Mem       map[string]uint64 `json:"meminfo_kb"`
	VM        map[string]uint64 `json:"vmstat"`
	PSI       PSI               `json:"psi"`
	Processes []Process         `json:"processes,omitempty"`
	Cgroups   []Cgroup          `json:"cgroups,omitempty"`
	NUMA      []NUMANode        `json:"numa,omitempty"`
	Zones     []Zone            `json:"zones,omitempty"`
	Findings  []Finding         `json:"findings"`
	Errors    []string          `json:"errors,omitempty"`
}
type Delta struct {
	Start          time.Time          `json:"start"`
	End            time.Time          `json:"end"`
	Seconds        float64            `json:"seconds"`
	Counters       map[string]uint64  `json:"counter_deltas"`
	Rates          map[string]float64 `json:"rates_per_second"`
	PSISomeDeltaUS uint64             `json:"psi_some_delta_us"`
	PSIFullDeltaUS uint64             `json:"psi_full_delta_us"`
	Findings       []Finding          `json:"findings"`
}
type Report struct {
	Version   string             `json:"version"`
	Generated time.Time          `json:"generated"`
	Samples   []Snapshot         `json:"samples"`
	Deltas    []Delta            `json:"deltas,omitempty"`
	Findings  []Finding          `json:"findings"`
	Summary   map[string]float64 `json:"summary,omitempty"`
}
type Options struct {
	Proc             string
	Sys              string
	CgroupRoot       string
	Interval         time.Duration
	Count            int
	Top              int
	Format           string
	Output           string
	IncludeProcesses bool
	IncludeCgroups   bool
	IncludeNUMA      bool
	IncludeZones     bool
	CgroupDepth      int
	CgroupLimit      int
	WarnPSI          float64
	CritPSI          float64
	WarnAvail        float64
	CritAvail        float64
	WarnSwap         float64
	CritSwap         float64
	Strict           bool
	Quiet            bool
}

func read(path string) (string, error) { b, e := os.ReadFile(path); return string(b), e }
func number(s string) uint64           { v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64); return v }
func signed(s string) int              { v, _ := strconv.Atoi(strings.TrimSpace(s)); return v }
func numericMap(path string) (map[string]uint64, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	m := map[string]uint64{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4*1024*1024)
	for sc.Scan() {
		a := strings.Fields(strings.ReplaceAll(sc.Text(), ":", ""))
		if len(a) >= 2 {
			if v, e := strconv.ParseUint(a[1], 10, 64); e == nil {
				m[a[0]] = v
			}
		}
	}
	return m, sc.Err()
}
func meminfo(path string) (map[string]uint64, error) { return numericMap(path) }
func psiRecord(line string) PSIRecord {
	r := PSIRecord{}
	for _, f := range strings.Fields(line)[1:] {
		p := strings.SplitN(f, "=", 2)
		if len(p) != 2 {
			continue
		}
		switch p[0] {
		case "avg10":
			r.Avg10, _ = strconv.ParseFloat(p[1], 64)
		case "avg60":
			r.Avg60, _ = strconv.ParseFloat(p[1], 64)
		case "avg300":
			r.Avg300, _ = strconv.ParseFloat(p[1], 64)
		case "total":
			r.Total = number(p[1])
		}
	}
	return r
}
func parsePSI(path string) (PSI, error) {
	s, e := read(path)
	if e != nil {
		return PSI{}, e
	}
	p := PSI{Available: true}
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "some ") {
			p.Some = psiRecord(l)
		}
		if strings.HasPrefix(l, "full ") {
			p.Full = psiRecord(l)
		}
	}
	return p, nil
}
func firstLine(path string) string {
	s, e := read(path)
	if e != nil {
		return ""
	}
	return strings.TrimSpace(s)
}
func hostname() string { h, _ := os.Hostname(); return h }
func kernel(proc string) string {
	s := firstLine(filepath.Join(proc, "sys/kernel/osrelease"))
	if s != "" {
		return s
	}
	return runtime.GOOS
}
func processInfo(proc string, pid int) (Process, error) {
	dir := filepath.Join(proc, strconv.Itoa(pid))
	m, e := numericMap(filepath.Join(dir, "status"))
	if e != nil {
		return Process{}, e
	}
	p := Process{PID: pid, Name: firstLine(filepath.Join(dir, "comm")), RSSKB: m["VmRSS"], SwapKB: m["VmSwap"], VMKB: m["VmSize"], OOMScore: signed(firstLine(filepath.Join(dir, "oom_score"))), OOMAdj: signed(firstLine(filepath.Join(dir, "oom_score_adj")))}
	return p, nil
}
func processes(proc string, top int) ([]Process, error) {
	entries, e := os.ReadDir(proc)
	if e != nil {
		return nil, e
	}
	out := []Process{}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || !entry.IsDir() {
			continue
		}
		p, e := processInfo(proc, pid)
		if e == nil {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RSSKB == out[j].RSSKB {
			return out[i].PID < out[j].PID
		}
		return out[i].RSSKB > out[j].RSSKB
	})
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return out, nil
}
func cgNum(path string) uint64 { return number(firstLine(path)) }
func cgRead(path string) map[string]uint64 {
	m, e := numericMap(path)
	if e != nil {
		return map[string]uint64{}
	}
	return m
}
func readCgroup(dir string) Cgroup {
	c := Cgroup{Path: dir, Events: cgRead(filepath.Join(dir, "memory.events")), LocalEvents: cgRead(filepath.Join(dir, "memory.events.local")), Stat: cgRead(filepath.Join(dir, "memory.stat")), Current: cgNum(filepath.Join(dir, "memory.current")), Peak: cgNum(filepath.Join(dir, "memory.peak")), Max: firstLine(filepath.Join(dir, "memory.max")), High: firstLine(filepath.Join(dir, "memory.high")), SwapCurrent: cgNum(filepath.Join(dir, "memory.swap.current")), SwapMax: firstLine(filepath.Join(dir, "memory.swap.max"))}
	c.PSI, _ = parsePSI(filepath.Join(dir, "memory.pressure"))
	return c
}
func cgroups(root string, depth, limit int) ([]Cgroup, error) {
	if _, e := os.Stat(filepath.Join(root, "cgroup.controllers")); e != nil {
		return nil, fmt.Errorf("cgroup v2 not found at %s: %w", root, e)
	}
	out := []Cgroup{}
	var walk func(string, int)
	walk = func(dir string, d int) {
		if len(out) >= limit {
			return
		}
		out = append(out, readCgroup(dir))
		if d >= depth {
			return
		}
		entries, e := os.ReadDir(dir)
		if e != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() && !entry.Type().IsRegular() {
				walk(filepath.Join(dir, entry.Name()), d+1)
				if len(out) >= limit {
					return
				}
			}
		}
	}
	walk(root, 0)
	return out, nil
}
func numa(sys string) ([]NUMANode, error) {
	root := filepath.Join(sys, "devices/system/node")
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, e
	}
	out := []NUMANode{}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "node") {
			continue
		}
		if _, e := strconv.Atoi(strings.TrimPrefix(entry.Name(), "node")); e != nil {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		n := NUMANode{Name: entry.Name(), Mem: map[string]uint64{}, VM: cgRead(filepath.Join(dir, "vmstat"))}
		s, _ := read(filepath.Join(dir, "meminfo"))
		for _, line := range strings.Split(s, "\n") {
			fields := strings.Fields(strings.ReplaceAll(line, ":", ""))
			if len(fields) >= 4 && fields[0] == "Node" {
				n.Mem[fields[2]] = number(fields[3])
			}
		}
		for _, v := range strings.Fields(firstLine(filepath.Join(dir, "distance"))) {
			n.Distance = append(n.Distance, signed(v))
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func buddyZones(proc string) ([]Zone, error) {
	s, e := read(filepath.Join(proc, "buddyinfo"))
	if e != nil {
		return nil, e
	}
	out := []Zone{}
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(strings.ReplaceAll(line, ",", ""))
		if len(fields) < 5 || fields[0] != "Node" || fields[2] != "zone" {
			continue
		}
		z := Zone{Node: fields[1], Name: fields[3], FreePages: map[string]uint64{}}
		for i, v := range fields[4:] {
			z.FreePages[fmt.Sprintf("order_%d", i)] = number(v)
		}
		out = append(out, z)
	}
	return out, nil
}
func addFinding(dst *[]Finding, sev, code, msg string, val float64) {
	*dst = append(*dst, Finding{Severity: sev, Code: code, Message: msg, Value: val})
}
func ratio(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}
func assess(s *Snapshot, o Options) {
	if s.PSI.Available {
		v := s.PSI.Some.Avg10
		if v >= o.CritPSI {
			addFinding(&s.Findings, "critical", "psi_some", "Sustained memory PSI some stalls", v)
		} else if v >= o.WarnPSI {
			addFinding(&s.Findings, "warning", "psi_some", "Elevated memory PSI some stalls", v)
		}
		v = s.PSI.Full.Avg10
		if v >= o.CritPSI/2 {
			addFinding(&s.Findings, "critical", "psi_full", "Severe simultaneous memory stalls", v)
		} else if v >= o.WarnPSI/2 {
			addFinding(&s.Findings, "warning", "psi_full", "Simultaneous memory stalls", v)
		}
	}
	total := s.Mem["MemTotal"]
	avail := s.Mem["MemAvailable"]
	if total > 0 {
		v := ratio(avail, total)
		if v <= o.CritAvail {
			addFinding(&s.Findings, "critical", "low_available", "Critically low available memory percentage", v)
		} else if v <= o.WarnAvail {
			addFinding(&s.Findings, "warning", "low_available", "Low available memory percentage", v)
		}
	}
	if t := s.Mem["SwapTotal"]; t > 0 {
		v := ratio(saturatingSub(t, s.Mem["SwapFree"]), t)
		if v >= o.CritSwap {
			addFinding(&s.Findings, "critical", "swap_usage", "Very high swap utilization", v)
		} else if v >= o.WarnSwap {
			addFinding(&s.Findings, "warning", "swap_usage", "High swap utilization", v)
		}
	}
	for _, c := range s.Cgroups {
		if c.Events["oom_kill"] > 0 {
			addFinding(&s.Findings, "info", "cgroup_oom_history", "Cgroup reports cumulative OOM kills: "+c.Path, float64(c.Events["oom_kill"]))
		}
		if c.Max != "" && c.Max != "max" {
			max := number(c.Max)
			if max > 0 && ratio(c.Current, max) > 90 {
				addFinding(&s.Findings, "warning", "cgroup_limit", "Cgroup memory usage near hard limit: "+c.Path, ratio(c.Current, max))
			}
		}
	}
	if len(s.Findings) == 0 {
		addFinding(&s.Findings, "info", "no_threshold_breach", "No configured instantaneous thresholds exceeded", 0)
	}
}
func saturatingSub(a, b uint64) uint64 {
	if b >= a {
		return 0
	}
	return a - b
}
func collect(o Options) Snapshot {
	s := Snapshot{Time: time.Now(), Host: hostname(), Kernel: kernel(o.Proc), Mem: map[string]uint64{}, VM: map[string]uint64{}, Findings: []Finding{}, Errors: []string{}}
	var e error
	s.Mem, e = meminfo(filepath.Join(o.Proc, "meminfo"))
	if e != nil {
		s.Errors = append(s.Errors, "meminfo: "+e.Error())
		s.Mem = map[string]uint64{}
	}
	s.VM, e = numericMap(filepath.Join(o.Proc, "vmstat"))
	if e != nil {
		s.Errors = append(s.Errors, "vmstat: "+e.Error())
		s.VM = map[string]uint64{}
	}
	s.PSI, e = parsePSI(filepath.Join(o.Proc, "pressure/memory"))
	if e != nil {
		s.Errors = append(s.Errors, "psi: "+e.Error())
	}
	if o.IncludeProcesses {
		s.Processes, e = processes(o.Proc, o.Top)
		if e != nil {
			s.Errors = append(s.Errors, "processes: "+e.Error())
		}
	}
	if o.IncludeCgroups {
		s.Cgroups, e = cgroups(o.CgroupRoot, o.CgroupDepth, o.CgroupLimit)
		if e != nil {
			s.Errors = append(s.Errors, "cgroups: "+e.Error())
		}
	}
	if o.IncludeNUMA {
		s.NUMA, e = numa(o.Sys)
		if e != nil {
			s.Errors = append(s.Errors, "numa: "+e.Error())
		}
	}
	if o.IncludeZones {
		s.Zones, e = buddyZones(o.Proc)
		if e != nil {
			s.Errors = append(s.Errors, "buddyinfo: "+e.Error())
		}
	}
	assess(&s, o)
	return s
}

var tracked = []string{"pgfault", "pgmajfault", "pswpin", "pswpout", "pgscan_kswapd", "pgscan_direct", "pgsteal_kswapd", "pgsteal_direct", "allocstall", "allocstall_dma", "allocstall_dma32", "allocstall_normal", "oom_kill", "compact_stall", "compact_fail", "compact_success", "workingset_refault_file", "workingset_refault_anon", "pgactivate", "pgdeactivate", "pgfree", "pgscan_file", "pgscan_anon", "pgsteal_file", "pgsteal_anon"}

func delta(a, b Snapshot) Delta {
	secs := b.Time.Sub(a.Time).Seconds()
	d := Delta{Start: a.Time, End: b.Time, Seconds: secs, Counters: map[string]uint64{}, Rates: map[string]float64{}, Findings: []Finding{}}
	if secs <= 0 {
		return d
	}
	for _, k := range tracked {
		av, okA := a.VM[k]
		bv, okB := b.VM[k]
		if !okA || !okB || bv < av {
			continue
		}
		diff := bv - av
		d.Counters[k] = diff
		d.Rates[k] = float64(diff) / secs
	}
	if b.PSI.Some.Total >= a.PSI.Some.Total {
		d.PSISomeDeltaUS = b.PSI.Some.Total - a.PSI.Some.Total
	}
	if b.PSI.Full.Total >= a.PSI.Full.Total {
		d.PSIFullDeltaUS = b.PSI.Full.Total - a.PSI.Full.Total
	}
	if v := d.Counters["oom_kill"]; v > 0 {
		addFinding(&d.Findings, "critical", "new_oom_kills", "OOM kills observed between samples", float64(v))
	}
	if v := d.Rates["pgmajfault"]; v > 100 {
		addFinding(&d.Findings, "warning", "major_fault_rate", "High major page fault rate", v)
	}
	if v := d.Rates["pswpout"]; v > 100 {
		addFinding(&d.Findings, "warning", "swap_out_rate", "High swap-out activity in pages per second", v)
	}
	if v := d.Rates["pgscan_direct"]; v > 1000 {
		addFinding(&d.Findings, "warning", "direct_reclaim", "High direct reclaim scanning rate", v)
	}
	if v := float64(d.PSIFullDeltaUS) / (secs * 1e6) * 100; v > 10 {
		addFinding(&d.Findings, "critical", "interval_full_stall", "High full memory stall fraction during sample interval", v)
	}
	return d
}
func summary(r *Report) {
	r.Summary = map[string]float64{}
	if len(r.Samples) == 0 {
		return
	}
	last := r.Samples[len(r.Samples)-1]
	r.Summary["memory_available_percent"] = ratio(last.Mem["MemAvailable"], last.Mem["MemTotal"])
	r.Summary["memory_used_estimate_kb"] = float64(saturatingSub(last.Mem["MemTotal"], last.Mem["MemAvailable"]))
	r.Summary["psi_some_avg10"] = last.PSI.Some.Avg10
	r.Summary["psi_full_avg10"] = last.PSI.Full.Avg10
	r.Summary["swap_used_kb"] = float64(saturatingSub(last.Mem["SwapTotal"], last.Mem["SwapFree"]))
	for _, d := range r.Deltas {
		for k, v := range d.Rates {
			r.Summary["latest_rate_"+k] = v
		}
	}
	seen := map[string]bool{}
	for _, s := range r.Samples {
		for _, f := range s.Findings {
			key := f.Severity + ":" + f.Code
			if !seen[key] {
				r.Findings = append(r.Findings, f)
				seen[key] = true
			}
		}
	}
	for _, d := range r.Deltas {
		for _, f := range d.Findings {
			key := f.Severity + ":" + f.Code
			if !seen[key] {
				r.Findings = append(r.Findings, f)
				seen[key] = true
			}
		}
	}
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].Code < r.Findings[j].Code })
}
func humanKB(v uint64) string {
	f := float64(v) * 1024
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", f, units[i])
}
func renderText(w io.Writer, r Report) {
	fmt.Fprintf(w, "MEMORY PRESSURE FORENSICS v%s\nGenerated: %s\nSamples: %d\n\n", r.Version, r.Generated.Format(time.RFC3339), len(r.Samples))
	for i, s := range r.Samples {
		fmt.Fprintf(w, "SAMPLE %d %s host=%s kernel=%s\n", i+1, s.Time.Format(time.RFC3339), s.Host, s.Kernel)
		for _, k := range []string{"MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached", "SReclaimable", "Shmem", "AnonPages", "Mapped", "Unevictable", "Dirty", "Writeback", "SwapTotal", "SwapFree", "Slab", "SUnreclaim", "PageTables", "Committed_AS", "CommitLimit", "HugePages_Total", "HugePages_Free"} {
			if v, ok := s.Mem[k]; ok {
				if strings.HasPrefix(k, "HugePages_") {
					fmt.Fprintf(w, "  %-23s %d\n", k, v)
				} else {
					fmt.Fprintf(w, "  %-23s %s\n", k, humanKB(v))
				}
			}
		}
		if s.PSI.Available {
			fmt.Fprintf(w, "  PSI some avg10/60/300   %.2f / %.2f / %.2f%%\n", s.PSI.Some.Avg10, s.PSI.Some.Avg60, s.PSI.Some.Avg300)
			fmt.Fprintf(w, "  PSI full avg10/60/300   %.2f / %.2f / %.2f%%\n", s.PSI.Full.Avg10, s.PSI.Full.Avg60, s.PSI.Full.Avg300)
		}
		if len(s.Processes) > 0 {
			fmt.Fprintln(w, "  TOP PROCESSES BY RSS")
			for _, p := range s.Processes {
				fmt.Fprintf(w, "    pid=%-7d rss=%-12s swap=%-12s oom=%-5d %s\n", p.PID, humanKB(p.RSSKB), humanKB(p.SwapKB), p.OOMScore, p.Name)
			}
		}
		if len(s.Cgroups) > 0 {
			fmt.Fprintf(w, "  CGROUPS (%d)\n", len(s.Cgroups))
			for _, c := range s.Cgroups {
				fmt.Fprintf(w, "    %s current=%s max=%s oom_kill=%d\n", c.Path, humanKB(c.Current/1024), c.Max, c.Events["oom_kill"])
			}
		}
		if len(s.NUMA) > 0 {
			fmt.Fprintln(w, "  NUMA")
			for _, n := range s.NUMA {
				fmt.Fprintf(w, "    %s free=%s total=%s\n", n.Name, humanKB(n.Mem["MemFree"]), humanKB(n.Mem["MemTotal"]))
			}
		}
		if len(s.Zones) > 0 {
			fmt.Fprintln(w, "  BUDDY ZONES")
			for _, z := range s.Zones {
				fmt.Fprintf(w, "    node=%s zone=%s order0=%d order9=%d\n", z.Node, z.Name, z.FreePages["order_0"], z.FreePages["order_9"])
			}
		}
		for _, f := range s.Findings {
			fmt.Fprintf(w, "  [%s] %s: %s (%.2f)\n", strings.ToUpper(f.Severity), f.Code, f.Message, f.Value)
		}
		for _, e := range s.Errors {
			fmt.Fprintf(w, "  [READ ERROR] %s\n", e)
		}
		fmt.Fprintln(w)
	}
	for i, d := range r.Deltas {
		fmt.Fprintf(w, "INTERVAL %d %.2fs psi_some=%.2f%% psi_full=%.2f%%\n", i+1, d.Seconds, float64(d.PSISomeDeltaUS)/math.Max(d.Seconds*1e6, 1)*100, float64(d.PSIFullDeltaUS)/math.Max(d.Seconds*1e6, 1)*100)
		keys := make([]string, 0, len(d.Rates))
		for k := range d.Rates {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %-30s %12.2f /s (%d total)\n", k, d.Rates[k], d.Counters[k])
		}
		for _, f := range d.Findings {
			fmt.Fprintf(w, "  [%s] %s: %s\n", strings.ToUpper(f.Severity), f.Code, f.Message)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "CONSOLIDATED FINDINGS")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  [%s] %s: %s\n", strings.ToUpper(f.Severity), f.Code, f.Message)
	}
}
func renderCSV(w io.Writer, r Report) error {
	cw := csv.NewWriter(w)
	if e := cw.Write([]string{"timestamp", "host", "mem_total_kb", "mem_available_kb", "swap_used_kb", "psi_some_avg10", "psi_full_avg10", "pgmajfault", "pswpin", "pswpout", "oom_kill", "findings"}); e != nil {
		return e
	}
	for _, s := range r.Samples {
		row := []string{s.Time.Format(time.RFC3339Nano), s.Host, strconv.FormatUint(s.Mem["MemTotal"], 10), strconv.FormatUint(s.Mem["MemAvailable"], 10), strconv.FormatUint(saturatingSub(s.Mem["SwapTotal"], s.Mem["SwapFree"]), 10), strconv.FormatFloat(s.PSI.Some.Avg10, 'f', 3, 64), strconv.FormatFloat(s.PSI.Full.Avg10, 'f', 3, 64), strconv.FormatUint(s.VM["pgmajfault"], 10), strconv.FormatUint(s.VM["pswpin"], 10), strconv.FormatUint(s.VM["pswpout"], 10), strconv.FormatUint(s.VM["oom_kill"], 10), strconv.Itoa(len(s.Findings))}
		if e := cw.Write(row); e != nil {
			return e
		}
	}
	cw.Flush()
	return cw.Error()
}
func run(ctx context.Context, o Options) (Report, error) {
	r := Report{Version: "1.0.0", Generated: time.Now(), Samples: []Snapshot{}, Deltas: []Delta{}, Findings: []Finding{}}
	for i := 0; i < o.Count; i++ {
		if ctx.Err() != nil {
			break
		}
		s := collect(o)
		if o.Strict && len(s.Errors) > 0 {
			return r, errors.New(strings.Join(s.Errors, "; "))
		}
		if len(r.Samples) > 0 {
			r.Deltas = append(r.Deltas, delta(r.Samples[len(r.Samples)-1], s))
		}
		r.Samples = append(r.Samples, s)
		if i+1 < o.Count {
			timer := time.NewTimer(o.Interval)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
			case <-timer.C:
			}
		}
	}
	summary(&r)
	return r, nil
}
func main() {
	o := Options{}
	flag.StringVar(&o.Proc, "proc", "/proc", "procfs mount path")
	flag.StringVar(&o.Sys, "sys", "/sys", "sysfs mount path")
	flag.StringVar(&o.CgroupRoot, "cgroup-root", "/sys/fs/cgroup", "cgroup v2 root")
	flag.DurationVar(&o.Interval, "interval", 2*time.Second, "sampling interval")
	flag.IntVar(&o.Count, "count", 1, "number of snapshots")
	flag.IntVar(&o.Top, "top", 10, "number of processes to show")
	flag.StringVar(&o.Format, "format", "text", "output format: text, json, csv")
	flag.StringVar(&o.Output, "output", "-", "output file or - for stdout")
	flag.BoolVar(&o.IncludeProcesses, "processes", true, "include process ranking")
	flag.BoolVar(&o.IncludeCgroups, "cgroups", true, "include cgroup v2 data")
	flag.BoolVar(&o.IncludeNUMA, "numa", true, "include NUMA nodes")
	flag.BoolVar(&o.IncludeZones, "zones", true, "include buddy allocator zones")
	flag.IntVar(&o.CgroupDepth, "cgroup-depth", 2, "maximum cgroup recursion depth")
	flag.IntVar(&o.CgroupLimit, "cgroup-limit", 100, "maximum cgroups")
	flag.Float64Var(&o.WarnPSI, "warn-psi", 10, "warning PSI some avg10 percentage")
	flag.Float64Var(&o.CritPSI, "crit-psi", 30, "critical PSI some avg10 percentage")
	flag.Float64Var(&o.WarnAvail, "warn-available", 15, "warning available memory percentage")
	flag.Float64Var(&o.CritAvail, "crit-available", 5, "critical available memory percentage")
	flag.Float64Var(&o.WarnSwap, "warn-swap", 70, "warning swap utilization percentage")
	flag.Float64Var(&o.CritSwap, "crit-swap", 90, "critical swap utilization percentage")
	flag.BoolVar(&o.Strict, "strict", false, "fail on unavailable diagnostic files")
	flag.BoolVar(&o.Quiet, "quiet", false, "suppress stderr messages")
	flag.Parse()
	if o.Count < 1 || o.Count > 100000 || o.Interval <= 0 || o.Top < 0 || o.CgroupDepth < 0 || o.CgroupLimit < 1 || o.WarnPSI < 0 || o.CritPSI <= o.WarnPSI || o.WarnAvail < o.CritAvail || o.CritAvail < 0 || o.WarnSwap > o.CritSwap || o.WarnSwap < 0 || o.CritSwap > 100 {
		fmt.Fprintln(os.Stderr, "invalid sampling or threshold options")
		os.Exit(2)
	}
	if o.Format != "text" && o.Format != "json" && o.Format != "csv" {
		fmt.Fprintln(os.Stderr, "format must be text, json or csv")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r, e := run(ctx, o)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	var w io.Writer = os.Stdout
	if o.Output != "-" {
		f, e := os.Create(o.Output)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}
	switch o.Format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		e = enc.Encode(r)
	case "csv":
		e = renderCSV(w, r)
	default:
		renderText(w, r)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
