// ============================================================
//
//	OLatency — Latency + Jitter Monitor (TCP RTT / DNS)
//	Author  : khaled.s.haddad
//	Website : owlsec.org
//	Language: Go (stdlib only, CGO disabled, static build) — OWL suite
//
//	Measure round-trip latency with the TCP handshake, DNS
//	resolution latency, and compare two targets head-to-head.
//	Live sparkline, jitter (mean successive difference), mdev,
//	standard deviation and loss — all from the standard library.
//
// ============================================================
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func header(title string) {
	fmt.Println()
	rule()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const BANNER = `
 ██████╗ ██╗      █████╗ ████████╗███████╗███╗   ██╗ ██████╗██╗   ██╗
██╔═══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝████╗  ██║██╔════╝╚██╗ ██╔╝
██║   ██║██║     ███████║   ██║   █████╗  ██╔██╗ ██║██║      ╚████╔╝
██║   ██║██║     ██╔══██║   ██║   ██╔══╝  ██║╚██╗██║██║       ╚██╔╝
╚██████╔╝███████╗██║  ██║   ██║   ███████╗██║ ╚████║╚██████╗   ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝   ╚═╝
`

const (
	APPNAME = "OLatency"
	SUITE   = "Owl Network Suite"
	SUBLINE = "TCP RTT · HTTP TTFB · DNS · Jitter · Loss · Compare · Multi-target · Export · SLA"
	VERSION = "1.1"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

func sparkline(vals []float64) string {
	if len(vals) == 0 {
		return ""
	}
	mn, mx := vals[0], vals[0]
	for _, v := range vals {
		if v < mn {
			mn = v
		}
		if v > mx {
			mx = v
		}
	}
	var b strings.Builder
	rng := mx - mn
	for _, v := range vals {
		idx := 0
		if rng > 0 {
			idx = int((v - mn) / rng * float64(len(sparkRunes)-1))
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkRunes) {
			idx = len(sparkRunes) - 1
		}
		b.WriteRune(sparkRunes[idx])
	}
	return b.String()
}

// tcpRTT returns handshake time in ms; a "connection refused" still proves the
// host is reachable (the packet round-tripped), so it counts as a timed sample.
func tcpRTT(addr string, timeout time.Duration) (float64, bool) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	rtt := float64(time.Since(start).Microseconds()) / 1000.0
	if err == nil {
		c.Close()
		return rtt, true
	}
	if strings.Contains(err.Error(), "refused") {
		return rtt, true
	}
	return 0, false
}

type stats struct {
	min, max, mean, std, jitter, loss, mdev, p95 float64
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := p / 100 * float64(len(sorted)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if hi >= len(sorted) {
		hi = len(sorted) - 1
	}
	frac := rank - float64(lo)
	return sorted[lo] + (sorted[hi]-sorted[lo])*frac
}

func calcStats(samples []float64, total int) stats {
	var s stats
	if len(samples) == 0 {
		s.loss = 100
		return s
	}
	s.min, s.max = samples[0], samples[0]
	sum := 0.0
	for _, v := range samples {
		if v < s.min {
			s.min = v
		}
		if v > s.max {
			s.max = v
		}
		sum += v
	}
	s.mean = sum / float64(len(samples))
	var vs, md float64
	for _, v := range samples {
		vs += (v - s.mean) * (v - s.mean)
		md += math.Abs(v - s.mean)
	}
	s.std = math.Sqrt(vs / float64(len(samples)))
	s.mdev = md / float64(len(samples))
	for i := 1; i < len(samples); i++ {
		s.jitter += math.Abs(samples[i] - samples[i-1])
	}
	if len(samples) > 1 {
		s.jitter /= float64(len(samples) - 1)
	}
	if total > 0 {
		s.loss = 100 * float64(total-len(samples)) / float64(total)
	}
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)
	s.p95 = percentile(sorted, 95)
	return s
}

func parseHostPort(in, defPort string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(in); err == nil {
		return in
	}
	return net.JoinHostPort(in, defPort)
}

func atoiDef(s string, def int) int {
	if v, e := strconv.Atoi(strings.TrimSpace(s)); e == nil && v > 0 {
		return v
	}
	return def
}

func statsTable(s stats, n, ok int) {
	table([]string{"Metric", "Value"}, [][]string{
		{"Samples", fmt.Sprintf("%d / %d ok", ok, n)},
		{"Min", fmt.Sprintf("%.2f ms", s.min)},
		{"Avg", fmt.Sprintf("%.2f ms", s.mean)},
		{"p95", fmt.Sprintf("%.2f ms", s.p95)},
		{"Max", fmt.Sprintf("%.2f ms", s.max)},
		{"Std Dev", fmt.Sprintf("%.2f ms", s.std)},
		{"Mean Dev (mdev)", fmt.Sprintf("%.2f ms", s.mdev)},
		{"Jitter", fmt.Sprintf("%.2f ms", s.jitter)},
		{"Loss", fmt.Sprintf("%.1f %%", s.loss)},
	})
}

// monitor runs the live TCP-RTT loop. interactive controls the sparkline draw.
func monitor(target string, n int, live bool) ([]float64, stats) {
	var samples []float64
	window := []float64{}
	for i := 0; i < n; i++ {
		rtt, ok := tcpRTT(target, 2*time.Second)
		if ok {
			samples = append(samples, rtt)
			window = append(window, rtt)
			if len(window) > 40 {
				window = window[1:]
			}
		}
		if live {
			st := calcStats(samples, i+1)
			cur := "timeout"
			curCol := R
			if ok {
				cur = fmt.Sprintf("%.2fms", rtt)
				curCol = GRN
				if st.mean > 0 && rtt > st.mean*2 {
					curCol = YLW
				}
			}
			fmt.Printf("\r  %s  last:%s avg:%s loss:%s   ",
				col(sparkline(window), CY),
				col(cur, curCol),
				col(fmt.Sprintf("%.2fms", st.mean), W),
				col(fmt.Sprintf("%.0f%%", st.loss), W))
			time.Sleep(250 * time.Millisecond)
		}
	}
	return samples, calcStats(samples, n)
}

// httpTTFB times a single GET: DNS+connect+TLS up to the first response byte.
// Returns total ms to first byte and the HTTP status code.
func httpTTFB(url string, timeout time.Duration) (float64, int, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, 0, err
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	var start time.Time
	var ttfb time.Duration
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { ttfb = time.Since(start) },
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
	client := &http.Client{
		// don't follow redirects: we measure the first endpoint.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	start = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if ttfb == 0 {
		ttfb = time.Since(start)
	}
	return float64(ttfb.Microseconds()) / 1000.0, resp.StatusCode, nil
}

// monitorHTTP probes a URL n times for TTFB and returns the samples + stats.
func monitorHTTP(url string, n int) ([]float64, stats, int) {
	var samples []float64
	lastCode := 0
	for i := 0; i < n; i++ {
		ms, code, err := httpTTFB(url, 5*time.Second)
		if err == nil {
			samples = append(samples, ms)
			lastCode = code
		}
	}
	return samples, calcStats(samples, n), lastCode
}

// targetResult holds one target's outcome in a multi-target run.
type targetResult struct {
	target string
	st     stats
	ok     int
	n      int
}

// multiTarget probes several TCP targets concurrently and ranks them by avg RTT.
func multiTarget(targets []string, n int) []targetResult {
	results := make([]targetResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, addr string) {
			defer wg.Done()
			var samples []float64
			for k := 0; k < n; k++ {
				if r, ok := tcpRTT(addr, 2*time.Second); ok {
					samples = append(samples, r)
				}
			}
			results[idx] = targetResult{target: addr, st: calcStats(samples, n), ok: len(samples), n: n}
		}(i, t)
	}
	wg.Wait()
	rankResults(results)
	return results
}

// rankResults sorts targets fastest-first; unreachable (no samples) sink last.
func rankResults(rs []targetResult) {
	sort.SliceStable(rs, func(i, j int) bool {
		if (rs[i].ok == 0) != (rs[j].ok == 0) {
			return rs[j].ok == 0 // reachable before unreachable
		}
		return rs[i].st.mean < rs[j].st.mean
	})
}

// exportSamples writes the per-sample series + summary to CSV or JSON by extension.
func exportSamples(path, label string, samples []float64, st stats) error {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".json") {
		payload := map[string]interface{}{
			"tool":    APPNAME,
			"version": VERSION,
			"target":  label,
			"samples": samples,
			"stats": map[string]float64{
				"min": st.min, "avg": st.mean, "p95": st.p95, "max": st.max,
				"std": st.std, "mdev": st.mdev, "jitter": st.jitter, "loss": st.loss,
			},
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(path, append(b, '\n'), 0644)
	}
	// default: CSV.
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"index", "target", "rtt_ms"})
	for i, v := range samples {
		w.Write([]string{strconv.Itoa(i + 1), label, fmt.Sprintf("%.3f", v)})
	}
	w.Write([]string{})
	w.Write([]string{"metric", "value"})
	for _, kv := range [][2]string{
		{"min", fmt.Sprintf("%.3f", st.min)}, {"avg", fmt.Sprintf("%.3f", st.mean)},
		{"p95", fmt.Sprintf("%.3f", st.p95)}, {"max", fmt.Sprintf("%.3f", st.max)},
		{"jitter", fmt.Sprintf("%.3f", st.jitter)}, {"loss_pct", fmt.Sprintf("%.1f", st.loss)},
	} {
		w.Write([]string{kv[0], kv[1]})
	}
	return w.Error()
}

// slaEval checks avg/loss against thresholds; returns (ok, reasons). A threshold
// <= 0 is ignored.
func slaEval(st stats, maxAvg, maxLoss float64) (bool, []string) {
	var reasons []string
	ok := true
	if maxAvg > 0 && st.mean > maxAvg {
		ok = false
		reasons = append(reasons, fmt.Sprintf("avg %.2fms > %.2fms", st.mean, maxAvg))
	}
	if maxLoss > 0 && st.loss > maxLoss {
		ok = false
		reasons = append(reasons, fmt.Sprintf("loss %.1f%% > %.1f%%", st.loss, maxLoss))
	}
	return ok, reasons
}

// ---------------------------------------------------------------------------
// Interactive handlers
// ---------------------------------------------------------------------------

func doMonitor() {
	clear()
	banner()
	header("Live Latency + Jitter Monitor")
	target := parseHostPort(prompt("target host[:port] (default :443)"), "443")
	if target == "" {
		return
	}
	n := atoiDef(prompt("samples (default 30)"), 30)
	clear()
	banner()
	info("Live latency monitor → " + target + "  (TCP handshake RTT)")
	fmt.Println()
	samples, st := monitor(target, n, true)
	fmt.Print("\n\n")
	statsTable(st, n, len(samples))
	maybeExport(target, samples, st)
	pause()
}

func doDNSLatency() {
	clear()
	banner()
	header("DNS Resolution Latency")
	host := prompt("hostname to resolve (e.g. example.com)")
	if host == "" {
		return
	}
	n := atoiDef(prompt("samples (default 10)"), 10)
	clear()
	banner()
	info("DNS resolution latency for " + host)
	fmt.Println()
	var samples []float64
	r := &net.Resolver{}
	for i := 0; i < n; i++ {
		start := time.Now()
		_, err := r.LookupHost(context.Background(), host)
		el := float64(time.Since(start).Microseconds()) / 1000.0
		if err == nil {
			samples = append(samples, el)
			fmt.Printf("  q%2d  %s %.2fms\n", i+1, col("ok", GRN), el)
		} else {
			fmt.Printf("  q%2d  %s %s\n", i+1, col("fail", R), err.Error())
		}
		time.Sleep(150 * time.Millisecond)
	}
	fmt.Println()
	st := calcStats(samples, n)
	statsTable(st, n, len(samples))
	maybeExport(host, samples, st)
	pause()
}

func doCompare() {
	clear()
	banner()
	header("Compare Two Targets Head-to-Head")
	a := parseHostPort(prompt("target A host[:port] (default :443)"), "443")
	b := parseHostPort(prompt("target B host[:port] (default :443)"), "443")
	if a == "" || b == "" {
		return
	}
	n := atoiDef(prompt("samples each (default 15)"), 15)
	clear()
	banner()
	info(fmt.Sprintf("Comparing %s  vs  %s", a, b))
	fmt.Println()
	var sa, sb []float64
	for i := 0; i < n; i++ {
		if r, ok := tcpRTT(a, 2*time.Second); ok {
			sa = append(sa, r)
		}
		if r, ok := tcpRTT(b, 2*time.Second); ok {
			sb = append(sb, r)
		}
		fmt.Printf("\r  progress %d/%d", i+1, n)
		time.Sleep(150 * time.Millisecond)
	}
	fmt.Print("\n\n")
	st1, st2 := calcStats(sa, n), calcStats(sb, n)
	table([]string{"Metric", "A: " + a, "B: " + b}, [][]string{
		{"Avg", fmt.Sprintf("%.2f ms", st1.mean), fmt.Sprintf("%.2f ms", st2.mean)},
		{"Min", fmt.Sprintf("%.2f ms", st1.min), fmt.Sprintf("%.2f ms", st2.min)},
		{"p95", fmt.Sprintf("%.2f ms", st1.p95), fmt.Sprintf("%.2f ms", st2.p95)},
		{"Max", fmt.Sprintf("%.2f ms", st1.max), fmt.Sprintf("%.2f ms", st2.max)},
		{"Jitter", fmt.Sprintf("%.2f ms", st1.jitter), fmt.Sprintf("%.2f ms", st2.jitter)},
		{"Loss", fmt.Sprintf("%.0f %%", st1.loss), fmt.Sprintf("%.0f %%", st2.loss)},
	})
	fmt.Println()
	switch {
	case len(sa) == 0 && len(sb) == 0:
		warnMsg("neither target responded")
	case st1.mean < st2.mean:
		okMsg(fmt.Sprintf("A is faster by %.2f ms avg", st2.mean-st1.mean))
	case st2.mean < st1.mean:
		okMsg(fmt.Sprintf("B is faster by %.2f ms avg", st1.mean-st2.mean))
	default:
		info("both targets are equal on average")
	}
	pause()
}

func doHTTP() {
	clear()
	banner()
	header("HTTP(S) Time-To-First-Byte")
	url := prompt("URL or host (e.g. example.com or https://site/path)")
	if url == "" {
		return
	}
	n := atoiDef(prompt("samples (default 10)"), 10)
	clear()
	banner()
	info("HTTP TTFB → " + url)
	fmt.Println()
	samples, st, code := monitorHTTP(url, n)
	if len(samples) == 0 {
		errMsg("no successful requests (check URL / connectivity)")
		pause()
		return
	}
	info("Sparkline:  " + col(sparkline(samples), CY) + "   last HTTP status: " + strconv.Itoa(code))
	fmt.Println()
	statsTable(st, n, len(samples))
	maybeExport(url, samples, st)
	pause()
}

func doMulti() {
	clear()
	banner()
	header("Multi-Target Ranking")
	raw := prompt("targets, comma-separated (host[:port],...)")
	if strings.TrimSpace(raw) == "" {
		return
	}
	var targets []string
	for _, t := range strings.Split(raw, ",") {
		if hp := parseHostPort(t, "443"); hp != "" {
			targets = append(targets, hp)
		}
	}
	if len(targets) == 0 {
		return
	}
	n := atoiDef(prompt("samples each (default 10)"), 10)
	clear()
	banner()
	info(fmt.Sprintf("Probing %d targets × %d samples (parallel)…", len(targets), n))
	fmt.Println()
	rows := [][]string{}
	for i, r := range multiTarget(targets, n) {
		status := fmt.Sprintf("%.2f ms", r.st.mean)
		if r.ok == 0 {
			status = col("unreachable", R)
		}
		rows = append(rows, []string{
			fmt.Sprintf("%d", i+1), r.target, status,
			fmt.Sprintf("%.2f", r.st.p95), fmt.Sprintf("%.2f", r.st.jitter),
			fmt.Sprintf("%.0f%%", r.st.loss),
		})
	}
	table([]string{"Rank", "Target", "Avg", "p95", "Jitter", "Loss"}, rows)
	pause()
}

func maybeExport(label string, samples []float64, st stats) {
	out := strings.TrimSpace(prompt("export samples to file? (.csv/.json path or blank)"))
	if out == "" {
		return
	}
	if err := exportSamples(out, label, samples, st); err != nil {
		errMsg(err.Error())
	} else {
		okMsg("Wrote " + out)
	}
}

// ---------------------------------------------------------------------------
// Interactive menu
// ---------------------------------------------------------------------------

func menu(title string, items [][2]string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
			col(pad(it[0], 28), W) + col("─ "+it[1], DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 28), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 28), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	rule()
	return prompt("Select option")
}

func interactive() {
	for {
		c := menu("Main Menu", [][2]string{
			{"Live monitor", "TCP handshake RTT + jitter, live sparkline"},
			{"DNS latency", "time repeated hostname resolutions"},
			{"Compare targets", "two hosts head-to-head"},
			{"HTTP TTFB", "time-to-first-byte of an HTTP(S) endpoint"},
			{"Multi-target rank", "probe many hosts in parallel, ranked"},
		})
		switch strings.ToLower(c) {
		case "1":
			doMonitor()
		case "2":
			doDNSLatency()
		case "3":
			doCompare()
		case "4":
			doHTTP()
		case "5":
			doMulti()
		case "h", "help", "?":
			tuiHelp()
		case "0", "00", "q", "exit", "":
			clear()
			okMsg("Goodbye — owlsec.org")
			return
		default:
			warnMsg("unknown selection")
			pause()
		}
	}
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    " + APPNAME + " [flags]            (no flags → interactive TUI)")
	fmt.Println()
	sec("MODES")
	fmt.Println("    --monitor HOST[:port]   measure TCP handshake RTT (default port 443)")
	fmt.Println("    --http URL              measure HTTP(S) time-to-first-byte")
	fmt.Println("    --dns HOST              measure DNS resolution latency")
	fmt.Println("    --compare A,B           compare two TCP targets head-to-head")
	fmt.Println("    --targets A,B,C         probe many TCP targets in parallel, ranked")
	fmt.Println()
	sec("PARAMETERS")
	fmt.Println("    --samples N             number of probes (default 30 monitor / 10 http/dns)")
	fmt.Println("    --port STR              default port when HOST has none (default 443)")
	fmt.Println()
	sec("OUTPUT & GATES")
	fmt.Println("    --export FILE           write samples+stats to FILE (.csv or .json)")
	fmt.Println("    --sla-avg MS            exit 3 if average RTT exceeds MS")
	fmt.Println("    --sla-loss PCT          exit 3 if loss exceeds PCT percent")
	fmt.Println("    --quiet                 print only the average RTT in ms — scriptable")
	fmt.Println("    --no-color              disable ANSI colour")
	fmt.Println()
	sec("GENERAL")
	fmt.Println("    --demo  --selftest  --version  -h/--help")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    " + APPNAME + " --monitor 1.1.1.1:443 --samples 50 --export rtt.csv")
	fmt.Println("    " + APPNAME + " --http https://example.com --samples 20")
	fmt.Println("    " + APPNAME + " --monitor example.com --sla-avg 80 --sla-loss 5")
	fmt.Println("    " + APPNAME + " --dns example.com --samples 20 --export dns.json")
	fmt.Println("    " + APPNAME + " --targets 1.1.1.1,8.8.8.8,9.9.9.9 --samples 15")
	fmt.Println()
	rule()
}

// finishCLI handles the shared tail: export, SLA gate, and (non-quiet) table.
func finishCLI(title, label string, samples []float64, st stats, n int, quiet bool, export string, slaAvg, slaLoss float64) int {
	if export != "" {
		if err := exportSamples(export, label, samples, st); err != nil {
			errMsg(err.Error())
		} else if !quiet {
			okMsg("Wrote " + export)
		}
	}
	rc := 0
	slaOn := slaAvg > 0 || slaLoss > 0
	ok, reasons := slaEval(st, slaAvg, slaLoss)
	if slaOn && !ok {
		rc = 3
	}
	if quiet {
		fmt.Printf("%.2f\n", st.mean)
	} else {
		banner()
		header(title)
		statsTable(st, n, len(samples))
		if slaOn {
			fmt.Println()
			if ok {
				okMsg("SLA met")
			} else {
				errMsg("SLA breach: " + strings.Join(reasons, "; "))
			}
		}
	}
	return rc
}

func cliMonitor(target string, n int, quiet bool, export string, slaAvg, slaLoss float64) int {
	if n <= 0 {
		n = 30
	}
	samples, st := monitor(target, n, false)
	return finishCLI("TCP RTT — "+target, target, samples, st, n, quiet, export, slaAvg, slaLoss)
}

func cliHTTP(url string, n int, quiet bool, export string, slaAvg, slaLoss float64) int {
	if n <= 0 {
		n = 10
	}
	samples, st, _ := monitorHTTP(url, n)
	return finishCLI("HTTP TTFB — "+url, url, samples, st, n, quiet, export, slaAvg, slaLoss)
}

func cliMulti(spec string, n int, port string, quiet bool) int {
	if n <= 0 {
		n = 10
	}
	var targets []string
	for _, t := range strings.Split(spec, ",") {
		if hp := parseHostPort(t, port); hp != "" {
			targets = append(targets, hp)
		}
	}
	if len(targets) == 0 {
		errMsg("--targets needs at least one host")
		return 2
	}
	res := multiTarget(targets, n)
	if quiet {
		for _, r := range res {
			fmt.Printf("%s %.2f\n", r.target, r.st.mean)
		}
		return 0
	}
	banner()
	header("Multi-Target Ranking")
	rows := [][]string{}
	for i, r := range res {
		avg := fmt.Sprintf("%.2f ms", r.st.mean)
		if r.ok == 0 {
			avg = "unreachable"
		}
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), r.target, avg,
			fmt.Sprintf("%.2f", r.st.p95), fmt.Sprintf("%.0f%%", r.st.loss)})
	}
	table([]string{"Rank", "Target", "Avg", "p95", "Loss"}, rows)
	return 0
}

func cliDNS(host string, n int, quiet bool) int {
	return cliDNSFull(host, n, quiet, "", 0, 0)
}

func cliDNSFull(host string, n int, quiet bool, export string, slaAvg, slaLoss float64) int {
	if n <= 0 {
		n = 10
	}
	var samples []float64
	r := &net.Resolver{}
	for i := 0; i < n; i++ {
		start := time.Now()
		_, err := r.LookupHost(context.Background(), host)
		el := float64(time.Since(start).Microseconds()) / 1000.0
		if err == nil {
			samples = append(samples, el)
		}
	}
	return finishCLI("DNS latency — "+host, host, samples, calcStats(samples, n), n, quiet, export, slaAvg, slaLoss)
}

func cliCompare(spec string, n int, quiet bool) int {
	parts := strings.SplitN(spec, ",", 2)
	if len(parts) != 2 {
		errMsg("--compare needs two targets: A,B")
		return 2
	}
	if n <= 0 {
		n = 15
	}
	a := parseHostPort(parts[0], "443")
	b := parseHostPort(parts[1], "443")
	var sa, sb []float64
	for i := 0; i < n; i++ {
		if r, ok := tcpRTT(a, 2*time.Second); ok {
			sa = append(sa, r)
		}
		if r, ok := tcpRTT(b, 2*time.Second); ok {
			sb = append(sb, r)
		}
	}
	st1, st2 := calcStats(sa, n), calcStats(sb, n)
	if quiet {
		fmt.Printf("%.2f %.2f\n", st1.mean, st2.mean)
		return 0
	}
	banner()
	header("Compare — " + a + " vs " + b)
	table([]string{"Metric", "A: " + a, "B: " + b}, [][]string{
		{"Avg", fmt.Sprintf("%.2f ms", st1.mean), fmt.Sprintf("%.2f ms", st2.mean)},
		{"p95", fmt.Sprintf("%.2f ms", st1.p95), fmt.Sprintf("%.2f ms", st2.p95)},
		{"Jitter", fmt.Sprintf("%.2f ms", st1.jitter), fmt.Sprintf("%.2f ms", st2.jitter)},
		{"Loss", fmt.Sprintf("%.0f %%", st1.loss), fmt.Sprintf("%.0f %%", st2.loss)},
	})
	return 0
}

func runDemo() {
	banner()
	header("Demo — statistics on a fixed sample set")
	fixed := []float64{12.1, 13.4, 11.8, 40.2, 12.0, 12.6, 13.1, 12.9, 11.5, 60.4}
	info("Latency samples (ms):")
	fmt.Println("  " + col(fmt.Sprintf("%v", fixed), W))
	fmt.Println()
	info("Sparkline:  " + col(sparkline(fixed), CY))
	fmt.Println()
	statsTable(calcStats(fixed, len(fixed)), len(fixed), len(fixed))
	fmt.Println()
	info("Run --selftest to verify the statistics engine against known values.")
}

func main() {
	var (
		fMon    = flag.String("monitor", "", "")
		fDNS    = flag.String("dns", "", "")
		fCmp    = flag.String("compare", "", "")
		fHTTP   = flag.String("http", "", "")
		fTgts   = flag.String("targets", "", "")
		fN      = flag.Int("samples", 0, "")
		fPort   = flag.String("port", "443", "")
		fExport = flag.String("export", "", "")
		fSLAAvg = flag.Float64("sla-avg", 0, "")
		fSLALos = flag.Float64("sla-loss", 0, "")
		fQuiet  = flag.Bool("quiet", false, "")
		fNoCol  = flag.Bool("no-color", false, "")
		fDemo   = flag.Bool("demo", false, "")
		fSelf   = flag.Bool("selftest", false, "")
		fVer    = flag.Bool("version", false, "")
	)
	flag.Usage = usage
	flag.Parse()
	if *fNoCol {
		noColor = true
	}
	switch {
	case *fVer:
		fmt.Printf("%s %s  (OWL suite — %s / %s)\n", APPNAME, VERSION, AUTHOR, WEBSITE)
		return
	case *fSelf:
		os.Exit(runSelfTest())
	case *fDemo:
		runDemo()
		return
	case *fMon != "":
		os.Exit(cliMonitor(parseHostPort(*fMon, *fPort), *fN, *fQuiet, *fExport, *fSLAAvg, *fSLALos))
	case *fHTTP != "":
		os.Exit(cliHTTP(strings.TrimSpace(*fHTTP), *fN, *fQuiet, *fExport, *fSLAAvg, *fSLALos))
	case *fTgts != "":
		os.Exit(cliMulti(*fTgts, *fN, *fPort, *fQuiet))
	case *fDNS != "":
		os.Exit(cliDNSFull(strings.TrimSpace(*fDNS), *fN, *fQuiet, *fExport, *fSLAAvg, *fSLALos))
	case *fCmp != "":
		os.Exit(cliCompare(*fCmp, *fN, *fQuiet))
	default:
		interactive()
	}
}

// ---------------------------------------------------------------------------
// Self-test — checks the statistics engine against hand-computed values.
// ---------------------------------------------------------------------------

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func runSelfTest() int {
	banner()
	header("Self-Test — statistics & helpers")
	pass, fail := 0, 0
	check := func(name string, cond bool) {
		if cond {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W))
		}
	}

	// calcStats on a known set {10,20,30,40,50}, no loss.
	s := calcStats([]float64{10, 20, 30, 40, 50}, 5)
	check("min = 10", approx(s.min, 10))
	check("max = 50", approx(s.max, 50))
	check("mean = 30", approx(s.mean, 30))
	check("std dev = sqrt(200)", approx(s.std, math.Sqrt(200)))
	check("mdev = 12", approx(s.mdev, 12))
	check("jitter (mean successive diff) = 10", approx(s.jitter, 10))
	check("loss = 0%", approx(s.loss, 0))

	// loss accounting: 3 of 5 responded.
	s2 := calcStats([]float64{5, 5, 5}, 5)
	check("loss = 40% when 3/5 respond", approx(s2.loss, 40))
	check("empty sample set = 100% loss", approx(calcStats(nil, 4).loss, 100))

	// percentile.
	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	check("p95 of 1..10 = 9.55", approx(percentile(sorted, 95), 9.55))
	check("p50 of 1..10 = 5.5", approx(percentile(sorted, 50), 5.5))
	check("p0 = min", approx(percentile(sorted, 0), 1))
	check("p100 = max", approx(percentile(sorted, 100), 10))

	// sparkline bounds: distinct min & max runes, right length.
	sp := sparkline([]float64{0, 1, 2, 3, 4, 5, 6, 7})
	spR := []rune(sp)
	check("sparkline length matches input", len(spR) == 8)
	check("sparkline low = ▁", len(spR) > 0 && spR[0] == '▁')
	check("sparkline high = █", len(spR) == 8 && spR[7] == '█')
	check("sparkline of empty = \"\"", sparkline(nil) == "")
	check("sparkline of flat line stays low", func() bool {
		r := []rune(sparkline([]float64{5, 5, 5}))
		return len(r) == 3 && r[0] == '▁'
	}())

	// parseHostPort.
	check("parseHostPort adds default port", parseHostPort("example.com", "443") == "example.com:443")
	check("parseHostPort keeps explicit port", parseHostPort("example.com:80", "443") == "example.com:80")
	check("parseHostPort empty = empty", parseHostPort("", "443") == "")
	check("parseHostPort IPv6 literal", parseHostPort("[2001:db8::1]:53", "443") == "[2001:db8::1]:53")

	// helpers.
	check("stripANSI removes colour", stripANSI(col("hi", CY)) == "hi")
	check("visw counts runes not bytes", visw("abc") == 3)
	check("atoiDef falls back", atoiDef("notnum", 7) == 7)
	check("atoiDef parses", atoiDef("42", 7) == 42)

	// v1.1: SLA gate.
	slaStats := stats{mean: 100, loss: 10}
	okAvg, _ := slaEval(slaStats, 50, 0)
	check("slaEval fails when avg over threshold", !okAvg)
	okAvg2, _ := slaEval(slaStats, 150, 0)
	check("slaEval passes when avg under threshold", okAvg2)
	okLoss, rs := slaEval(slaStats, 0, 5)
	check("slaEval fails on loss + gives a reason", !okLoss && len(rs) == 1)
	okNone, _ := slaEval(slaStats, 0, 0)
	check("slaEval with no thresholds passes", okNone)

	// v1.1: multi-target ranking — fastest first, unreachable last.
	rs2 := []targetResult{
		{target: "slow", st: stats{mean: 90}, ok: 3},
		{target: "down", st: stats{mean: 0}, ok: 0},
		{target: "fast", st: stats{mean: 10}, ok: 3},
	}
	rankResults(rs2)
	check("rankResults puts fastest first", rs2[0].target == "fast")
	check("rankResults sinks unreachable last", rs2[2].target == "down")

	// v1.1: CSV/JSON export round-trip.
	tmp := os.TempDir() + "/olat_selftest.json"
	_ = exportSamples(tmp, "t", []float64{1, 2, 3}, calcStats([]float64{1, 2, 3}, 3))
	jb, _ := os.ReadFile(tmp)
	var jv map[string]interface{}
	check("exportSamples writes valid JSON", json.Unmarshal(jb, &jv) == nil && jv["target"] == "t")
	os.Remove(tmp)
	tmpc := os.TempDir() + "/olat_selftest.csv"
	_ = exportSamples(tmpc, "t", []float64{1, 2}, calcStats([]float64{1, 2}, 2))
	cb, _ := os.ReadFile(tmpc)
	check("exportSamples writes CSV with header", strings.Contains(string(cb), "index,target,rtt_ms"))
	os.Remove(tmpc)

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	usage()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OLatency measures network round-trip latency and its variation (jitter) without root or raw sockets. It times the TCP three-way handshake to a host:port as a portable RTT probe, times DNS name resolution, and can race two targets head-to-head.",
	"A \"connection refused\" still proves the packet round-tripped, so it counts as a reachable, timed sample. Everything is computed from the Go standard library.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Each option asks for a target and a sample count; press Enter to accept the default shown in brackets. [H] opens this help, [0] or q quits.",
	"Targets are host or host:port (default port 443). The live monitor draws a sparkline that scales to the recent window; final statistics include min/avg/p95/max, standard deviation, mdev, jitter and loss.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Live monitor: probe one target repeatedly with TCP-handshake RTT, drawing a live sparkline and running average, then a full statistics table. Offers to export the samples."},
	{"2", "DNS latency: time repeated resolutions of a hostname through the system resolver and summarise them."},
	{"3", "Compare targets: probe two hosts the same number of times and show which is faster on average, with per-target jitter and loss."},
	{"4", "HTTP TTFB: measure the time-to-first-byte of an HTTP(S) endpoint (DNS+connect+TLS+server), with the last HTTP status code."},
	{"5", "Multi-target rank: probe many TCP targets in parallel and rank them fastest-first; unreachable hosts sink to the bottom."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "Jitter here is the mean of successive RTT differences (the ITU-T packet-delay-variation estimate), not the standard deviation."},
	{"*", "TCP-handshake RTT includes connection setup, so it is a little higher than ICMP ping but needs no privileges and traverses most firewalls on port 443."},
	{"*", "--quiet on the CLI prints only the average ms, handy in scripts: MS=$(OLatency --monitor host --quiet)."},
	{"*", "p95 is the 95th-percentile latency — a better tail-latency signal than max for noisy links."},
	{"*", "--export FILE saves the per-sample series + summary as .csv or .json (chosen by extension); the monitor/DNS/HTTP menu runs also offer this."},
	{"*", "--sla-avg MS and --sla-loss PCT turn OLatency into a CI/monitoring gate: it exits 3 if the threshold is breached."},
	{"*", "--targets a,b,c ranks many endpoints in parallel — handy for picking the closest mirror or resolver."},
}
