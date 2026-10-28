// symbolon audits the TLS/SSL configuration of a service: protocols, suites,
// preference order and certificate.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/horoslabs/symbolon/internal/scan"
)

var version = "dev"

const usage = `symbolon — TLS/SSL audit

Usage:
  symbolon scan [flags] host[:port]...
  symbolon version

Scan flags:
  -json            JSON output
  -html            HTML report (symbolon scan -html host > report.html)
  -list file       read targets from a file (one per line, # comments)
  -sni name        SNI to send (defaults to the host)
  -timeout 5s      per-connection timeout
  -c 4             targets in parallel
  -fail-on level   exit with code 2 if findings >= level
                   (critical, high, medium, low)

Example:
  symbolon scan badssl.com tls-v1-0.badssl.com:1010
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string {
	return fmt.Sprintf("findings above threshold (code %d)", int(e))
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("missing subcommand")
	}
	switch args[0] {
	case "scan":
		err := cmdScan(args[1:], out)
		if code, ok := err.(exitCode); ok {
			fmt.Fprintln(os.Stderr, code.Error())
			os.Exit(int(code))
		}
		return err
	case "version", "-v", "--version":
		fmt.Fprintln(out, version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return nil
	}
	fmt.Fprint(os.Stderr, usage)
	return fmt.Errorf("unknown subcommand %q", args[0])
}

func readList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func cmdScan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	asHTML := fs.Bool("html", false, "HTML report")
	list := fs.String("list", "", "file with targets")
	sni := fs.String("sni", "", "SNI to send")
	timeout := fs.Duration("timeout", 5*time.Second, "per-connection timeout")
	conc := fs.Int("c", 4, "targets in parallel")
	failOn := fs.String("fail-on", "", "severity threshold for exit code 2")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets := fs.Args()
	if *list != "" {
		more, err := readList(*list)
		if err != nil {
			return err
		}
		targets = append(targets, more...)
	}
	if len(targets) == 0 {
		return fmt.Errorf("specify at least one target")
	}
	if *asJSON && *asHTML {
		return fmt.Errorf("-json and -html are mutually exclusive")
	}
	if *failOn != "" && scan.Rank(*failOn) >= scan.Rank(scan.Info) {
		return fmt.Errorf("-fail-on %q is not valid (critical, high, medium, low)", *failOn)
	}
	if *conc < 1 {
		*conc = 1
	}

	type item struct {
		rep *scan.Report
		err error
	}
	results := make([]item, len(targets))
	sem := make(chan struct{}, *conc)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rep, err := scan.Scan(t, scan.Options{Timeout: *timeout, SNI: *sni})
			results[i] = item{rep, err}
		}(i, t)
	}
	wg.Wait()

	var reports []*scan.Report
	exceeded := false
	for i, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", targets[i], r.err)
			continue
		}
		reports = append(reports, r.rep)
		if *failOn != "" {
			for _, f := range r.rep.Findings {
				if scan.Rank(f.Severity) <= scan.Rank(*failOn) {
					exceeded = true
				}
			}
		}
	}

	switch {
	case *asHTML:
		if err := scan.WriteHTML(out, reports); err != nil {
			return err
		}
	case *asJSON:
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return err
		}
	default:
		for i, r := range reports {
			if i > 0 {
				fmt.Fprintln(out)
			}
			r.WriteText(out)
		}
	}
	if len(reports) == 0 {
		return fmt.Errorf("no target scanned")
	}
	if exceeded {
		return exitCode(2)
	}
	return nil
}
