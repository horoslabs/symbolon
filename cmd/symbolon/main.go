// symbolon audita la configuración TLS/SSL de un servicio: protocolos, suites,
// orden de preferencia y certificado.
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

const usage = `symbolon — auditoría TLS/SSL

Uso:
  symbolon scan [flags] host[:puerto]...
  symbolon version

Flags de scan:
  -json            salida JSON
  -list fichero    lee objetivos de un fichero (uno por línea, # comenta)
  -sni nombre      SNI a enviar (por defecto, el host)
  -timeout 5s      timeout por conexión
  -c 4             objetivos en paralelo
  -fail-on nivel   sale con código 2 si hay hallazgos >= nivel
                   (critical, high, medium, low)

Ejemplo:
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
	return fmt.Sprintf("hallazgos por encima del umbral (código %d)", int(e))
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("falta el subcomando")
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
	return fmt.Errorf("subcomando desconocido %q", args[0])
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
	asJSON := fs.Bool("json", false, "salida JSON")
	list := fs.String("list", "", "fichero con objetivos")
	sni := fs.String("sni", "", "SNI a enviar")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout por conexión")
	conc := fs.Int("c", 4, "objetivos en paralelo")
	failOn := fs.String("fail-on", "", "umbral de severidad para código de salida 2")
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
		return fmt.Errorf("indica al menos un objetivo")
	}
	if *failOn != "" && scan.Rank(*failOn) >= scan.Rank(scan.Info) {
		return fmt.Errorf("-fail-on %q no es válido (critical, high, medium, low)", *failOn)
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

	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return err
		}
	} else {
		for i, r := range reports {
			if i > 0 {
				fmt.Fprintln(out)
			}
			r.WriteText(out)
		}
	}
	if len(reports) == 0 {
		return fmt.Errorf("ningún objetivo escaneado")
	}
	if exceeded {
		return exitCode(2)
	}
	return nil
}
