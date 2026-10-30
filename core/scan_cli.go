package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func loadDir(root string) *vfs {
	v := newVFS()
	info, err := os.Stat(root)
	if err == nil && !info.IsDir() {
		if b, err := os.ReadFile(root); err == nil {
			v.add(newVFile(filepath.Base(root), b))
		}
		return v
	}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.Size() > 4<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		v.add(newVFile(filepath.ToSlash(rel), b))
		return nil
	})
	return v
}

func scanCLI(args []string, testing bool) {
	fl := flag.NewFlagSet("scan", flag.ExitOnError)
	conc := fl.Int("c", 10, "concurrency")
	overall := fl.Int("t", 15000, "overall timeout ms")
	noData := fl.Bool("nodata", false, "skip data-plane probe")
	pretty := fl.Bool("pretty", false, "human readable output")
	fl.Parse(args)
	if fl.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: core scan|detect [-c N] [-t ms] [-nodata] [-pretty] <dir|file>")
		os.Exit(2)
	}
	opt := &scanOptions{Concurrency: *conc, Timeouts: scanTimeouts{Overall: *overall}}
	dp := !*noData
	opt.DataProbe = &dp
	opt.normalize()
	initRuntime(nil)
	v := loadDir(fl.Arg(0))
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	names := map[int]string{}
	emit := func(x any) {
		if *pretty {
			printPretty(w, x, names)
		} else {
			b, _ := json.Marshal(x)
			w.Write(b)
			w.WriteByte('\n')
		}
		w.Flush()
	}
	if !testing {
		res := discover(v)
		for _, c := range res.configs {
			emit(c.view())
		}
		emit(summaryView{Ev: "summary", Files: res.files, Configs: len(res.configs), Dependencies: res.deps, Ignored: res.ignored})
		return
	}
	runScan(opt, v, emit)
}

func printPretty(w *bufio.Writer, x any, names map[int]string) {
	switch v := x.(type) {
	case configView:
		label := v.File
		if v.Multi {
			label += "[" + strconv.Itoa(v.Index) + "]"
		}
		names[v.ID] = label
		fmt.Fprintf(w, "#%d %-40s %-12s %-12s %s:%d %s/%s %s %s\n", v.ID, label, v.Format, v.Protocol, v.Host, v.Port, v.Transport, v.Security, v.Status, v.Error)
		if len(v.Dependencies) > 0 {
			fmt.Fprintf(w, "    deps: %s\n", strings.Join(v.Dependencies, ", "))
		}
		if len(v.Warnings) > 0 {
			fmt.Fprintf(w, "    warnings: %s\n", strings.Join(v.Warnings, "; "))
		}
		if v.DuplicateOf != 0 {
			fmt.Fprintf(w, "    duplicate of #%d\n", v.DuplicateOf)
		}
	case summaryView:
		fmt.Fprintf(w, "== files=%d configs=%d deps=%d ignored=%d\n", v.Files, v.Configs, v.Dependencies, v.Ignored)
	case *TestResult:
		st := func(b *bool) string {
			if b == nil {
				return "-"
			}
			if *b {
				return "Y"
			}
			return "N"
		}
		s := v.Stages
		fmt.Fprintf(w, "=> #%d %-40s %-20s %5dms [p%s d%s t%s h%s a%s x%s] %s %s %s %s\n", v.ID, names[v.ID], v.Result, v.Latency,
			st(s.Parse), st(s.DNS), st(s.Transport), st(s.Handshake), st(s.Authentication), st(s.DataPlane), v.Engine, v.ErrorCode, v.ErrorMessage, v.Note)
	default:
		b, _ := json.Marshal(x)
		if strings.Contains(string(b), `"testing"`) {
			return
		}
		w.Write(b)
		w.WriteByte('\n')
	}
}

func filterCLI(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: core filter <format> <file> <i,j,...>")
		os.Exit(2)
	}
	b, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var idx []int
	for _, s := range strings.Split(args[2], ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			idx = append(idx, n)
		}
	}
	out, err := filterFile(args[0], newVFile(filepath.Base(args[1]), b), idx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}
