package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type runConfig struct {
	URLs        []string `json:"urls"`
	Timeout     int      `json:"timeout"`
	Concurrency int      `json:"concurrency"`
	DNS         []string `json:"dns"`
}

type job struct {
	ID   int64  `json:"id"`
	Link string `json:"link"`
}

type result struct {
	ID     int64  `json:"id"`
	OK     bool   `json:"ok"`
	Delay  int64  `json:"delay,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Engine string `json:"engine,omitempty"`
	Error  string `json:"error,omitempty"`
	Done   bool   `json:"done,omitempty"`
}

var defaultURLs = []string{
	"http://cp.cloudflare.com/generate_204",
	"https://www.google.com/generate_204",
}

type emitter struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func (e *emitter) emit(r result) {
	b, _ := json.Marshal(r)
	e.mu.Lock()
	e.w.Write(b)
	e.w.WriteByte('\n')
	e.w.Flush()
	e.mu.Unlock()
}

func protocolOutput() *os.File {
	fd, err := unix.Dup(1)
	if err != nil {
		return os.Stdout
	}
	if err := unix.Dup2(2, 1); err != nil {
		return os.Stdout
	}
	return os.NewFile(uintptr(fd), "protocol")
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "files":
			scanMain()
			return
		case "export":
			exportMain()
			return
		}
		cli(os.Args[1:])
		return
	}
	out := protocolOutput()
	em := &emitter{w: bufio.NewWriterSize(out, 64<<10)}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	if !sc.Scan() {
		em.emit(result{Done: true, Error: "missing config"})
		return
	}
	cfg := &runConfig{}
	if err := json.Unmarshal(sc.Bytes(), cfg); err != nil {
		em.emit(result{Done: true, Error: "bad config: " + err.Error()})
		return
	}
	normalizeConfig(cfg)
	initRuntime(cfg.DNS)

	jobs := make(chan job, cfg.Concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				em.emit(runJob(cfg, j))
			}
		}()
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var j job
		if err := json.Unmarshal([]byte(line), &j); err != nil {
			continue
		}
		jobs <- j
	}
	close(jobs)
	wg.Wait()
	em.emit(result{Done: true})
	os.Exit(0)
}

func normalizeConfig(cfg *runConfig) {
	if len(cfg.URLs) == 0 {
		cfg.URLs = defaultURLs
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 6000
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 64
	}
	if cfg.Concurrency > 1024 {
		cfg.Concurrency = 1024
	}
}

func runJob(cfg *runConfig, j job) (r result) {
	r.ID = j.ID
	defer func() {
		if p := recover(); p != nil {
			r.OK = false
			r.Delay = 0
			r.Error = fmt.Sprint("internal error: ", p)
		}
	}()
	n, err := parseLink(strings.TrimSpace(j.Link))
	if n != nil {
		r.Proto = n.Proto
	}
	if err != nil {
		r.Error = shortErr(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Millisecond)
	defer cancel()
	d, engine, err := testNode(ctx, n, cfg.URLs)
	r.Engine = engine
	if err != nil {
		if ctx.Err() != nil && !errors.Is(err, errRejected) {
			r.Error = "timeout"
		} else {
			r.Error = shortErr(err)
		}
		return
	}
	r.OK = true
	r.Delay = d.Milliseconds()
	if r.Delay < 1 {
		r.Delay = 1
	}
	return
}

func retryable(ctx context.Context, err error) bool {
	if err == nil || errors.Is(err, errRejected) || ctx.Err() != nil {
		return false
	}
	dl, ok := ctx.Deadline()
	return !ok || time.Until(dl) > 2*time.Second
}

func runOnce(ctx context.Context, c candidate, dialer Dialer, urls []string) (time.Duration, error) {
	if c.Probe != nil {
		return c.Probe(ctx)
	}
	d, err := raceURLs(ctx, dialer, urls)
	go dialer.Close()
	return d, err
}

func testNode(ctx context.Context, n *node, urls []string) (time.Duration, string, error) {
	var buildErr error
	for _, c := range n.Candidates {
		var dialer Dialer
		if c.Probe == nil {
			dl, err := c.Build()
			if err != nil {
				buildErr = fmt.Errorf("%s: %w", c.Engine, err)
				continue
			}
			dialer = dl
		}
		d, err := runOnce(ctx, c, dialer, urls)
		if retryable(ctx, err) {
			var again Dialer
			if c.Probe == nil {
				again, _ = c.Build()
			}
			if c.Probe != nil || again != nil {
				if d2, err2 := runOnce(ctx, c, again, urls); err2 == nil {
					return d2, c.Engine, nil
				}
			}
		}
		return d, c.Engine, err
	}
	if buildErr == nil {
		buildErr = errors.New("unsupported")
	}
	return 0, "", buildErr
}

func shortErr(err error) string {
	s := err.Error()
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func cli(args []string) {
	switch args[0] {
	case "parse":
		initRuntime(nil)
		for _, l := range args[1:] {
			n, err := parseLink(l)
			if err != nil {
				fmt.Println("ERR", err)
				continue
			}
			fmt.Println("proto:", n.Proto)
			for _, c := range n.Candidates {
				fmt.Println(" engine:", c.Engine)
				if c.Debug != nil {
					b, _ := json.MarshalIndent(c.Debug, "  ", "  ")
					fmt.Println(" ", string(b))
				}
				if c.Build != nil {
					d, err := c.Build()
					if err != nil {
						fmt.Println("  build error:", err)
					} else {
						fmt.Println("  build ok")
						d.Close()
					}
				}
			}
		}
	case "test":
		cfg := &runConfig{}
		normalizeConfig(cfg)
		initRuntime(nil)
		for _, l := range args[1:] {
			b, _ := json.Marshal(runJob(cfg, job{Link: l}))
			fmt.Println(string(b))
		}
	case "scan":
		scanCLI(args[1:], true)
	case "detect":
		scanCLI(args[1:], false)
	case "filter":
		filterCLI(args[1:])
	default:
		io.WriteString(os.Stderr, "usage: core [parse|test] links... | scan|detect [flags] <dir> | filter <format> <file> <indices> | files | export\n")
	}
}
