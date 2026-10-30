package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

var errRejected = errors.New("rejected")

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	Close() error
}

type candidate struct {
	Engine string
	Build  func() (Dialer, error)
	Probe  func(ctx context.Context) (time.Duration, error)
	Debug  any
}

type node struct {
	Proto      string
	Candidates []candidate
}

func raceURLs(ctx context.Context, d Dialer, urls []string) (time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		d   time.Duration
		err error
	}
	ch := make(chan res, len(urls))
	start := time.Now()
	for _, u := range urls {
		go func(u string) {
			err := fetch(ctx, d, u)
			ch <- res{time.Since(start), err}
		}(u)
	}
	var first error
	for range urls {
		r := <-ch
		if r.err == nil {
			return r.d, nil
		}
		if first == nil || errors.Is(first, context.Canceled) {
			first = r.err
		}
	}
	return 0, first
}

func fetch(ctx context.Context, d Dialer, target string) error {
	tr := &http.Transport{
		DialContext:         d.DialContext,
		DisableKeepAlives:   true,
		DisableCompression:  true,
		TLSClientConfig:     &tls.Config{},
		TLSHandshakeTimeout: 0,
		MaxIdleConns:        -1,
		Proxy:               nil,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return cleanNetErr(err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%w: http %d", errRejected, resp.StatusCode)
	}
	return nil
}

func cleanNetErr(err error) error {
	var ue interface{ Unwrap() error }
	for i := 0; i < 4; i++ {
		if errors.As(err, &ue) {
			if inner := ue.Unwrap(); inner != nil {
				if _, ok := inner.(*net.OpError); ok {
					err = inner
					continue
				}
			}
		}
		break
	}
	return err
}

type pipeConn struct {
	net.Conn
	onClose func()
}

func (p *pipeConn) Close() error {
	err := p.Conn.Close()
	if p.onClose != nil {
		p.onClose()
	}
	return err
}
