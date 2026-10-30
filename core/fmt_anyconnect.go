package main

import (
	"errors"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var ocACProfileRe = regexp.MustCompile(`<(?:[A-Za-z_][\w.-]*:)?AnyConnectProfile[\s>/]`)
var ocHostEntryRe = regexp.MustCompile(`(?s)<(?:[A-Za-z_][\w.-]*:)?HostEntry\b[^>]*>.*?</(?:[A-Za-z_][\w.-]*:)?HostEntry\s*>`)

type ocACProfileFormat struct{}

func (ocACProfileFormat) Detect(f *vfile) int {
	if len(f.Data) == 0 || len(f.Data) > 4<<20 || !f.IsText() {
		return 0
	}
	t := f.Text()
	if len(t) > 256<<10 {
		t = t[:256<<10]
	}
	if !ocACProfileRe.MatchString(t) {
		return 0
	}
	if strings.Contains(t, "HostEntry") {
		return 90
	}
	return 60
}

func (ocACProfileFormat) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	doc := ocParseXML(f.Data)
	prof := doc.find("AnyConnectProfile")
	if prof == nil {
		return nil, errors.New("no AnyConnectProfile element")
	}
	var entries []*ocNode
	for _, sl := range ocFindAll(prof, "ServerList") {
		entries = append(entries, sl.children("HostEntry")...)
	}
	if len(entries) == 0 {
		return nil, errors.New("AnyConnect profile has no ServerList/HostEntry")
	}
	raws := ocHostEntryRe.FindAllString(f.Text(), -1)
	var out []*Config
	for i, e := range entries {
		name := e.childText("HostName")
		addr := e.childText("HostAddress")
		if addr == "" {
			addr = name
		}
		group := strings.Trim(e.childText("UserGroup"), "/ ")
		spec := &ocSpec{Name: name, Protocol: "anyconnect", Host: addr}
		_, port, p := ocSplitServer(addr)
		if port > 0 {
			spec.Port = port
		}
		if group != "" {
			spec.Path = "/" + group
		} else if p != "" {
			spec.Path = p
		}
		c := ocConfig(f, fs, spec)
		c.Format = "AnyConnect Profile"
		if c.Name == "" {
			c.Name = addr
		}
		pp := e.child("PrimaryProtocol")
		if pp != nil && strings.EqualFold(strings.TrimSpace(pp.Text), "IPsec") {
			c.Warn("primary protocol is IPsec (IKEv2); the SSL/TLS gateway is tested")
		}
		if i < len(raws) {
			c.RawConfig = []byte(raws[i])
		}
		if c.Status == StateParsed && strings.TrimSpace(addr) == "" {
			c.Status = StateInvalid
			c.Error = "HostEntry has no HostAddress/HostName"
		}
		out = append(out, c)
	}
	return out, nil
}

func (ocACProfileFormat) Filter(f *vfile, indices []int) ([]byte, error) {
	t := string(f.Data)
	locs := ocHostEntryRe.FindAllStringIndex(t, -1)
	if len(locs) == 0 {
		return f.Data, nil
	}
	keep := map[int]bool{}
	for _, i := range indices {
		keep[i] = true
	}
	var b strings.Builder
	last := 0
	for i, l := range locs {
		b.WriteString(t[last:l[0]])
		if keep[i] {
			b.WriteString(t[l[0]:l[1]])
		}
		last = l[1]
	}
	b.WriteString(t[last:])
	return []byte(b.String()), nil
}

func ocFindAll(n *ocNode, name string) []*ocNode {
	var out []*ocNode
	var walk func(*ocNode)
	walk = func(x *ocNode) {
		for _, c := range x.Children {
			if strings.EqualFold(c.Name, name) {
				out = append(out, c)
				continue
			}
			walk(c)
		}
	}
	walk(n)
	return out
}

var ocCfgOpts = map[string]int{
	"background": 0, "pid-file": 1, "setuid": 1, "script-tun": 0, "syslog": 0, "csd-user": 1, "csd-wrapper": 1,
	"external-browser": 1, "no-external-auth": 0, "pfs": 0, "allow-insecure-crypto": 0, "certificate": 1, "sslkey": 1,
	"cookie": 1, "compression": 1, "deflate": 0, "juniper": 0, "no-deflate": 0, "cert-expire-warning": 1, "usergroup": 1,
	"http-auth": 1, "interface": 1, "mtu": 1, "base-mtu": 1, "script": 1, "timestamp": 0, "passtos": 0,
	"key-password": 1, "proxy": 1, "proxy-auth": 1, "user": 1, "verbose": 0, "cafile": 1, "no-dtls": 0,
	"authenticate": 0, "cookieonly": 0, "printcookie": 0, "quiet": 0, "queue-len": 1, "xmlconfig": 1, "cookie-on-stdin": 0,
	"passwd-on-stdin": 0, "no-passwd": 0, "reconnect-timeout": 1, "dtls-ciphers": 1, "dtls12-ciphers": 1, "authgroup": 1,
	"servercert": 1, "resolve": 1, "sni": 1, "key-password-from-fsid": 0, "useragent": 1, "version-string": 1,
	"local-hostname": 1, "disable-ipv6": 0, "no-proxy": 0, "libproxy": 0, "no-http-keepalive": 0, "no-cert-check": 0,
	"force-dpd": 1, "force-trojan": 1, "non-inter": 0, "dtls-local-port": 1, "token-mode": 1, "token-secret": 1, "os": 1,
	"no-xmlpost": 0, "dump-http-traffic": 0, "no-system-trust": 0, "protocol": 1, "form-entry": 1, "gnutls-debug": 1,
	"gnutls-priority": 1, "openssl-ciphers": 1, "server": 1, "mca-certificate": 1, "mca-key": 1, "mca-key-password": 1,
}

var ocCfgDistinct = map[string]bool{
	"authgroup": true, "usergroup": true, "servercert": true, "csd-wrapper": true, "csd-user": true, "passwd-on-stdin": true,
	"cookie-on-stdin": true, "no-dtls": true, "useragent": true, "version-string": true, "no-xmlpost": true, "form-entry": true,
	"token-mode": true, "token-secret": true, "juniper": true, "dtls-ciphers": true, "dtls12-ciphers": true, "mca-certificate": true,
	"mca-key": true, "reconnect-timeout": true, "local-hostname": true, "no-http-keepalive": true, "force-dpd": true,
	"force-trojan": true, "http-auth": true, "external-browser": true, "no-external-auth": true, "script-tun": true,
	"key-password-from-fsid": true, "non-inter": true, "authenticate": true, "cookieonly": true, "printcookie": true,
	"dump-http-traffic": true, "allow-insecure-crypto": true, "no-system-trust": true, "dtls-local-port": true,
}

var ocCfgExtra = map[string]bool{"password": true, "passwd": true, "pass": true, "gateway": true, "url": true, "host": true, "port": true, "name": true, "group": true}

var ocCfgForeign = map[string]bool{
	"remote": true, "client": true, "dev": true, "proto": true, "auth-user-pass": true, "conn": true, "config": true,
	"keyexchange": true, "left": true, "right": true, "privatekey": true, "endpoint": true, "allowedips": true,
	"tls-auth": true, "cipher": true, "persist-key": true, "nobind": true, "remote-cert-tls": true, "auth": true,
}

type ocCfgLine struct {
	key string
	val string
}

func ocCfgLines(text string) ([]ocCfgLine, int, int, bool, string) {
	var out []ocCfgLine
	known, unknown := 0, 0
	distinct := false
	bareURL := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") || strings.HasPrefix(line, "<") || strings.HasPrefix(line, "{") {
			return nil, 0, 1 << 20, false, ""
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "https://") && !strings.ContainsAny(line, " \t") {
			if bareURL == "" {
				bareURL = line
			}
			known++
			continue
		}
		line = strings.TrimPrefix(line, "--")
		key, val := line, ""
		if i := strings.IndexAny(line, "= \t"); i >= 0 {
			key = line[:i]
			val = strings.TrimSpace(line[i:])
			val = strings.TrimSpace(strings.TrimPrefix(val, "="))
		}
		key = strings.ToLower(key)
		if ocCfgForeign[key] {
			return nil, 0, 1 << 20, false, ""
		}
		if _, ok := ocCfgOpts[key]; ok {
			known++
			if ocCfgDistinct[key] {
				distinct = true
			}
			if key == "protocol" && ocNormProto(unquote(val)) != "" && unquote(val) != "" {
				distinct = true
			}
		} else if ocCfgExtra[key] {
			known++
		} else {
			unknown++
		}
		out = append(out, ocCfgLine{key: key, val: unquote(val)})
	}
	return out, known, unknown, distinct, bareURL
}

type ocCfgFormat struct{}

func (ocCfgFormat) Detect(f *vfile) int {
	if len(f.Data) == 0 || len(f.Data) > 64<<10 || !f.IsText() {
		return 0
	}
	lines, known, unknown, distinct, bare := ocCfgLines(f.Text())
	if !distinct || known < 2 || unknown*4 > known {
		return 0
	}
	hasServer := bare != ""
	for _, l := range lines {
		if (l.key == "server" || l.key == "gateway" || l.key == "url" || l.key == "host") && l.val != "" {
			hasServer = true
		}
	}
	if hasServer {
		return 70
	}
	return 45
}

func (ocCfgFormat) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	lines, _, _, _, bare := ocCfgLines(f.Text())
	spec := &ocSpec{Protocol: "anyconnect", Name: strings.TrimSuffix(f.Name, path.Ext(f.Name))}
	server := bare
	var warns []string
	var deps []*vfile
	var certDeps []*vfile
	var keyPass string
	var certFile, keyFile *vfile
	for _, l := range lines {
		v := l.val
		switch l.key {
		case "protocol":
			spec.Protocol = v
		case "juniper":
			spec.Protocol = "nc"
		case "user":
			spec.Username = v
		case "password", "passwd", "pass":
			spec.Password = v
		case "authgroup", "group":
			spec.Group = v
		case "usergroup":
			spec.Path = "/" + strings.TrimPrefix(v, "/")
		case "server", "gateway", "url", "host":
			if server == "" {
				server = v
			}
		case "port":
			if n, err := strconv.Atoi(v); err == nil {
				spec.Port = n
			}
		case "name":
			spec.Name = v
		case "servercert":
			if spec.ServerCertPin == "" {
				spec.ServerCertPin = v
			} else {
				spec.ServerCertPin += "," + v
			}
		case "cafile":
			if g := fs.Resolve(f, v); g != nil {
				spec.CACert = append(spec.CACert, g.Data...)
				certDeps = append(certDeps, g)
			} else {
				warns = append(warns, "CA file "+path.Base(v)+" not found")
			}
		case "certificate":
			if g := fs.Resolve(f, v); g != nil {
				certFile = g
				certDeps = append(certDeps, g)
			} else {
				warns = append(warns, "client certificate "+path.Base(v)+" not found")
			}
		case "sslkey":
			if g := fs.Resolve(f, v); g != nil {
				keyFile = g
				deps = append(deps, g)
			} else {
				warns = append(warns, "client key "+path.Base(v)+" not found")
			}
		case "key-password":
			keyPass = v
		case "form-entry":
			_, rest, ok := strings.Cut(v, ":")
			if !ok {
				continue
			}
			k, val, ok := strings.Cut(rest, "=")
			if !ok {
				continue
			}
			switch strings.ToLower(k) {
			case "username", "user", "uname":
				if spec.Username == "" {
					spec.Username = val
				}
			case "password", "passwd", "pwd", "credential":
				if spec.Password == "" {
					spec.Password = val
				}
			case "group_list", "realm", "domain":
				if spec.Group == "" {
					spec.Group = val
				}
			}
		case "cookie":
			warns = append(warns, "session cookie in file ignored")
		}
	}
	if certFile != nil {
		data := certFile.Data
		if ext := certFile.Ext; ext == "p12" || ext == "pfx" || !strings.Contains(string(data), "-----BEGIN") && keyFile == nil {
			if cp, kp, _, err := decodePKCS12(data, keyPass); err == nil {
				spec.ClientCert, spec.ClientKey = cp, kp
			} else {
				warns = append(warns, "client certificate could not be decoded: "+shortErr(err))
			}
		} else {
			spec.ClientCert = data
			if keyFile != nil {
				spec.ClientKey = keyFile.Data
			}
		}
	}
	spec.Host = server
	c := ocConfig(f, fs, spec)
	c.Format = "OpenConnect"
	for _, w := range warns {
		c.Warn("%s", w)
	}
	for _, d := range certDeps {
		c.AddDep(fs, d, true)
	}
	for _, d := range deps {
		c.AddDep(fs, d, false)
	}
	if c.Status == StateParsed && strings.TrimSpace(server) == "" {
		c.Status = StateInvalid
		c.Error = "no server/gateway in file"
	}
	c.RawConfig = f.Data
	return []*Config{c}, nil
}

func init() {
	registerFormat(&fileFormat{Name: "AnyConnect Profile", Detector: ocACProfileFormat{}, Parser: ocACProfileFormat{}, Filter: ocACProfileFormat{}})
	registerFormat(&fileFormat{Name: "OpenConnect", Detector: ocCfgFormat{}, Parser: ocCfgFormat{}})
}
