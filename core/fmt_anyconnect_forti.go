package main

import (
	"path"
	"strconv"
	"strings"
)

var ocOFVKeys = map[string]bool{
	"host": true, "port": true, "username": true, "password": true, "otp": true, "otp-prompt": true, "otp-delay": true,
	"no-ftm-push": true, "pinentry": true, "realm": true, "set-dns": true, "set-routes": true, "half-internet-routes": true,
	"pppd-use-peerdns": true, "pppd-log": true, "pppd-plugin": true, "pppd-ipparam": true, "pppd-ifname": true, "pppd-call": true,
	"pppd-accept-remote": true, "use-syslog": true, "persistent": true, "trusted-cert": true, "ca-file": true, "user-cert": true,
	"user-key": true, "insecure-ssl": true, "cipher-list": true, "min-tls": true, "seclevel-1": true, "use-resolvconf": true,
	"saml-login": true, "sni": true, "ifname": true, "check-virtual-desktop": true, "use-peer-dns": true, "no-routes": true,
}

var ocOFVDistinct = map[string]bool{
	"trusted-cert": true, "set-dns": true, "set-routes": true, "half-internet-routes": true, "pppd-use-peerdns": true,
	"pppd-log": true, "pppd-plugin": true, "pppd-ipparam": true, "pppd-ifname": true, "pppd-call": true, "pppd-accept-remote": true,
	"otp-prompt": true, "otp-delay": true, "no-ftm-push": true, "insecure-ssl": true, "seclevel-1": true, "use-resolvconf": true,
	"saml-login": true, "check-virtual-desktop": true, "user-cert": true, "user-key": true, "persistent": true, "min-tls": true,
}

func ocOFVLines(text string) ([][2]string, bool) {
	var out [][2]string
	known, unknown := 0, 0
	distinct, host := false, false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") || strings.HasPrefix(line, "<") || strings.HasPrefix(line, "{") {
			return nil, false
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			unknown++
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = unquote(strings.TrimSpace(v))
		if ocOFVKeys[k] {
			known++
			if ocOFVDistinct[k] {
				distinct = true
			}
			if k == "host" && v != "" {
				host = true
			}
		} else {
			unknown++
		}
		out = append(out, [2]string{k, v})
	}
	if !host || !distinct || known < 2 || unknown*4 > known {
		return nil, false
	}
	return out, true
}

type ocOFVFormat struct{}

func (ocOFVFormat) Detect(f *vfile) int {
	if len(f.Data) == 0 || len(f.Data) > 64<<10 || !f.IsText() {
		return 0
	}
	if _, ok := ocOFVLines(f.Text()); ok {
		return 65
	}
	return 0
}

func (ocOFVFormat) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	lines, _ := ocOFVLines(f.Text())
	spec := &ocSpec{Protocol: "fortinet", Name: strings.TrimSuffix(f.Name, path.Ext(f.Name))}
	var warns []string
	var certDeps, deps []*vfile
	var certFile, keyFile *vfile
	for _, kv := range lines {
		k, v := kv[0], kv[1]
		switch k {
		case "host":
			spec.Host = v
		case "port":
			if n, err := strconv.Atoi(v); err == nil {
				spec.Port = n
			}
		case "username":
			spec.Username = v
		case "password":
			spec.Password = v
		case "realm":
			spec.Group = v
		case "trusted-cert":
			h := strings.ToLower(strings.ReplaceAll(v, ":", ""))
			if len(h) == 64 && ocIsHex(h) {
				if spec.ServerCertPin != "" {
					spec.ServerCertPin += ","
				}
				spec.ServerCertPin += "sha256:" + h
			} else {
				warns = append(warns, "unrecognized trusted-cert value ignored")
			}
		case "ca-file":
			if g := fs.Resolve(f, v); g != nil {
				spec.CACert = append(spec.CACert, g.Data...)
				certDeps = append(certDeps, g)
			} else {
				warns = append(warns, "CA file "+path.Base(v)+" not found")
			}
		case "user-cert":
			if strings.HasPrefix(v, "pkcs11:") {
				warns = append(warns, "PKCS#11 client certificate cannot be used")
			} else if g := fs.Resolve(f, v); g != nil {
				certFile = g
				certDeps = append(certDeps, g)
			} else {
				warns = append(warns, "client certificate "+path.Base(v)+" not found")
			}
		case "user-key":
			if g := fs.Resolve(f, v); g != nil {
				keyFile = g
				deps = append(deps, g)
			} else {
				warns = append(warns, "client key "+path.Base(v)+" not found")
			}
		case "saml-login":
			warns = append(warns, "SAML login configured")
		}
	}
	if certFile != nil {
		spec.ClientCert = certFile.Data
		if keyFile != nil {
			spec.ClientKey = keyFile.Data
		}
	}
	c := ocConfig(f, fs, spec)
	c.Format = "openfortivpn"
	for _, w := range warns {
		c.Warn("%s", w)
	}
	for _, d := range certDeps {
		c.AddDep(fs, d, true)
	}
	for _, d := range deps {
		c.AddDep(fs, d, false)
	}
	c.RawConfig = f.Data
	return []*Config{c}, nil
}

func init() {
	registerFormat(&fileFormat{Name: "openfortivpn", Detector: ocOFVFormat{}, Parser: ocOFVFormat{}})
}
