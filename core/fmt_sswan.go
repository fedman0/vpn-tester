package main

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

func swJSONObj(m map[string]any, k string) map[string]any {
	for mk, v := range m {
		if strings.EqualFold(mk, k) {
			if o, ok := v.(map[string]any); ok {
				return o
			}
		}
	}
	return map[string]any{}
}

func swSswanObjects(f *vfile) []map[string]any {
	t := strings.TrimSpace(f.Text())
	if !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(t), &v); err != nil {
		return nil
	}
	var list []any
	switch x := v.(type) {
	case map[string]any:
		list = []any{x}
	case []any:
		list = x
	}
	var out []map[string]any
	for _, it := range list {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		typ := strings.ToLower(jsonString(m, "type"))
		remote := swJSONObj(m, "remote")
		if strings.HasPrefix(typ, "ikev2") || (jsonString(remote, "addr") != "" && (jsonString(m, "uuid") != "" || f.Ext == "sswan")) {
			out = append(out, m)
		}
	}
	return out
}

type SswanDetector struct{}

func (SswanDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) > 4<<20 {
		return 0
	}
	if len(swSswanObjects(f)) > 0 {
		return 92
	}
	return 0
}

type SswanParser struct{}

func (SswanParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	objs := swSswanObjects(f)
	if len(objs) == 0 {
		return nil, errors.New("not a strongSwan profile")
	}
	var out []*Config
	for _, m := range objs {
		out = append(out, swSswanConfig(f, fs, m))
	}
	return out, nil
}

func swSswanConfig(f *vfile, fs *vfs, m map[string]any) *Config {
	remote := swJSONObj(m, "remote")
	local := swJSONObj(m, "local")
	typ := strings.ToLower(jsonString(m, "type"))
	spec := &ikeSpec{Version: 2, Kind: "sswan"}
	spec.Name = firstNonEmpty(jsonString(m, "name"), jsonString(remote, "addr"))
	spec.Host = jsonString(remote, "addr")
	if p, err := strconv.Atoi(jsonString(remote, "port")); err == nil {
		spec.Port = p
	}
	spec.RemoteID = jsonString(remote, "id")
	spec.LocalID = jsonString(local, "id")
	spec.Username = firstNonEmpty(jsonString(local, "eap_id", "eap-id", "username", "user"), jsonString(m, "username", "user", "eap_id"))
	spec.Password = firstNonEmpty(jsonString(local, "password", "eap_password"), jsonString(m, "password"))
	spec.PSK = firstNonEmpty(jsonString(local, "psk", "secret", "shared-secret"), jsonString(m, "psk", "shared-secret", "secret"))
	if v := jsonString(m, "ike-proposal", "ike_proposal"); v != "" {
		spec.IKEProposals = []string{v}
	}
	if v := jsonString(m, "esp-proposal", "esp_proposal"); v != "" {
		spec.ESPProposals = []string{v}
	}
	switch typ {
	case "ikev2-eap":
		spec.Auth = "eap"
	case "ikev2-cert":
		spec.Auth = "pubkey"
	case "ikev2-cert-eap":
		spec.Auth = "pubkey+eap"
	case "ikev2-eap-tls":
		spec.Auth = "eap-tls"
	case "ikev2-byod-eap":
		spec.Auth = "byod"
	case "ikev2-psk":
		spec.Auth = "psk"
	default:
		spec.Auth = ""
	}
	var warns []string
	if ca := jsonString(remote, "cert"); ca != "" {
		if pm := swCertPEM([]byte(ca)); pm != nil {
			spec.CACerts = append(spec.CACerts, pm)
		} else {
			warns = append(warns, "remote.cert could not be decoded")
		}
	}
	if p12 := jsonString(local, "p12"); p12 != "" {
		raw, err := b64decode(p12)
		if err != nil {
			warns = append(warns, "local.p12 is not valid base64")
		} else {
			cert, key, cas, err := decodePKCS12(raw, firstNonEmpty(jsonString(local, "p12-password", "p12_password", "p12password"), spec.Password))
			if err != nil {
				warns = append(warns, swP12Err(err))
			} else {
				spec.ClientCert = cert
				spec.ClientKey = key
				for _, ca := range cas {
					cs := ike2ParseCerts(ca)
					if len(cs) == 1 && cs[0].IsCA {
						spec.CACerts = append(spec.CACerts, ca)
					} else {
						spec.ClientCert = append(spec.ClientCert, ca...)
					}
				}
			}
		}
	}
	if spec.Host == "" {
		c := invalidConfig(f, "strongSwan", errors.New("missing remote.addr"))
		c.Name = spec.Name
		return c
	}
	if spec.Auth == "" {
		c := unsupportedConfig(f, "strongSwan", "IKEv2", "unknown strongSwan profile type "+typ)
		c.Name, c.Host = spec.Name, spec.Host
		return c
	}
	c := ikeConfig(f, fs, spec)
	c.Format = "strongSwan"
	if spec.Auth == "byod" {
		c.Warn("BYOD (EAP-TTLS/TNC) profile: only the IKE handshake and server authentication can be tested")
	}
	c.Warnings = append(c.Warnings, warns...)
	return c
}

func init() {
	registerFormat(&fileFormat{Name: "strongSwan", Detector: SswanDetector{}, Parser: SswanParser{}})
}
