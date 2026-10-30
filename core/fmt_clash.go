package main

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	yaml2 "gopkg.in/yaml.v2"
)

var clTopRe = regexp.MustCompile(`(?m)^(proxies|proxy-providers)\s*:|"proxies"\s*:`)

var clKeyRe = regexp.MustCompile(`^("[^"]*"|'[^']*'|[A-Za-z0-9_.][^:#]*?)\s*:(\s|$)`)

var clBuiltin = map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}

func clNorm(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = clNorm(e)
		}
		return t
	case map[any]any:
		o := make(map[string]any, len(t))
		for k, e := range t {
			o[fmt.Sprint(k)] = clNorm(e)
		}
		return o
	case []any:
		for i, e := range t {
			t[i] = clNorm(e)
		}
		return t
	}
	return v
}

type clNode struct{ v any }

func (n *clNode) UnmarshalYAML(un func(any) error) error {
	var r any
	if err := un(&r); err != nil {
		return err
	}
	switch r.(type) {
	case nil:
		n.v = nil
		return nil
	case map[any]any, map[string]any:
		var m map[string]clNode
		if err := un(&m); err != nil {
			n.v = clNorm(r)
			return nil
		}
		o := make(map[string]any, len(m))
		for k, x := range m {
			o[k] = x.v
		}
		n.v = o
		return nil
	case []any:
		var l []clNode
		if err := un(&l); err != nil {
			n.v = clNorm(r)
			return nil
		}
		o := make([]any, len(l))
		for i, x := range l {
			o[i] = x.v
		}
		n.v = o
		return nil
	}
	var s string
	if un(&s) == nil {
		switch r.(type) {
		case bool:
			if !strings.EqualFold(s, "true") && !strings.EqualFold(s, "false") {
				n.v = s
				return nil
			}
		case int, int64, uint64, float64:
			if len(s) > 1 && s[0] == '0' && s[1] >= '0' && s[1] <= '9' || strings.Contains(s, "_") {
				n.v = s
				return nil
			}
		}
	}
	n.v = r
	return nil
}

func clDecode(b []byte) (map[string]any, error) {
	var root clNode
	if err := yaml2.Unmarshal(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}), &root); err != nil {
		return nil, err
	}
	doc, ok := root.v.(map[string]any)
	if !ok || doc == nil {
		return nil, errors.New("not a YAML mapping")
	}
	return doc, nil
}

func clMarshal(v any) ([]byte, error) {
	return yaml2.Marshal(v)
}

type MihomoConfigDetector struct{}

func (MihomoConfigDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) == 0 {
		return 0
	}
	t := f.Text()
	if !clTopRe.MatchString(t) {
		return 0
	}
	doc, err := clDecode(f.Data)
	if err != nil {
		if strings.Contains(t, "type:") && strings.Contains(t, "server:") {
			return 20
		}
		return 0
	}
	n := 0
	for _, p := range pxList(doc, "proxies") {
		if m, ok := p.(map[string]any); ok && pxStr(m, "type") != "" && pxStr(m, "name") != "" {
			n++
		}
	}
	if n > 0 {
		return 75
	}
	if len(pxMap(doc, "proxy-providers")) > 0 {
		return 30
	}
	return 0
}

type MihomoConfigParser struct{}

func (MihomoConfigParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	doc, err := clDecode(f.Data)
	if err != nil {
		return nil, err
	}
	ps := pxList(doc, "proxies")
	if len(ps) == 0 {
		if len(pxMap(doc, "proxy-providers")) > 0 {
			return []*Config{unsupportedConfig(f, "Clash", "", "config only references proxy-providers; scan the provider files directly")}, nil
		}
		return nil, errors.New("no proxies in config")
	}
	byName := map[string]map[string]any{}
	for _, p := range ps {
		if m, ok := p.(map[string]any); ok {
			byName[pxStr(m, "name")] = m
		}
	}
	groups := clGroups(doc)
	warns := clCheckGroups(doc, byName, groups)
	out := make([]*Config, 0, len(ps))
	for i, p := range ps {
		m, ok := p.(map[string]any)
		if !ok {
			out = append(out, invalidConfig(f, "Clash", fmt.Errorf("proxies[%d] is not a mapping", i)))
			continue
		}
		c := clConfig(f, m, byName, groups)
		pxWarnAll(c, warns)
		c.RawConfig, _ = clMarshal(m)
		out = append(out, c)
	}
	return out, nil
}

func clGroups(doc map[string]any) map[string][]string {
	groups := map[string][]string{}
	for _, g := range pxList(doc, "proxy-groups") {
		if gm, ok := g.(map[string]any); ok {
			groups[pxStr(gm, "name")] = pxStrs(gm["proxies"])
		}
	}
	return groups
}

func clCheckGroups(doc map[string]any, byName map[string]map[string]any, groups map[string][]string) []string {
	var w []string
	for _, g := range pxList(doc, "proxy-groups") {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		for _, mem := range pxStrs(gm["proxies"]) {
			if _, ok := byName[mem]; ok {
				continue
			}
			if _, ok := groups[mem]; ok || clBuiltin[strings.ToUpper(mem)] {
				continue
			}
			if len(w) < 3 {
				w = append(w, fmt.Sprintf("proxy-group %q references unknown proxy %q", pxStr(gm, "name"), mem))
			}
		}
	}
	return w
}

func clCompat(m map[string]any) []string {
	var notes []string
	typ := strings.ToLower(pxStr(m, "type"))
	m["type"] = typ
	switch typ {
	case "hysteria2":
		if !pxHas(m, "password") && pxHas(m, "auth") {
			m["password"] = pxStr(m, "auth")
			delete(m, "auth")
		}
		if !pxHas(m, "up") && pxHas(m, "up-speed") {
			m["up"] = pxStr(m, "up-speed")
		}
		if !pxHas(m, "down") && pxHas(m, "down-speed") {
			m["down"] = pxStr(m, "down-speed")
		}
		delete(m, "up-speed")
		delete(m, "down-speed")
	case "vmess", "vless", "trojan":
		if strings.EqualFold(pxStr(m, "network"), "ws") && !pxHas(m, "ws-opts") && (pxHas(m, "ws-path") || pxHas(m, "ws-headers")) {
			ws := map[string]any{"path": firstNonEmpty(pxStr(m, "ws-path"), "/")}
			if h := pxMap(m, "ws-headers"); h != nil {
				ws["headers"] = h
			}
			m["ws-opts"] = ws
			delete(m, "ws-path")
			delete(m, "ws-headers")
			notes = append(notes, "legacy ws-path/ws-headers converted to ws-opts")
		}
	}
	return append(notes, pxSanitize(m)...)
}

func clResolve(name string, byName map[string]map[string]any, groups map[string][]string, depth int) (map[string]any, error) {
	if depth > 8 {
		return nil, fmt.Errorf("dialer-proxy %q nests too deep", name)
	}
	if m, ok := byName[name]; ok {
		return m, nil
	}
	if mem, ok := groups[name]; ok {
		for _, x := range mem {
			if clBuiltin[strings.ToUpper(x)] {
				continue
			}
			if m, err := clResolve(x, byName, groups, depth+1); err == nil {
				return m, nil
			}
		}
		return nil, fmt.Errorf("dialer-proxy group %q has no usable proxy", name)
	}
	return nil, fmt.Errorf("dialer-proxy %q not found", name)
}

func clChain(m map[string]any, byName map[string]map[string]any, groups map[string][]string) ([]map[string]any, []string, error) {
	chain := []map[string]any{m}
	var notes []string
	seen := map[string]bool{pxStr(m, "name"): true}
	cur := m
	for i := 0; i < 8; i++ {
		dp := pxStr(cur, "dialer-proxy")
		if dp == "" || strings.EqualFold(dp, "DIRECT") {
			return chain, notes, nil
		}
		t, err := clResolve(dp, byName, groups, 0)
		if err != nil {
			return chain, notes, err
		}
		tn := pxStr(t, "name")
		if seen[tn] {
			return chain, notes, fmt.Errorf("dialer-proxy loop at %q", tn)
		}
		seen[tn] = true
		if _, isGroup := groups[dp]; isGroup {
			notes = append(notes, fmt.Sprintf("dialer-proxy group %q resolved to %q", dp, tn))
		}
		cp := pxCopyMap(t)
		notes = append(notes, clCompat(cp)...)
		chain = append([]map[string]any{cp}, chain...)
		cur = cp
	}
	return chain, notes, errors.New("dialer-proxy chain too long")
}

func clConfig(f *vfile, raw map[string]any, byName map[string]map[string]any, groups map[string][]string) *Config {
	m := pxCopyMap(raw)
	name := pxStr(m, "name")
	typ := strings.ToLower(pxStr(m, "type"))
	mk := func(c *Config) *Config {
		c.Name = name
		c.Host = pxStr(m, "server")
		c.Port = pxInt(m, "port")
		return c
	}
	switch {
	case typ == "":
		return mk(invalidConfig(f, "Clash", errors.New("proxy has no type")))
	case pxNonProxyTypes[typ]:
		return mk(unsupportedConfig(f, "Clash", typ, typ+" is not a remote proxy"))
	case pxMeshTypes[typ]:
		return mk(unsupportedConfig(f, "Clash", typ, typ+" joins a mesh network; not tested"))
	case !pxMihomoTypes[typ]:
		return mk(unsupportedConfig(f, "Clash", typ, "proxy type "+typ+" is not supported by mihomo"))
	}
	notes := clCompat(m)
	chain, cn, err := clChain(m, byName, groups)
	c := pxMihomoConfig(f, "Clash", chain, name, err)
	pxWarnAll(c, notes)
	pxWarnAll(c, cn)
	return c
}

type MihomoConfigFilter struct{}

func clDeps(name string, byName map[string]int, groups map[string][]string, depth int, out map[int]bool) {
	if name == "" || depth > 8 {
		return
	}
	if i, ok := byName[name]; ok {
		out[i] = true
		return
	}
	for _, x := range groups[name] {
		clDeps(x, byName, groups, depth+1, out)
	}
}

func (MihomoConfigFilter) Filter(f *vfile, idx []int) ([]byte, error) {
	doc, err := clDecode(f.Data)
	if err != nil {
		return f.Data, nil
	}
	ps := pxList(doc, "proxies")
	if len(ps) == 0 {
		return f.Data, nil
	}
	keep := make([]bool, len(ps))
	for _, i := range idx {
		if i >= 0 && i < len(ps) {
			keep[i] = true
		}
	}
	names := make([]string, len(ps))
	byName := map[string]int{}
	for i, p := range ps {
		m, _ := p.(map[string]any)
		names[i] = pxStr(m, "name")
		if _, dup := byName[names[i]]; !dup {
			byName[names[i]] = i
		}
	}
	groups := clGroups(doc)
	for changed := true; changed; {
		changed = false
		for i, p := range ps {
			if !keep[i] {
				continue
			}
			m, _ := p.(map[string]any)
			deps := map[int]bool{}
			clDeps(pxStr(m, "dialer-proxy"), byName, groups, 0, deps)
			for j := range deps {
				if !keep[j] {
					keep[j] = true
					changed = true
				}
			}
		}
	}
	removed := map[string]bool{}
	var kept []any
	var keptNames []string
	for i, p := range ps {
		if keep[i] {
			kept = append(kept, p)
			keptNames = append(keptNames, names[i])
		}
	}
	for i := range ps {
		if !keep[i] && names[i] != "" {
			removed[names[i]] = true
		}
	}
	for _, n := range keptNames {
		delete(removed, n)
	}
	if len(kept) == len(ps) {
		return f.Data, nil
	}
	if kept == nil {
		kept = []any{}
	}
	repl := map[string]any{}
	if gs := pxList(doc, "proxy-groups"); len(gs) > 0 {
		if ng, ch := clPruneGroups(gs, removed); ch {
			repl["proxy-groups"] = ng
		}
	}
	fallback := "DIRECT"
	if ng, ok := repl["proxy-groups"].([]any); ok && len(ng) > 0 {
		fallback = pxStr(ng[0].(map[string]any), "name")
	} else if gs := pxList(doc, "proxy-groups"); len(gs) > 0 {
		if gm, ok := gs[0].(map[string]any); ok {
			fallback = pxStr(gm, "name")
		}
	} else if len(keptNames) > 0 {
		fallback = keptNames[0]
	}
	if rules := pxList(doc, "rules"); len(rules) > 0 {
		if nr, ch := clPruneRules(rules, removed, fallback); ch {
			repl["rules"] = nr
		}
	}
	if sr := pxMap(doc, "sub-rules"); len(sr) > 0 {
		ch := false
		for k := range sr {
			if l, ok := sr[k].([]any); ok {
				if nr, c := clPruneRules(l, removed, ""); c {
					sr[k] = nr
					ch = true
				}
			}
		}
		if ch {
			repl["sub-rules"] = sr
		}
	}
	if out, ok := clRewrite(f.Text(), keep, kept, repl); ok && clVerify(out, keptNames) {
		return out, nil
	}
	doc["proxies"] = kept
	for k, v := range repl {
		doc[k] = v
	}
	if b, err := clMarshal(clOrdered(doc)); err == nil && clVerify(b, keptNames) {
		return b, nil
	}
	return f.Data, nil
}

func clGroupHasSources(gm map[string]any) bool {
	return pxHas(gm, "use") || pxBool(gm, "include-all") || pxBool(gm, "include-all-proxies") || pxBool(gm, "include-all-providers")
}

func clPruneGroups(gs []any, removed map[string]bool) ([]any, bool) {
	alive := make([]bool, len(gs))
	for i := range alive {
		alive[i] = true
	}
	changed := false
	for again := true; again; {
		again = false
		for i, g := range gs {
			gm, ok := g.(map[string]any)
			if !alive[i] || !ok {
				continue
			}
			members := pxList(gm, "proxies")
			nm := []any{}
			for _, x := range members {
				if !removed[pxScalar(x)] {
					nm = append(nm, x)
				}
			}
			if len(nm) != len(members) {
				changed = true
				if len(nm) == 0 {
					delete(gm, "proxies")
				} else {
					gm["proxies"] = nm
				}
			}
			if len(nm) == 0 && len(members) > 0 && !clGroupHasSources(gm) {
				alive[i] = false
				removed[pxStr(gm, "name")] = true
				again = true
				changed = true
			}
		}
	}
	out := []any{}
	for i, g := range gs {
		if alive[i] {
			out = append(out, g)
		}
	}
	return out, changed
}

func clRuleTarget(fields []string) int {
	if len(fields) < 2 {
		return -1
	}
	switch strings.ToUpper(fields[0]) {
	case "MATCH", "FINAL":
		return 1
	case "SUB-RULE":
		return -1
	}
	if len(fields) < 3 {
		return -1
	}
	return 2
}

func clPruneRules(rules []any, removed map[string]bool, fallback string) ([]any, bool) {
	out := []any{}
	changed := false
	for _, r := range rules {
		s, ok := r.(string)
		if !ok {
			out = append(out, r)
			continue
		}
		fields := pxSplitTop(s, ',')
		ti := clRuleTarget(fields)
		if ti < 0 || !removed[fields[ti]] {
			out = append(out, r)
			continue
		}
		changed = true
		if ti == 1 && fallback != "" {
			fields[1] = fallback
			out = append(out, strings.Join(fields, ","))
		}
	}
	return out, changed
}

type clSec struct {
	key        string
	start, end int
}

func clSections(lines []string) []clSec {
	var secs []clSec
	for i, l := range lines {
		if l == "" || l[0] == ' ' || l[0] == '\t' || l[0] == '#' || l[0] == '-' {
			if strings.HasPrefix(l, "---") && len(secs) > 0 {
				secs[len(secs)-1].end = i
			}
			continue
		}
		mm := clKeyRe.FindStringSubmatch(l)
		if mm == nil {
			continue
		}
		if len(secs) > 0 && secs[len(secs)-1].end < 0 {
			secs[len(secs)-1].end = i
		}
		secs = append(secs, clSec{key: strings.Trim(mm[1], `"'`), start: i, end: -1})
	}
	if len(secs) > 0 && secs[len(secs)-1].end < 0 {
		secs[len(secs)-1].end = len(lines)
	}
	return secs
}

func clOrdered(v any) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			ri, rj := clKeyRank(keys[i]), clKeyRank(keys[j])
			if ri != rj {
				return ri < rj
			}
			return keys[i] < keys[j]
		})
		ms := make(yaml2.MapSlice, 0, len(keys))
		for _, k := range keys {
			ms = append(ms, yaml2.MapItem{Key: k, Value: clOrdered(x[k])})
		}
		return ms
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = clOrdered(e)
		}
		return out
	}
	return v
}

func clKeyRank(k string) int {
	switch k {
	case "name":
		return 0
	case "type":
		return 1
	case "server":
		return 2
	case "port":
		return 3
	}
	return 4
}

func clMarshalSection(key string, v any) ([]string, error) {
	b, err := clMarshal(yaml2.MapSlice{{Key: key, Value: clOrdered(v)}})
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n"), nil
}

func clTrailing(sec []string) []string {
	i := len(sec)
	for i > 1 && strings.TrimSpace(sec[i-1]) == "" {
		i--
	}
	return sec[i:]
}

func clCutItems(sec []string, keep []bool) ([]string, bool) {
	head := sec[0]
	_, rest, _ := strings.Cut(head, ":")
	rest = strings.TrimSpace(rest)
	if rest != "" && !strings.HasPrefix(rest, "#") {
		return nil, false
	}
	ind := -1
	var starts []int
	for i := 1; i < len(sec); i++ {
		l := sec[i]
		t := strings.TrimLeft(l, " ")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		cur := len(l) - len(t)
		if ind < 0 {
			if !(strings.HasPrefix(t, "- ") || t == "-") {
				return nil, false
			}
			ind = cur
		}
		if cur == ind && (strings.HasPrefix(t, "- ") || t == "-") {
			starts = append(starts, i)
		} else if cur < ind {
			return nil, false
		}
	}
	if len(starts) != len(keep) {
		return nil, false
	}
	out := append([]string{head}, sec[1:starts[0]]...)
	for k, st := range starts {
		end := len(sec)
		if k+1 < len(starts) {
			end = starts[k+1]
		}
		if keep[k] {
			out = append(out, sec[st:end]...)
		}
	}
	return out, true
}

func clRewrite(text string, keep []bool, kept []any, repl map[string]any) ([]byte, bool) {
	lines := strings.Split(text, "\n")
	secs := clSections(lines)
	var out []string
	pos := 0
	seen := map[string]bool{}
	for _, s := range secs {
		out = append(out, lines[pos:s.start]...)
		pos = s.end
		if seen[s.key] {
			return nil, false
		}
		seen[s.key] = true
		switch v, ok := repl[s.key]; {
		case s.key == "proxies":
			sec, ok := clCutItems(lines[s.start:s.end], keep)
			if !ok {
				var err error
				if sec, err = clMarshalSection("proxies", kept); err != nil {
					return nil, false
				}
				sec = append(sec, clTrailing(lines[s.start:s.end])...)
			}
			out = append(out, sec...)
		case ok:
			sec, err := clMarshalSection(s.key, v)
			if err != nil {
				return nil, false
			}
			out = append(out, sec...)
			out = append(out, clTrailing(lines[s.start:s.end])...)
		default:
			out = append(out, lines[s.start:s.end]...)
		}
	}
	out = append(out, lines[pos:]...)
	if !seen["proxies"] {
		return nil, false
	}
	for k := range repl {
		if !seen[k] {
			return nil, false
		}
	}
	return []byte(strings.Join(out, "\n")), true
}

func clVerify(b []byte, names []string) bool {
	doc, err := clDecode(b)
	if err != nil {
		return false
	}
	ps := pxList(doc, "proxies")
	if len(ps) != len(names) {
		return false
	}
	for i, p := range ps {
		m, _ := p.(map[string]any)
		if pxStr(m, "name") != names[i] {
			return false
		}
	}
	return true
}

func init() {
	registerFormat(&fileFormat{Name: "Clash", Detector: MihomoConfigDetector{}, Parser: MihomoConfigParser{}, Filter: MihomoConfigFilter{}})
}
