package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

type ocNode struct {
	Name     string
	Attrs    []xml.Attr
	Children []*ocNode
	Text     string
}

func ocParseXML(b []byte) *ocNode {
	root := &ocNode{}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	d.AutoClose = xml.HTMLAutoClose
	d.Entity = xml.HTMLEntity
	d.CharsetReader = func(label string, input io.Reader) (io.Reader, error) { return input, nil }
	stack := []*ocNode{root}
	n := 0
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		n++
		if n > 200000 {
			break
		}
		cur := stack[len(stack)-1]
		switch t := tok.(type) {
		case xml.StartElement:
			nd := &ocNode{Name: t.Name.Local, Attrs: append([]xml.Attr(nil), t.Attr...)}
			cur.Children = append(cur.Children, nd)
			if len(stack) < 64 {
				stack = append(stack, nd)
			}
		case xml.EndElement:
			for i := len(stack) - 1; i > 0; i-- {
				if strings.EqualFold(stack[i].Name, t.Name.Local) {
					stack = stack[:i]
					break
				}
			}
		case xml.CharData:
			if len(cur.Text) < 1<<20 {
				cur.Text += string(t)
			}
		case xml.Comment:
			if len(cur.Text) < 1<<20 {
				cur.Children = append(cur.Children, &ocNode{Name: "#comment", Text: string(t)})
			}
		}
	}
	return root
}

func (n *ocNode) attr(name string) (string, bool) {
	if n == nil {
		return "", false
	}
	for _, a := range n.Attrs {
		if strings.EqualFold(a.Name.Local, name) {
			return a.Value, true
		}
	}
	return "", false
}

func (n *ocNode) a(name string) string {
	v, _ := n.attr(name)
	return v
}

func (n *ocNode) child(name string) *ocNode {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if strings.EqualFold(c.Name, name) {
			return c
		}
	}
	return nil
}

func (n *ocNode) children(name string) []*ocNode {
	if n == nil {
		return nil
	}
	var out []*ocNode
	for _, c := range n.Children {
		if strings.EqualFold(c.Name, name) {
			out = append(out, c)
		}
	}
	return out
}

func (n *ocNode) find(name string) *ocNode {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if strings.EqualFold(c.Name, name) {
			return c
		}
		if f := c.find(name); f != nil {
			return f
		}
	}
	return nil
}

func (n *ocNode) text() string {
	if n == nil {
		return ""
	}
	return strings.TrimSpace(n.Text)
}

func (n *ocNode) deepText() string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	var walk func(*ocNode)
	walk = func(x *ocNode) {
		if x.Name == "#comment" {
			return
		}
		b.WriteString(x.Text)
		b.WriteByte(' ')
		for _, c := range x.Children {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

func (n *ocNode) childText(name string) string {
	return n.child(name).text()
}

func (n *ocNode) xml(b *strings.Builder) {
	if n.Name == "#comment" {
		return
	}
	b.WriteByte('<')
	b.WriteString(n.Name)
	for _, a := range n.Attrs {
		b.WriteByte(' ')
		if a.Name.Space != "" && a.Name.Space != "xmlns" {
			b.WriteString(a.Name.Space)
			b.WriteByte(':')
		} else if a.Name.Space == "xmlns" {
			b.WriteString("xmlns:")
		}
		b.WriteString(a.Name.Local)
		b.WriteString("=\"")
		xml.EscapeText(b, []byte(a.Value))
		b.WriteByte('"')
	}
	if len(n.Children) == 0 && strings.TrimSpace(n.Text) == "" {
		b.WriteString("/>")
		return
	}
	b.WriteByte('>')
	xml.EscapeText(b, []byte(strings.TrimSpace(n.Text)))
	for _, c := range n.Children {
		c.xml(b)
	}
	b.WriteString("</")
	b.WriteString(n.Name)
	b.WriteByte('>')
}

func ocXMLEsc(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

type ocField struct {
	Tag     string
	Type    string
	Name    string
	ID      string
	Value   string
	Label   string
	Checked bool
	Options []ocOption
}

type ocOption struct {
	Value    string
	Label    string
	Selected bool
}

type ocForm struct {
	Name   string
	ID     string
	Action string
	Method string
	Fields []*ocField
}

func ocParseHTMLForms(b []byte) []*ocForm {
	z := html.NewTokenizer(bytes.NewReader(b))
	var forms []*ocForm
	var cur *ocForm
	var sel *ocField
	var opt *ocOption
	steps := 0
	for {
		steps++
		if steps > 500000 {
			break
		}
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := z.TagName()
			name := string(tn)
			attrs := map[string]string{}
			if hasAttr {
				for {
					k, v, more := z.TagAttr()
					attrs[strings.ToLower(string(k))] = string(v)
					if !more {
						break
					}
				}
			}
			switch name {
			case "form":
				cur = &ocForm{Name: attrs["name"], ID: attrs["id"], Action: attrs["action"], Method: strings.ToUpper(attrs["method"])}
				if _, ok := attrs["action"]; !ok {
					cur.Action = ""
				}
				forms = append(forms, cur)
			case "input", "button", "textarea":
				if cur == nil {
					continue
				}
				typ := strings.ToLower(attrs["type"])
				if name == "input" && typ == "" {
					typ = "text"
				}
				if name == "button" && typ == "" {
					typ = "submit"
				}
				if name == "textarea" {
					typ = "text"
				}
				_, checked := attrs["checked"]
				cur.Fields = append(cur.Fields, &ocField{Tag: name, Type: typ, Name: attrs["name"], ID: attrs["id"], Value: attrs["value"], Label: firstNonEmpty(attrs["placeholder"], attrs["aria-label"], attrs["title"]), Checked: checked})
			case "select":
				if cur == nil {
					continue
				}
				sel = &ocField{Tag: "select", Type: "select", Name: attrs["name"], ID: attrs["id"]}
				cur.Fields = append(cur.Fields, sel)
			case "option":
				if sel == nil {
					continue
				}
				_, s := attrs["selected"]
				v, hasV := attrs["value"]
				sel.Options = append(sel.Options, ocOption{Value: v, Selected: s})
				opt = &sel.Options[len(sel.Options)-1]
				if !hasV {
					opt.Value = "\x00"
				}
			}
		case html.TextToken:
			if opt != nil && len(opt.Label) < 512 {
				opt.Label += string(z.Text())
			}
		case html.EndTagToken:
			tn, _ := z.TagName()
			switch string(tn) {
			case "form":
				cur = nil
				sel, opt = nil, nil
			case "select":
				sel, opt = nil, nil
			case "option":
				opt = nil
			}
		}
	}
	for _, f := range forms {
		for _, fl := range f.Fields {
			for i := range fl.Options {
				o := &fl.Options[i]
				o.Label = strings.TrimSpace(html.UnescapeString(o.Label))
				if o.Value == "\x00" {
					o.Value = o.Label
				}
			}
		}
	}
	return forms
}

func (f *ocForm) field(name string) *ocField {
	for _, fl := range f.Fields {
		if strings.EqualFold(fl.Name, name) {
			return fl
		}
	}
	return nil
}

func (f *ocForm) hasPassword() bool {
	for _, fl := range f.Fields {
		if fl.Type == "password" {
			return true
		}
	}
	return false
}

func ocFindForm(forms []*ocForm, names ...string) *ocForm {
	for _, n := range names {
		for _, f := range forms {
			if strings.EqualFold(f.Name, n) || strings.EqualFold(f.ID, n) {
				return f
			}
		}
	}
	return nil
}

var ocScriptRe = regexp.MustCompile(`(?is)<(script|style)[^>]*>.*?</(script|style)>`)
var ocTagRe = regexp.MustCompile(`(?s)<[^>]*>`)

func ocStripTags(s string) string {
	s = ocScriptRe.ReplaceAllString(s, " ")
	s = ocTagRe.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(html.UnescapeString(s)), " ")
}

func ocChooseOption(fl *ocField, want string) (string, bool) {
	if len(fl.Options) == 0 {
		return fl.Value, want == ""
	}
	if want != "" {
		for _, o := range fl.Options {
			if strings.EqualFold(o.Value, want) || strings.EqualFold(o.Label, want) {
				return o.Value, true
			}
		}
	}
	for _, o := range fl.Options {
		if o.Selected {
			return o.Value, want == ""
		}
	}
	return fl.Options[0].Value, want == ""
}

func ocOptionList(fl *ocField) string {
	var names []string
	for _, o := range fl.Options {
		l := o.Label
		if l == "" {
			l = o.Value
		}
		names = append(names, l)
		if len(names) >= 6 {
			break
		}
	}
	return strings.Join(names, ", ")
}
