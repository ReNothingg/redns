package web

import (
	"bytes"
	"crypto/sha1"
	"encoding/xml"
	"fmt"
	"strings"
)

type ProfileParams struct {
	Host      string
	DoHURL    string
	DoTName   string
	Addresses []string
	Label     string
	Only      string
	Consent   string
}

func uuidFor(parts ...string) string {
	sum := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16]))
}

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func Agreement(host string) string {
	raw, err := files.ReadFile("templates/agreement.txt")
	if err != nil {
		return ""
	}
	text := strings.ReplaceAll(string(raw), "**", "")
	return strings.ReplaceAll(text, "{host}", host)
}

func dnsPayload(b *strings.Builder, p ProfileParams, protocol string) {
	kind, server := "DoH", p.DoHURL
	if protocol == "TLS" {
		kind, server = "DoT", p.DoTName
	}
	name := "ReDNS · " + kind
	id := uuidFor(p.Host, protocol, server)
	b.WriteString("\t\t<dict>\n\t\t\t<key>DNSSettings</key>\n\t\t\t<dict>\n")
	b.WriteString("\t\t\t\t<key>DNSProtocol</key>\n\t\t\t\t<string>" + protocol + "</string>\n")
	if protocol == "HTTPS" {
		b.WriteString("\t\t\t\t<key>ServerURL</key>\n\t\t\t\t<string>" + esc(server) + "</string>\n")
	} else {
		b.WriteString("\t\t\t\t<key>ServerName</key>\n\t\t\t\t<string>" + esc(server) + "</string>\n")
	}
	if len(p.Addresses) > 0 {
		b.WriteString("\t\t\t\t<key>ServerAddresses</key>\n\t\t\t\t<array>\n")
		for _, a := range p.Addresses {
			b.WriteString("\t\t\t\t\t<string>" + esc(a) + "</string>\n")
		}
		b.WriteString("\t\t\t\t</array>\n")
	}
	b.WriteString("\t\t\t</dict>\n")
	b.WriteString("\t\t\t<key>PayloadDescription</key>\n\t\t\t<string>" + esc(kind+" через "+p.Host) + "</string>\n")
	b.WriteString("\t\t\t<key>PayloadDisplayName</key>\n\t\t\t<string>" + esc(name) + "</string>\n")
	b.WriteString("\t\t\t<key>PayloadIdentifier</key>\n\t\t\t<string>com.apple.dnsSettings.managed." + id + "</string>\n")
	b.WriteString("\t\t\t<key>PayloadType</key>\n\t\t\t<string>com.apple.dnsSettings.managed</string>\n")
	b.WriteString("\t\t\t<key>PayloadUUID</key>\n\t\t\t<string>" + id + "</string>\n")
	b.WriteString("\t\t\t<key>PayloadVersion</key>\n\t\t\t<integer>1</integer>\n")
	b.WriteString("\t\t\t<key>ProhibitDisablement</key>\n\t\t\t<false/>\n")
	b.WriteString("\t\t</dict>\n")
}

func Profile(p ProfileParams) []byte {
	protocols := []string{"HTTPS", "TLS"}
	switch p.Only {
	case "doh":
		protocols = []string{"HTTPS"}
	case "dot":
		protocols = []string{"TLS"}
	}
	title := "ReDNS"
	if p.Label != "" {
		title += " · " + p.Label
	}
	ident := "redns." + p.Host
	if p.Only != "" {
		ident += "." + p.Only
	}
	outer := uuidFor(ident, p.DoHURL, p.DoTName)

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`)
	if p.Consent != "" {
		b.WriteString("\t<key>ConsentText</key>\n\t<dict>\n")
		b.WriteString("\t\t<key>default</key>\n\t\t<string>" + esc(p.Consent) + "</string>\n")
		b.WriteString("\t\t<key>ru</key>\n\t\t<string>" + esc(p.Consent) + "</string>\n")
		b.WriteString("\t</dict>\n")
	}
	b.WriteString("\t<key>PayloadContent</key>\n\t<array>\n")
	for _, proto := range protocols {
		dnsPayload(&b, p, proto)
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>PayloadDescription</key>\n\t<string>" + esc("DNS-over-HTTPS и DNS-over-TLS через "+p.Host+". Активный режим выбирается в Настройках → Основные → VPN и управление устройством → DNS.") + "</string>\n")
	b.WriteString("\t<key>PayloadDisplayName</key>\n\t<string>" + esc(title) + "</string>\n")
	b.WriteString("\t<key>PayloadIdentifier</key>\n\t<string>" + esc(ident) + "</string>\n")
	b.WriteString("\t<key>PayloadOrganization</key>\n\t<string>ReDNS</string>\n")
	b.WriteString("\t<key>PayloadRemovalDisallowed</key>\n\t<false/>\n")
	b.WriteString("\t<key>PayloadScope</key>\n\t<string>System</string>\n")
	b.WriteString("\t<key>PayloadType</key>\n\t<string>Configuration</string>\n")
	b.WriteString("\t<key>PayloadUUID</key>\n\t<string>" + outer + "</string>\n")
	b.WriteString("\t<key>PayloadVersion</key>\n\t<integer>1</integer>\n")
	b.WriteString("</dict>\n</plist>\n")
	return []byte(b.String())
}
