package web

import (
	"bytes"
	"strings"
	"text/template"
)

const (
	winScript       = "windows.ps1"
	winRemoveScript = "windows-remove.ps1"
	winInstaller    = "ReDNS-Windows.cmd"
)

var winTmpl = template.Must(template.New("windows.ps1").Funcs(template.FuncMap{"psq": psq}).ParseFS(files, "templates/windows.ps1"))

type WindowsParams struct {
	Mode      string
	Host      string
	DoHURL    string
	ScriptURL string
	IPv4      string
	IPv6      string
	Label     string
}

func psq(s string) string {
	s = strings.NewReplacer("\r", "", "\n", " ", "‘", "'", "’", "'", "‚", "'", "‛", "'").Replace(s)
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func WindowsScript(p WindowsParams) []byte {
	var b bytes.Buffer
	if err := winTmpl.Execute(&b, p); err != nil {
		panic(err)
	}
	return []byte(strings.ReplaceAll(strings.ReplaceAll(b.String(), "\r\n", "\n"), "\n", "\r\n"))
}

func WindowsInstaller(scriptURL string) []byte {
	lines := []string{
		"@echo off",
		`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$env:REDNS_PAUSE='1'; [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; irm '` + strings.ReplaceAll(scriptURL, "'", "''") + `' | iex"`,
		"",
	}
	return []byte(strings.Join(lines, "\r\n"))
}

func WindowsCommand(scriptURL string) string {
	return "irm " + scriptURL + " | iex"
}
