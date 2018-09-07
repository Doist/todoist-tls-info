// Command todoist-tls-info connects to todoist.com:443 and dumps TLS session
// info to stdout and todoist-tls-info.txt file.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"text/tabwriter"
	"text/template"
	"time"
)

func main() {
	b, err := run()
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Stdout.Write(b)
	if name := "todoist-tls-info.txt"; ioutil.WriteFile(name, b, 0666) == nil {
		fmt.Println("\n✓ Report also saved to", name)
	}
}

func run() ([]byte, error) {
	const domain = "todoist.com"
	buf := new(bytes.Buffer)
	switch addrs, err := net.LookupHost(domain); err {
	case nil:
		fmt.Fprintf(buf, "%q resolved to:\n\n", domain)
		for _, addr := range addrs {
			fmt.Fprintf(buf, " - %s\n", addr)
		}
		fmt.Fprintln(buf)
	default:
		fmt.Fprintln(buf, "host lookup:", err)
	}
	conn, err := net.DialTimeout("tcp", domain+":443", 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	fmt.Fprintln(buf, "Connected to", conn.RemoteAddr())
	cfg := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	}
	tconn := tls.Client(conn, cfg)
	defer tconn.Close()
	if err := tconn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %v", err)
	}
	fns := template.FuncMap{"sha256sum": sha256.Sum256}
	tpl := template.Must(template.New("info").Funcs(fns).Parse(body))
	twr := tabwriter.NewWriter(buf, 0, 8, 1, ' ', 0)
	if err := tpl.Execute(twr, tconn.ConnectionState()); err != nil {
		return nil, err
	}
	if err := twr.Flush(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const body = `
TLS connection details:

TLS version:      {{.Version | printf "%#0x"}}
TLS cipher suite: {{.CipherSuite | printf "%#x"}}

Certificate chain as presented by remote:
{{range .PeerCertificates}}
=======================
{{if .Subject.CommonName -}}
Common Name:	{{.Subject.CommonName}}{{end}}
Version:	{{.Version}}
Serial Number:	{{.SerialNumber.Bytes | printf "% x"}}
Signature Algorithm:	{{.SignatureAlgorithm}}
Public Key Algorithm:	{{.PublicKeyAlgorithm}}
Fingerprint (SHA-256):	{{sha256sum .Raw | printf "% x"}}
Issuer:	{{.Issuer}}
Subject:	{{.Subject}}
Key Usage:	{{.KeyUsage | printf "%#x"}}
Not Before:	{{.NotBefore}}
Not After:	{{.NotAfter}}
{{- if .DNSNames}}
DNS Names:{{range .DNSNames}}
 - {{printf "%q" .}}
{{- end}}{{end}}
{{end}}`
