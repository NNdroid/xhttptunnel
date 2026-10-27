package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// StunProfile mirrors the subset of the Stun client's Profile that a share link
// can meaningfully carry. The field names are the ones the importer actually
// reads (app.fjj.stun.repo.Profile), so they must not be renamed casually:
// unknown keys are dropped silently by Gson, which turns a typo into a node
// that imports cleanly and then fails at connect time.
type StunProfile struct {
	// ID is omitted when empty: every import path assigns a fresh UUID, and a
	// literal "" would only add noise to the payload.
	ID                    string `json:"id,omitempty"`
	Name                  string `json:"name"`
	SSHAddr               string `json:"sshAddr"`
	User                  string `json:"user"`
	Pass                  string `json:"pass"`
	AuthType              string `json:"authType"`
	TunnelType            string `json:"tunnelType"`
	TunnelTLSEnabled      bool   `json:"tunnelTlsEnabled"`
	ProxyAddr             string `json:"proxyAddr"`
	CustomHost            string `json:"customHost"`
	ServerName            string `json:"serverName"`
	CustomPath            string `json:"customPath"`
	EnableCustomPath      bool   `json:"enableCustomPath"`
	ProxyAuthRequired     bool   `json:"proxyAuthRequired"`
	ProxyAuthToken        string `json:"proxyAuthToken"`
	ALPN                  string `json:"alpn"`
	VerifyCertFingerprint bool   `json:"verifyCertFingerprint"`
	ServerCertFingerprint string `json:"serverCertFingerprint"`
}

func GenerateXHTTPTunnelURI(host, port, path, target, psk, sni, fingerprint, remark, pin string, insecure bool) string {
	serverAddr := shareServerAddr(host, port)

	name := remark
	if name == "" {
		name = "XHTTP - " + serverAddr
	}

	// The Stun importer reads sshAddr as a bare "host:port". Server configs
	// store the value as "tcp://host:port" because the server dialer wants the
	// scheme; passing it through unchanged yields a node that imports fine but
	// never connects, so a scan of the QR looks plausible while being useless.
	sshAddr := stripTargetScheme(target)

	// 1. Official stun:// URI
	prof := StunProfile{
		Name:             name,
		SSHAddr:          sshAddr,
		User:             "root",
		AuthType:         "password",
		TunnelType:       "xhttp",
		TunnelTLSEnabled: true,
		ProxyAddr:        serverAddr,
		CustomHost:       sni,
		ServerName:       sni,
		CustomPath:       path,
		// The path is authoritative for xhttp (the importer only honours the
		// flag for masque), so enable it whenever we have one. Deriving it from
		// a "/stream" comparison coupled this file to the server's default path.
		EnableCustomPath:  path != "",
		ProxyAuthRequired: psk != "",
		ProxyAuthToken:    psk,
		// "auto" lets the node try h3 first and fall back to h2/h1.1; the app's
		// own default ("h2,http/1.1") normalises to h2, which would leave a
		// server listening only on udp:// unreachable after an import.
		ALPN: "auto",
		// The pin fields are what the importer verifies against. A field named
		// "fingerprint" is not part of the profile schema and was dropped by the
		// app's JSON parser, so a shared node silently fell back to CA
		// verification — which a self-signed server always fails.
		VerifyCertFingerprint: fingerprint != "",
		ServerCertFingerprint: fingerprint,
	}
	if prof.SSHAddr == "" {
		prof.SSHAddr = "127.0.0.1:22"
	}

	profJSON, _ := json.Marshal(prof)
	stunURI, usedPin, encErr := encryptStunURI(profJSON, pin)

	// 2. Protocol URI
	u := &url.URL{
		Scheme: "xhttp",
		Host:   serverAddr,
		Path:   path,
	}
	q := u.Query()
	if sshAddr != "" && sshAddr != "127.0.0.1:22" {
		q.Set("target", sshAddr)
	}
	if psk != "" {
		q.Set("psk", psk)
	}
	if sni != "" {
		q.Set("sni", sni)
	}
	if fingerprint != "" {
		q.Set("fp", fingerprint)
	}
	// A pin replaces CA verification outright, so advertising "insecure" beside
	// it would describe the opposite of what the node does.
	if insecure && fingerprint == "" {
		q.Set("insecure", "1")
	}
	u.RawQuery = q.Encode()

	if encErr != nil {
		stunURI = "stun://" + base64.StdEncoding.EncodeToString(profJSON)
		fmt.Fprintf(os.Stderr, "Warning: failed to encrypt share URI (%v); falling back to a PLAINTEXT stun:// payload.\n", encErr)
		fmt.Printf("\n[1] Stun share link (stun://, NOT encrypted):\n  %s\n", stunURI)
		fmt.Printf("\n[!] The payload above is plain base64 JSON: anyone who sees the QR can read the PSK. The PIN is not used.\n")
	} else {
		fmt.Printf("\n[1] Stun share link (stun://, PIN-encrypted):\n  %s\n", stunURI)
		if pin == "" {
			fmt.Printf("\n[PIN] %s  <- share this PIN with the importer (Stun App will ask for it)\n", usedPin)
		} else {
			fmt.Printf("\n[PIN] (using provided PIN)\n")
		}
	}
	fmt.Printf("\n[2] Direct Protocol URI (plaintext):\n  %s\n", u.String())
	if fingerprint != "" {
		fmt.Printf("\n[FP] certificate pinned (SHA-256) as serverCertFingerprint:\n  %s\n", fingerprint)
	} else {
		fmt.Printf("\n[FP] no certificate pin: the node verifies the server against the system CA roots instead\n")
	}
	fmt.Printf("\n[SSH] imported as %s with an empty password — the share link cannot carry credentials, so set the real user/password or private key in the app.\n\n", prof.User)

	return stunURI
}

// shareServerAddr renders "host:port" for both the shared profile and the
// plaintext URI. IPv6 literals are bracketed: a bare "2001:db8::10:9443" is not
// an address any dialer can parse, yet it used to be exactly what an IPv6
// server produced. Unspecified listen addresses are replaced by a placeholder
// the operator is expected to edit, as before.
func shareServerAddr(host, port string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	switch host {
	case "", ":", "0.0.0.0", "::":
		host = "YOUR_SERVER_IP"
	}
	return net.JoinHostPort(host, port)
}

// stripTargetScheme removes a leading "tcp://" or "udp://" from an address
// string, leaving the bare "host:port" form that external importers (Stun,
// other Stun-like apps) expect in sshAddr. Any other prefix is not a network
// scheme we emit, so the string is returned unchanged rather than truncated.
func stripTargetScheme(addr string) string {
	for _, s := range []string{"tcp://", "udp://"} {
		if len(addr) > len(s) && strings.EqualFold(addr[:len(s)], s) {
			return addr[len(s):]
		}
	}
	return addr
}

// PrintTerminalQR renders text as a scannable QR code on the terminal.
//
// The QR is drawn with unicode half-block glyphs plus explicit ANSI black/white
// colors, so the polarity is correct regardless of the terminal theme (a plain
// foreground-color rendering would come out inverted on dark-background
// terminals and many scanners reject inverted codes). Falls back to printing
// the raw text if the payload is too large to encode.
func PrintTerminalQR(text string) {
	fmt.Println("Scan in Stun Android / TV App (Supports stun:// and direct scan):")

	s, err := renderTerminalQR(text)
	if err != nil {
		fmt.Printf("\n  %s\n\n", text)
		return
	}
	fmt.Print(s)
}

// renderTerminalQR encodes text into an ANSI-colored half-block QR string.
// Each '▀' glyph covers a vertical pair of modules: its upper half takes the
// foreground color (top module) and its lower half the background color
// (bottom module). Dark modules are black, light modules are white.
func renderTerminalQR(text string) (string, error) {
	qr, err := qrcode.New(text, qrcode.Low)
	if err != nil {
		return "", err
	}
	bits := qr.Bitmap()

	const (
		fgBlack = "\x1b[30m"
		fgWhite = "\x1b[97m"
		bgBlack = "\x1b[40m"
		bgWhite = "\x1b[47m"
		reset   = "\x1b[0m"
	)
	fgColor := func(dark bool) string {
		if dark {
			return fgBlack
		}
		return fgWhite
	}
	bgColor := func(dark bool) string {
		if dark {
			return bgBlack
		}
		return bgWhite
	}

	// Pad an odd-height grid with one light row so the half-block pairing
	// below stays uniform; the extra row is quiet zone below the bottom
	// border and does not alter the code.
	if len(bits)%2 == 1 {
		bits = append(bits, make([]bool, len(bits[0])))
	}

	var b strings.Builder
	b.WriteString("\n")
	for y := 0; y < len(bits)-1; y += 2 {
		b.WriteString("  ")
		for x := range bits[y] {
			b.WriteString(fgColor(bits[y][x]))
			b.WriteString(bgColor(bits[y+1][x]))
			b.WriteString("▀")
		}
		b.WriteString(reset)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return b.String(), nil
}
