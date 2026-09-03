package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

type StunProfile struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	SSHAddr           string `json:"sshAddr"`
	User              string `json:"user"`
	Pass              string `json:"pass"`
	AuthType          string `json:"authType"`
	TunnelType        string `json:"tunnelType"`
	ProxyAddr         string `json:"proxyAddr"`
	CustomHost        string `json:"customHost"`
	ServerName        string `json:"serverName"`
	CustomPath        string `json:"customPath"`
	EnableCustomPath  bool   `json:"enableCustomPath"`
	ProxyAuthRequired bool   `json:"proxyAuthRequired"`
	ProxyAuthToken    string `json:"proxyAuthToken"`
}

func GenerateXHTTPTunnelURI(host, port, path, target, psk, sni, remark, pin string, insecure bool) string {
	serverAddr := fmt.Sprintf("%s:%s", host, port)
	if host == "" || host == "0.0.0.0" || host == ":" {
		serverAddr = "YOUR_SERVER_IP:" + port
	}

	name := remark
	if name == "" {
		name = "XHTTP - " + serverAddr
	}

	// 1. Official stun:// URI
	prof := StunProfile{
		Name:              name,
		SSHAddr:           target,
		User:              "root",
		AuthType:          "password",
		TunnelType:        "xhttp",
		ProxyAddr:         serverAddr,
		CustomHost:        sni,
		ServerName:        sni,
		CustomPath:        path,
		EnableCustomPath:  path != "" && path != "/stream",
		ProxyAuthRequired: psk != "",
		ProxyAuthToken:    psk,
	}
	if prof.SSHAddr == "" {
		prof.SSHAddr = "127.0.0.1:22"
	}
	profJSON, _ := json.Marshal(prof)
	stunURI, usedPin, err := encryptStunURI(profJSON, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to encrypt share URI (%v); falling back to plaintext stun://.\n", err)
		stunURI = "stun://" + base64.StdEncoding.EncodeToString(profJSON)
	}

	// 2. Protocol URI
	u := &url.URL{
		Scheme: "xhttp",
		Host:   serverAddr,
		Path:   path,
	}
	q := u.Query()
	if target != "" && target != "tcp://127.0.0.1:22" {
		q.Set("target", target)
	}
	if psk != "" {
		q.Set("psk", psk)
	}
	if sni != "" {
		q.Set("sni", sni)
	}
	if insecure {
		q.Set("insecure", "1")
	}
	u.RawQuery = q.Encode()

	fmt.Printf("\n[1] Official Stun Sharing Link (stun://, encrypted):\n  %s\n", stunURI)
	if pin == "" {
		fmt.Printf("\n[PIN] %s  <- share this PIN with the importer (Stun App will ask for it)\n", usedPin)
	} else {
		fmt.Printf("\n[PIN] (using provided PIN)\n")
	}
	fmt.Printf("\n[2] Direct Protocol URI (plaintext):\n  %s\n\n", u.String())

	return stunURI
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
