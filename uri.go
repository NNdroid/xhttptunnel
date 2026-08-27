package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
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

func PrintTerminalQR(text string) {
	fmt.Println("Scan in Stun Android / TV App (Supports stun:// and direct scan):")
	fmt.Printf("\n  %s\n\n", text)
}
