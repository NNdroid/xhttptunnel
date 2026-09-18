package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/NNdroid/xhttptunnel/tunnel"
)

// ---------------------------------------------------------------------------
// Shared generated-config machinery
//
// gen-config, gen-systemd and gen-nginx all end at the same resolved, checked
// *FileConfig. Keeping resolution, validation and rendering here means the CLI
// flags, the emitted JSON and the repo's sample configs cannot drift apart:
// they share one code path instead of three hand-maintained templates.
// ---------------------------------------------------------------------------

// placeholderPSK is one of the tokens isPlaceholderPSK refuses to boot with.
// gen-config emits it only on purpose (see -psk-mode placeholder) so an
// unedited file fails loudly instead of coming up with a guessable secret.
const placeholderPSK = "replace-with-a-random-secret"

const (
	pskModeAuto        = "auto"        // server: random, client: placeholder
	pskModeRandom      = "random"      // always generate
	pskModePlaceholder = "placeholder" // always emit the inert example token
	pskModeOpen        = "open"        // empty PSK, no authentication
)

// genSpec is the operator-supplied half of a config. build() turns it into a
// complete, validated *FileConfig.
type genSpec struct {
	Mode   string
	Listen string
	Path   string
	Server string
	Target string

	PSK     string
	PSKFile string
	PSKMode string

	SelfSign   bool
	SelfSignCN string
	Cert       string
	Key        string
	Fallback   string

	SNI         string
	Host        string
	ALPN        string
	StreamMode  string
	Fingerprint string

	LogLevel string
	Dump     bool

	MaxSessions      int
	MaxSessionsPerIP int
	HealthPath       string
	MinProtoVersion  int
	ChunkSizeKB      int
	MaxConns         int
	IdleTimeout      int
	// "loopback", "all", or a comma-separated list of host:port / :port /
	// host: / [host] / *, each optionally prefixed tcp:// or udp://.
	AllowedTargets string
	TrustProxy     bool

	// TCP Brutal (Linux kernel only). Flat here because flag.FlagSet has no
	// nested namespace; see brutal().
	BrutalEnable      bool
	BrutalRate        uint64
	BrutalCwndGain    int
	BrutalGroupID     uint64
	BrutalGroupRemote bool
	BrutalBWExchange  bool
	BrutalBWAdvertise uint64
	BrutalBWInterval  int

	// Changed holds the flags the operator actually set, so an explicit
	// "-psk """ (open mode) is distinguishable from the flag being omitted.
	Changed map[string]bool
	// PSKGenerated records a freshly generated secret so the caller can show it
	// once, out of band of the JSON stream.
	PSKGenerated string
	// PSKExplicit is true when the operator supplied the secret directly, which
	// turns an example token into a hard error rather than a template warning.
	PSKExplicit bool
}

func changedFlags(cmd *flag.FlagSet) map[string]bool {
	out := map[string]bool{}
	cmd.Visit(func(f *flag.Flag) { out[f.Name] = true })
	return out
}

// randomPSK returns a hex-encoded secret of the requested bit length (256 when
// the request is unusable). 256 bits matches the 32-byte / 64-hex-char secret
// scripts/install.sh has always generated.
func randomPSK(bits int) (string, error) {
	if bits <= 0 || bits%8 != 0 {
		bits = 256
	}
	buf := make([]byte, bits/8)
	if _, err := crand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random PSK: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// resolvePSK applies -psk / -psk-file / -psk-mode in that precedence.
func (s *genSpec) resolvePSK(mode string) (string, error) {
	if s.PSKFile != "" {
		b, err := os.ReadFile(s.PSKFile)
		if err != nil {
			return "", fmt.Errorf("read -psk-file %s: %w", s.PSKFile, err)
		}
		s.PSKExplicit = true
		return strings.TrimSpace(string(b)), nil
	}
	if s.Changed["psk"] {
		s.PSKExplicit = true
		return s.PSK, nil
	}
	switch s.PSKMode {
	case pskModePlaceholder:
		return placeholderPSK, nil
	case pskModeOpen:
		return "", nil
	case pskModeRandom:
		p, err := randomPSK(256)
		if err != nil {
			return "", err
		}
		s.PSKGenerated = p
		return p, nil
	case pskModeAuto, "":
		if mode == "server" {
			p, err := randomPSK(256)
			if err != nil {
				return "", err
			}
			s.PSKGenerated = p
			return p, nil
		}
		// A client must reuse the server's secret; inventing one would yield a
		// file that fails every handshake. Keep the placeholder so the binary
		// refuses to start instead of failing on the first connection.
		return placeholderPSK, nil
	default:
		return "", fmt.Errorf("-psk-mode %q is not %q, %q, %q or %q", s.PSKMode, pskModeAuto, pskModeRandom, pskModePlaceholder, pskModeOpen)
	}
}

// brutal folds the flat -brutal-* flags into the nested config block. No
// per-mode rule is applied here: checkConfig runs BrutalConfig.Validate, which
// is the single place that knows which combinations are legal on each side.
// CwndGain is taken from a signed flag because the flag package has no
// 32-bit-unsigned binder; a negative value is caught in build so it cannot
// wrap into a 4-billion-tenths cwnd_gain.
func (s *genSpec) brutal() tunnel.BrutalConfig {
	return tunnel.BrutalConfig{
		Enabled:         s.BrutalEnable,
		Rate:            s.BrutalRate,
		CwndGain:        uint32(s.BrutalCwndGain),
		GroupID:         s.BrutalGroupID,
		GroupFromRemote: s.BrutalGroupRemote,
		BWExchange:      s.BrutalBWExchange,
		BWAdvertise:     s.BrutalBWAdvertise,
		BWInterval:      s.BrutalBWInterval,
	}
}

// build fills per-mode defaults and returns a config ready to be written. It
// deliberately does not call applyServerDefaults: that helper writes
// cert.pem/key.pem into the working directory, which a generator must not do.
func (s *genSpec) build() (*FileConfig, error) {
	mode := strings.ToLower(strings.TrimSpace(s.Mode))
	switch mode {
	case "server", "client":
	default:
		return nil, fmt.Errorf("-mode must be \"server\" or \"client\", got %q", s.Mode)
	}
	if s.BrutalCwndGain < 0 {
		return nil, fmt.Errorf("-brutal-cwnd-gain %d must be 0 (the default) or 1-100 tenths", s.BrutalCwndGain)
	}

	cfg := &FileConfig{
		Mode:              mode,
		Listen:            s.Listen,
		Path:              s.Path,
		ServerURL:         s.Server,
		Target:            s.Target,
		SelfSign:          s.SelfSign,
		SelfSignCN:        s.SelfSignCN,
		Cert:              s.Cert,
		Key:               s.Key,
		Fallback:          s.Fallback,
		SNI:               s.SNI,
		Host:              s.Host,
		ALPN:              s.ALPN,
		StreamMode:        s.StreamMode,
		Fingerprint:       s.Fingerprint,
		LogLevel:          s.LogLevel,
		Dump:              s.Dump,
		MaxSessions:       s.MaxSessions,
		MaxSessionsPerIP:  s.MaxSessionsPerIP,
		HealthPath:        s.HealthPath,
		MinProtoVersion:   s.MinProtoVersion,
		ChunkSizeKB:       s.ChunkSizeKB,
		MaxConns:          s.MaxConns,
		IdleTimeout:       s.IdleTimeout,
		TrustProxyHeaders: s.TrustProxy,
		Brutal:            s.brutal(),
	}

	psk, err := s.resolvePSK(mode)
	if err != nil {
		return nil, err
	}
	cfg.PSK = psk

	switch mode {
	case "server":
		if cfg.Listen == "" {
			cfg.Listen = ":8443"
		}
		if cfg.Path == "" {
			cfg.Path = "/stream"
		}
		if cfg.Target == "" {
			cfg.Target = "tcp://127.0.0.1:22"
		}
		// selfsign without a Common Name is fine at boot (applyServerDefaults
		// picks www.bing.com), but the generated file should show the disguise
		// the operator will actually get.
		if cfg.SelfSign && cfg.SelfSignCN == "" {
			cfg.SelfSignCN = "www.bing.com"
		}
		if cfg.Fallback == "" {
			cfg.Fallback = "https://www.bing.com"
		}
		if cfg.MaxSessions == 0 {
			cfg.MaxSessions = 2000
		}
		if cfg.MaxSessionsPerIP == 0 {
			cfg.MaxSessionsPerIP = 50
		}
		cfg.AllowedTargets = s.allowedTargets()
	case "client":
		if cfg.Listen == "" {
			cfg.Listen = "tcp://127.0.0.1:1080"
		}
		if cfg.ServerURL == "" {
			cfg.ServerURL = "https://127.0.0.1:8443/stream"
		}
		if cfg.Target == "" {
			cfg.Target = "127.0.0.1:22"
		}
		if cfg.ALPN == "" {
			cfg.ALPN = "auto"
		}
		if cfg.StreamMode == "" {
			cfg.StreamMode = "auto"
		}
		if cfg.MaxConns == 0 {
			cfg.MaxConns = 512
		}
		if cfg.IdleTimeout == 0 {
			cfg.IdleTimeout = 900
		}
		// A client config has no selfsign_cn field, but the disguise has to
		// reach it as sni/host or a self-signed origin will not verify. Passing
		// -selfsign-cn in client mode fans it out there.
		if cfg.SelfSignCN != "" {
			if cfg.SNI == "" {
				cfg.SNI = cfg.SelfSignCN
			}
			if cfg.Host == "" {
				cfg.Host = cfg.SelfSignCN
			}
		}
	}

	if cfg.ChunkSizeKB == 0 {
		cfg.ChunkSizeKB = 256
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	return cfg, nil
}

// allowedTargets interprets the -allowed-targets shorthand. Left unset the
// operator gets the safe loopback-only policy; opening it up takes the explicit
// word "all", because an empty list means "allow every target".
func (s *genSpec) allowedTargets() []string {
	raw := strings.TrimSpace(s.AllowedTargets)
	if raw == "" {
		// Changed with an empty value is ambiguous between "unset" and "open";
		// -allowed-targets all is the unambiguous spelling.
		return []string{"127.0.0.1:", "localhost:"}
	}
	if strings.EqualFold(raw, "loopback") {
		return []string{"127.0.0.1:", "localhost:"}
	}
	if strings.EqualFold(raw, "all") {
		return []string{}
	}
	out := []string{}
	for _, entry := range strings.Split(raw, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Validation
//
// Mirrors the checks the engine performs at boot, so a generated file is
// rejected at generation time rather than at service start.
// ---------------------------------------------------------------------------

type configCheck struct {
	problems []string
	warnings []string
}

func (c *configCheck) fail(format string, a ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, a...))
}

func (c *configCheck) warn(format string, a ...any) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, a...))
}

// warned reports whether any advisory was raised.
func (c *configCheck) warned() bool { return len(c.warnings) > 0 }

func (c *configCheck) err() error {
	if len(c.problems) == 0 {
		return nil
	}
	return errors.New("generated config is invalid:\n  - " + strings.Join(c.problems, "\n  - "))
}

// checkConfig validates cfg. explicitPSK distinguishes "the operator typed an
// example token" (rejected) from "the generator substituted one as a template"
// (accepted with a warning, so `gen-config -mode client` still emits a file).
func checkConfig(cfg *FileConfig, explicitPSK bool) *configCheck {
	c := &configCheck{}
	portInRange := func(n int) bool { return n >= 1 && n <= 65535 }

	if _, host, port, ok := splitAddr(cfg.Listen); !ok || !portInRange(port) {
		c.fail("listen %q must be [tcp|udp|tcp+udp]://host:port with a port in 1-65535", cfg.Listen)
	} else if host != "" && hostIllegal(host) {
		// An empty host means "all interfaces" (":8443"), which is the
		// intentional server default.
		c.fail("listen host %q is not a valid hostname or address", host)
	}

	if cfg.Path != "" && !strings.HasPrefix(cfg.Path, "/") {
		c.fail("path %q must start with \"/\"", cfg.Path)
	}

	if cfg.Mode == "client" {
		if strings.Contains(cfg.Target, "://") {
			c.fail("target %q must be bare \"host:port\". The client sends it verbatim as X-Target and the server strips any scheme before the allowlist check and the dial, so a tcp:// prefix would be silently ignored rather than honoured: it would read like a protocol selector while doing nothing. The client's protocol comes from listen instead: udp://0.0.0.0:1080 opens a UDP forwarder; tcp:// belongs in the server's own target", cfg.Target)
		} else if _, _, port, ok := splitAddr(cfg.Target); !ok || !portInRange(port) {
			c.fail("target %q must be \"host:port\" with a port in 1-65535", cfg.Target)
		}
		u, err := url.Parse(cfg.ServerURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			c.fail("server %q must be an http:// or https:// URL with a host", cfg.ServerURL)
		} else if u.Path == "" || u.Path == "/" {
			c.warn("server %q has no path; the tunnel path defaults to /stream, so an explicit one (e.g. https://example.com/stream) is what the server expects", cfg.ServerURL)
		}
	} else if _, _, port, ok := splitAddr(cfg.Target); !ok || !portInRange(port) {
		c.fail("target %q must be [tcp|udp]://host:port with a port in 1-65535", cfg.Target)
	}

	if cfg.HealthPath != "" && !strings.HasPrefix(cfg.HealthPath, "/") {
		c.fail("health_path %q must start with \"/\"", cfg.HealthPath)
	}

	if isPlaceholderPSK(cfg.PSK) {
		if explicitPSK {
			c.fail("psk is the published example token %q, which the binary refuses to run with; pass a real secret, -psk \"\" for open mode, or let the generator create one", cfg.PSK)
		} else {
			c.warn("psk is the placeholder %q, so this file will refuse to start until a real secret is supplied", cfg.PSK)
		}
	}
	if cfg.PSK == "" {
		c.warn("psk is empty: the tunnel will accept unauthenticated sessions")
	}

	if cfg.ALPN != "" {
		switch strings.ToLower(cfg.ALPN) {
		case "auto", "h3", "h2", "h1":
		default:
			c.fail("alpn %q must be \"auto\", \"h3\", \"h2\" or \"h1\"", cfg.ALPN)
		}
	}
	if cfg.StreamMode != "" {
		switch strings.ToLower(cfg.StreamMode) {
		case "auto", "poll", "stream":
		default:
			c.fail("stream_mode %q must be \"auto\", \"poll\" or \"stream\"", cfg.StreamMode)
		}
	}
	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		c.fail("log_level %q must be \"debug\", \"info\", \"warn\" or \"error\"", cfg.LogLevel)
	}
	if cfg.ChunkSizeKB != 0 && (cfg.ChunkSizeKB < 16 || cfg.ChunkSizeKB > 900) {
		c.fail("chunk_size_kb %d must be 0 or 16-900; the engine clamps to that range, so raising the ceiling means raising it on BOTH ends", cfg.ChunkSizeKB)
	}
	// Shared with the runtime, so the generator can never emit a file the
	// binary refuses. Validate also normalises cwnd_gain and bw_interval, so
	// the rendered file shows the values that will actually be in force.
	if err := cfg.Brutal.Validate(cfg.Mode); err != nil {
		c.fail("%s", err)
	}
	if cfg.Brutal.Enabled && cfg.Mode == "client" && strings.ToLower(cfg.ALPN) == "h3" {
		c.warn("brutal is enabled but alpn is h3: HTTP/3 tunnels run over QUIC/UDP and TCP Brutal only caps TCP sockets, so the setting will have no effect")
	}
	for name, v := range map[string]int{
		"max_sessions":        cfg.MaxSessions,
		"max_sessions_per_ip": cfg.MaxSessionsPerIP,
		"max_conns":           cfg.MaxConns,
		"idle_timeout":        cfg.IdleTimeout,
		"min_proto_version":   cfg.MinProtoVersion,
	} {
		if v < 0 {
			c.fail("%s must be >= 0", name)
		}
	}
	if cfg.SelfSignCN != "" && hostIllegal(cfg.SelfSignCN) {
		c.fail("selfsign_cn %q is not a valid hostname", cfg.SelfSignCN)
	}

	for _, entry := range cfg.AllowedTargets {
		if err := checkAllowedTargetEntry(entry); err != nil {
			c.fail("%s", err)
		}
	}

	if cfg.Mode == "server" && !cfg.SelfSign && cfg.Cert == "" && cfg.Key == "" {
		c.warn("selfsign is false and no cert/key is set, so the server speaks plain HTTP with no TLS disguise; that is only right behind a CDN that terminates TLS")
	}
	if cfg.Mode == "client" && cfg.Fingerprint == "" {
		// A client cannot tell a self-signed origin from a CDN one, so this is a
		// warning rather than an error: the system roots are the right trust
		// store for a real CDN, and the pin is the only thing that makes a
		// self-signed origin usable.
		msg := "fingerprint is empty, so the origin is verified with the system CA roots"
		if cfg.SNI == "" && cfg.Host == "" {
			msg += "; sni and host are empty too, so TLS SNI and HTTP Host inherit the server URL host, which fails hostname verification against a self-signed origin that impersonates a CDN domain"
		}
		msg += " - pin it with -fingerprint (`openssl x509 -in cert.pem -outform der | sha256sum`) and, for a self-signed origin, set -sni and -host to the disguised domain"
		c.warn("%s", msg)
	}
	return c
}

// splitAddr accepts "host:port", "[::1]:port" and an optional tcp://, udp://
// or tcp+udp:// scheme. It reports the scheme, host, numeric port and whether
// the input parsed at all.
func splitAddr(s string) (scheme, host string, port int, ok bool) {
	rest := s
	for _, p := range []string{"tcp+udp://", "tcp://", "udp://"} {
		if strings.HasPrefix(rest, p) {
			scheme = strings.TrimSuffix(p, "://")
			rest = rest[len(p):]
			break
		}
	}
	h, p, err := net.SplitHostPort(rest)
	if err != nil {
		return "", "", 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", "", 0, false
	}
	return scheme, h, n, true
}

// hostIllegal reports names and addresses nginx or a resolver would reject. The
// check stays permissive: an underscore-prefixed internal name is unusual but
// not invalid.
func hostIllegal(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" || len(host) > 253 {
		return true
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return strings.ContainsAny(host, " \t\r\n/\\:#@?")
}

// checkAllowedTargetEntry validates one allowed_targets entry. It is stricter
// than the runtime matcher, which drops an unparseable entry instead of
// failing: a typo should surface at generation time rather than becoming a
// rule that looks active but never fires. The accepted forms mirror
// targetPatternOf in tunnel/tunnel.go:
//
//	"host:port"        exact
//	":port"            any host on that port
//	"host:"            any port on that host
//	"[host]"           an IPv6 literal on any port
//	"*", "*:", ":*"    anything
//	any of the above prefixed with "tcp://" or "udp://", restricting the
//	protocol the client asked for
//
// A colon is mandatory apart from "*": "host:" already means that host on any
// port, so a bare name only adds ambiguity with a forgotten port number. An
// unbracketed IPv6 literal is rejected for the same reason — its colons are
// ambiguous, so write "[::1]:22" or "[::1]".
func checkAllowedTargetEntry(entry string) error {
	e := strings.TrimSpace(entry)
	if e == "" {
		return errors.New("allowed_targets has an empty entry")
	}

	restricted := ""
	if scheme, authority, found := strings.Cut(e, "://"); found && scheme != "" {
		switch strings.ToLower(scheme) {
		case "tcp", "udp":
			restricted = " (" + strings.ToLower(scheme) + "-only)"
		default:
			return fmt.Errorf("allowed_targets entry %q has scheme %q; only tcp and udp can be dialed, and any other scheme is a rule that never matches", entry, scheme)
		}
		e = authority
	}
	if e == "*" {
		return nil
	}
	// A colon is mandatory. "host:" already means that host on any port, so a
	// bare name only adds ambiguity with a forgotten port number, and the
	// runtime would treat it as a rule that never fires.
	if !strings.Contains(e, ":") {
		return fmt.Errorf("allowed_targets entry %q must be \"host:port\", \":port\", \"host:\", \"[host]\" or \"*\"%s", entry, restricted)
	}
	host, port, ok := splitHostPort(e)
	if !ok {
		return fmt.Errorf("allowed_targets entry %q must be \"host:port\", \":port\", \"host:\", \"[host]\" or \"*\"%s", entry, restricted)
	}
	if host != "" && host != "*" && hostIllegal(host) {
		return fmt.Errorf("allowed_targets entry %q has an invalid host%s", entry, restricted)
	}
	if port != "" && port != "*" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("allowed_targets entry %q must use a port in 1-65535%s", entry, restricted)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Ordered JSON rendering
//
// encoding/json sorts map keys alphabetically, which would flatten the field
// grouping into a plain alphabetical list. These renderers keep slice order,
// which is what lets the emitted file stay readable and stay shaped like the
// repo's sample configs.
// ---------------------------------------------------------------------------

type stringDoc struct{ key, value string }

type jsonLine struct {
	key  string
	val  any
	docs []stringDoc
}

func renderConfigJSON(lines []jsonLine) ([]byte, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, ln := range lines {
		b.WriteString("\n  \"")
		b.WriteString(ln.key)
		b.WriteString("\": ")
		if len(ln.docs) > 0 {
			b.WriteString("{\n")
			for j, d := range ln.docs {
				v, err := json.Marshal(d.value)
				if err != nil {
					return nil, err
				}
				b.WriteString("    \"")
				b.WriteString(d.key)
				b.WriteString("\": ")
				b.Write(v)
				if j+1 < len(ln.docs) {
					b.WriteByte(',')
				}
				b.WriteByte('\n')
			}
			b.WriteString("  }")
		} else {
			b.Write(indentValue(ln.val))
		}
		if i+1 < len(lines) {
			b.WriteByte(',')
		}
	}
	b.WriteString("\n}\n")
	return []byte(b.String()), nil
}

// indentValue marshals a value and re-indents its continuation lines so arrays
// and objects nest two spaces inside the enclosing object.
func indentValue(v any) []byte {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("null")
	}
	if !strings.Contains(string(raw), "\n") {
		return raw
	}
	parts := strings.Split(string(raw), "\n")
	for i := 1; i < len(parts); i++ {
		parts[i] = "  " + parts[i]
	}
	return []byte(strings.Join(parts, "\n"))
}

// renderServerConfig renders a server config. The _fields text mirrors
// config.server.json; gen_config_test.go keeps the key sets in step.
func renderServerConfig(cfg *FileConfig, withDocs bool) ([]byte, error) {
	var lines []jsonLine
	if withDocs {
		lines = append(lines, jsonLine{key: "_description", val: "xhttptunnel Split-HTTP / Meek Streaming Server Configuration."})
		lines = append(lines, jsonLine{key: "_fields", docs: serverFieldDocs()})
	}
	lines = append(lines,
		jsonLine{key: "mode", val: cfg.Mode},
		jsonLine{key: "listen", val: cfg.Listen},
		jsonLine{key: "path", val: cfg.Path},
		jsonLine{key: "target", val: cfg.Target},
		jsonLine{key: "psk", val: cfg.PSK},
		jsonLine{key: "selfsign", val: cfg.SelfSign},
		jsonLine{key: "selfsign_cn", val: cfg.SelfSignCN},
		jsonLine{key: "cert", val: cfg.Cert},
		jsonLine{key: "key", val: cfg.Key},
		jsonLine{key: "fallback", val: cfg.Fallback},
		jsonLine{key: "allowed_targets", val: cfg.AllowedTargets},
		jsonLine{key: "max_sessions", val: cfg.MaxSessions},
		jsonLine{key: "max_sessions_per_ip", val: cfg.MaxSessionsPerIP},
		jsonLine{key: "health_path", val: cfg.HealthPath},
		jsonLine{key: "min_proto_version", val: cfg.MinProtoVersion},
		jsonLine{key: "chunk_size_kb", val: cfg.ChunkSizeKB},
		jsonLine{key: "trust_proxy_headers", val: cfg.TrustProxyHeaders},
		jsonLine{key: "brutal", val: cfg.Brutal},
		jsonLine{key: "dump", val: cfg.Dump},
		jsonLine{key: "log_level", val: cfg.LogLevel},
	)
	return renderConfigJSON(lines)
}

// renderClientConfig renders a client config. The _fields text mirrors
// config.client.json; gen_config_test.go keeps the key sets in step.
func renderClientConfig(cfg *FileConfig, withDocs bool) ([]byte, error) {
	var lines []jsonLine
	if withDocs {
		lines = append(lines, jsonLine{key: "_description", val: "xhttptunnel Split-HTTP / Meek Streaming Client Configuration."})
		lines = append(lines, jsonLine{key: "_fields", docs: clientFieldDocs()})
	}
	lines = append(lines,
		jsonLine{key: "mode", val: cfg.Mode},
		jsonLine{key: "listen", val: cfg.Listen},
		jsonLine{key: "server", val: cfg.ServerURL},
		jsonLine{key: "target", val: cfg.Target},
		jsonLine{key: "psk", val: cfg.PSK},
		jsonLine{key: "sni", val: cfg.SNI},
		jsonLine{key: "host", val: cfg.Host},
		jsonLine{key: "alpn", val: cfg.ALPN},
		jsonLine{key: "stream_mode", val: cfg.StreamMode},
		jsonLine{key: "fingerprint", val: cfg.Fingerprint},
		jsonLine{key: "cert", val: cfg.Cert},
		jsonLine{key: "key", val: cfg.Key},
		jsonLine{key: "chunk_size_kb", val: cfg.ChunkSizeKB},
		jsonLine{key: "idle_timeout", val: cfg.IdleTimeout},
		jsonLine{key: "max_conns", val: cfg.MaxConns},
		jsonLine{key: "brutal", val: cfg.Brutal},
		jsonLine{key: "dump", val: cfg.Dump},
		jsonLine{key: "log_level", val: cfg.LogLevel},
	)
	return renderConfigJSON(lines)
}

func renderConfig(cfg *FileConfig, withDocs bool) ([]byte, error) {
	if cfg.Mode == "client" {
		return renderClientConfig(cfg, withDocs)
	}
	return renderServerConfig(cfg, withDocs)
}

func serverFieldDocs() []stringDoc {
	return []stringDoc{
		{"mode", "Operational mode: 'server'"},
		{"listen", "Server address. Plain address or tcp+udp:// enables H3 only with TLS; tcp:// disables H3 for a CDN HTTP origin."},
		{"path", "Custom Split-HTTP endpoint path (e.g. /stream)"},
		{"target", "Default backend service to forward tunnel traffic to (e.g. tcp://127.0.0.1:22 or udp://127.0.0.1:51820). Alias: default_target"},
		{"psk", "Pre-shared key for authentication. Never sent over the wire: each request carries a fresh nonce plus its HMAC-SHA256 over the nonce, session id and target, so a captured request leaks nothing and cannot be replayed or retargeted. Legacy clients that still send the bare token are accepted during the migration window (upgrade servers first, then clients). Aliases: token, auth_token. Empty = open mode."},
		{"selfsign", "Automatically generate simulated Amazon/Bing CDN self-signed TLS certificate if cert/key omitted (set false for plain HTTP behind CDN)"},
		{"selfsign_cn", "Common Name for auto self-signed certificate (e.g. www.bing.com)"},
		{"cert", "Optional path to custom TLS certificate file"},
		{"key", "Optional path to custom TLS private key file"},
		{"fallback", "Decoy URL to transparently proxy unauthorized requests to (e.g. https://www.bing.com). Empty returns an nginx-style 404."},
		{"allowed_targets", "Restrict which targets clients may request. Each entry may be prefixed with 'tcp://' or 'udp://' to restrict the protocol, and is otherwise one of: 'host:port' (exact), ':port' (any host on that port), 'host:' (any port on that host), '[host]' (an IPv6 literal on any port) or '*' (anything). An unbracketed IPv6 literal is rejected because its colons are ambiguous, so write '[::1]:22' or '[::1]' instead. So 'tcp://192.168.1.10:' admits only TCP to that host, 'udp://:53' only UDP DNS, and a bare '127.0.0.1:' admits either protocol. Checked at session creation, so a custom Handler only ever sees allowlisted targets. Empty = allow all, including non-loopback hosts."},
		{"max_sessions", "Maximum concurrent tunnel sessions allowed on server (0 = default 2000)"},
		{"max_sessions_per_ip", "Cap concurrent sessions from a single client address (0 = unlimited). Bounds one PSK holder's blast radius; counts the TCP peer address unless trust_proxy_headers is on."},
		{"health_path", "When set (e.g. /healthz), expose an unauthenticated JSON stats endpoint on the tunnel listener. Empty = disabled. Keep off on a public listener."},
		{"min_proto_version", "Reject (HTTP 426) clients advertising an X-XHTTP-Proto below this. 0 (default) accepts all clients, including legacy header-less ones. Set 2 to force the signed-nonce scheme: a client advertising v2 is admitted only by signature, which closes the bare-token fallback."},
		{"chunk_size_kb", "Caps the upstream payload carried by one poll request (clamped 16-900, default 256). Must be raised on BOTH ends together."},
		{"trust_proxy_headers", "Honour CF-Connecting-IP / X-Forwarded-For / X-Real-IP for client-address logging. Those headers are spoofable; enable only behind a trusted proxy that strips them."},
		{"brutal", "TCP Brutal (Linux kernel module only; inert on other platforms). Caps the send rate of this server's TCP tunnel sockets in bytes/s. The HTTP/3 socket is never affected. Nested object: enabled (default false; off means setsockopt is never called), rate (bytes/s; 0 is illegal unless bw_exchange supplies one), cwnd_gain (tenths, so 20 = 2.0x; 0 = default 20, max 100), group_id (0 = per-connection only), group_from_remote (derive the group from the peer's address instead of group_id; a static group_id on a server pools every client into one aggregate ceiling), bw_exchange (accept the _BrutalBwExchange protocol), bw_advertise (bytes/s this server can ingest; the peer applies it as its own send rate), bw_interval (seconds between exchange attempts, default 60). Exchange requests are authenticated but do not count against max_sessions. A socket failure never breaks a tunnel: the connection continues uncapped and the failure is logged once."},
		{"dump", "Dump raw packet hex data in logs for low-level debugging"},
		{"log_level", "Logging verbosity: debug, info, warn, error"},
	}
}

func clientFieldDocs() []stringDoc {
	return []stringDoc{
		{"mode", "Operational mode: 'client'"},
		{"listen", "Local TCP listening address for applications to connect to (e.g. tcp://127.0.0.1:1080)"},
		{"server", "Remote xhttptunnel server streaming URL (e.g. https://example.com:8443/stream)"},
		{"target", "Target backend service to connect through the tunnel (e.g. 127.0.0.1:22). Alias: forward"},
		{"psk", "Pre-shared key matching the server. It is never sent: each request carries a fresh nonce plus its HMAC-SHA256 over the nonce, session id and target, so a captured request leaks nothing and cannot be replayed or retargeted. Aliases: token, auth_token. Empty = connect unauthenticated."},
		{"sni", "Optional TLS SNI disguise/domain (default: inherited from the server URL domain. Required if the server URL uses a CDN IP)"},
		{"host", "Optional HTTP Host disguise/domain (default: inherited from the server URL domain. Required if the server URL uses a CDN IP)"},
		{"alpn", "HTTP protocol selection: 'auto' (probe HTTP/3, fall back), 'h3', 'h2', or 'h1'"},
		{"stream_mode", "Downlink transport: 'auto' (negotiate), 'poll' (legacy long-poll), or 'stream' (force streaming). Invalid values fail startup."},
		{"fingerprint", "SHA256 certificate pin of the server certificate (required for self-signed TLS; empty uses the system CA roots plus SNI hostname verification, which is appropriate for ordinary CDN HTTPS)"},
		{"cert", "Optional path to the server's TLS certificate. Client mode does not read it; it is used only by the gen-uri command to derive the fingerprint pin above."},
		{"key", "Optional path to the server's TLS private key. Not used by the client at all."},
		{"chunk_size_kb", "Caps the upstream payload carried by one poll request (clamped 16-900, default 256). Must match the server value; raise on BOTH ends together."},
		{"idle_timeout", "Drop a local connection after this many seconds without traffic (default 900). Idle SSH sessions need a keepalive below it."},
		{"max_conns", "Maximum concurrent client connections allowed (0 = default 2000)"},
		{"brutal", "TCP Brutal (Linux kernel module only; inert on other platforms). Caps the send rate of this client's TCP tunnel sockets in bytes/s. HTTP/3 tunnels run over QUIC/UDP and are never capped. Nested object: enabled (default false; off means setsockopt is never called), rate (bytes/s ceiling; 0 is illegal unless bw_exchange supplies one), cwnd_gain (tenths, so 20 = 2.0x; 0 = default 20, max 100), group_id (0 = per-connection only), bw_exchange (enable the _BrutalBwExchange protocol), bw_advertise (bytes/s this client can ingest; the server applies it as its own send rate), bw_interval (seconds between exchange attempts, default 60). The rate is a ceiling: the exchange can only lower it. A socket failure never breaks a tunnel: the connection continues uncapped and the failure is logged once."},
		{"dump", "Dump raw packet hex data in logs for low-level debugging"},
		{"log_level", "Logging verbosity: debug, info, warn, error"},
	}
}

// writeFileAtomic writes data to path with perm, replacing any existing file.
// Writing a sibling temp file and renaming means an interrupted run leaves
// either the old config or the new one, never a half-written secret.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".gen-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// os.Rename will not replace an existing file on Windows, so drop the old
	// one first. That leaves a very short window with no file, which matters
	// less here than a rename that fails.
	_ = os.Remove(path)
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = ""
	return nil
}

// bindGenConfigFlags attaches the config flags both gen-config and gen-systemd
// expose, so the two cannot accept different spellings of the same knob.
func bindGenConfigFlags(cmd *flag.FlagSet, s *genSpec) {
	cmd.StringVar(&s.Mode, "mode", "server", "Config mode: server or client")
	cmd.StringVar(&s.Listen, "listen", "", "Listen address (server: :8443, client: tcp://127.0.0.1:1080 when omitted)")
	cmd.StringVar(&s.Path, "path", "", "Tunnel path, e.g. /stream (server)")
	cmd.StringVar(&s.Server, "server", "", "Tunnel server URL, e.g. https://example.com:8443/stream (client)")
	cmd.StringVar(&s.Target, "target", "", "Default target: tcp://127.0.0.1:22 on a server, bare 127.0.0.1:22 on a client")
	cmd.StringVar(&s.PSK, "psk", "", "Pre-shared key; an empty value means open mode. Wins over -psk-mode")
	cmd.StringVar(&s.PSKFile, "psk-file", "", "Read the pre-shared key from this file instead of the command line")
	cmd.StringVar(&s.PSKMode, "psk-mode", pskModeAuto, "PSK source when -psk/-psk-file is unset: auto (server random, client placeholder), random, placeholder, open")
	cmd.BoolVar(&s.SelfSign, "selfsign", true, "Generate a self-signed CDN-style TLS certificate (server)")
	cmd.StringVar(&s.SelfSignCN, "selfsign-cn", "", "Common name for the self-signed cert; on a client it becomes sni and host")
	cmd.StringVar(&s.Cert, "cert", "", "Custom TLS certificate path (server); on a client it only feeds gen-uri's fingerprint pin")
	cmd.StringVar(&s.Key, "key", "", "Custom TLS private key path (server); never read by a client")
	cmd.StringVar(&s.Fallback, "fallback", "", "Decoy URL for unauthorized requests (server)")
	cmd.StringVar(&s.SNI, "sni", "", "TLS SNI disguise (client)")
	cmd.StringVar(&s.Host, "host", "", "HTTP Host disguise (client)")
	cmd.StringVar(&s.ALPN, "alpn", "", "Protocol selection: auto, h3, h2 or h1 (client)")
	cmd.StringVar(&s.StreamMode, "stream-mode", "", "Downlink transport: auto, poll or stream (client)")
	cmd.StringVar(&s.Fingerprint, "fingerprint", "", "SHA256 certificate pin (client)")
	cmd.StringVar(&s.LogLevel, "log-level", "", "Log level: debug, info, warn, error")
	cmd.BoolVar(&s.Dump, "dump", false, "Hex-dump tunnelled traffic (debugging only)")
	cmd.IntVar(&s.MaxSessions, "max-sessions", 0, "Server max concurrent sessions (0 = 2000)")
	cmd.IntVar(&s.MaxSessionsPerIP, "max-sessions-per-ip", 0, "Server max sessions per client address (0 = 50)")
	cmd.StringVar(&s.HealthPath, "health-path", "", "Unauthenticated stats path on the tunnel listener; empty disables it")
	cmd.IntVar(&s.MinProtoVersion, "min-proto-version", 0, "Reject clients advertising an older X-XHTTP-Proto (0 = accept all)")
	cmd.IntVar(&s.ChunkSizeKB, "chunk-size-kb", 0, "Upstream payload per poll request, 16-900 (0 = 256)")
	cmd.IntVar(&s.MaxConns, "max-conns", 0, "Client max concurrent connections (0 = 512)")
	cmd.IntVar(&s.IdleTimeout, "idle-timeout", 0, "Client seconds of silence before dropping a connection (0 = 900)")
	cmd.StringVar(&s.AllowedTargets, "allowed-targets", "", "loopback (default), all, or a comma-separated list of host:port / :port / host: / [host] / *, each optionally prefixed tcp:// or udp:// to restrict the protocol")
	cmd.BoolVar(&s.TrustProxy, "trust-proxy-headers", false, "Honour proxy IP headers for client-address logging (server)")
	cmd.BoolVar(&s.BrutalEnable, "brutal-enable", false, "Enable TCP Brutal on the TCP tunnel sockets (Linux only)")
	cmd.Uint64Var(&s.BrutalRate, "brutal-rate", 0, "brutal rate ceiling in bytes/s (required when brutal-enable is set and bw-exchange is not)")
	cmd.IntVar(&s.BrutalCwndGain, "brutal-cwnd-gain", 0, "brutal cwnd_gain in tenths, so 20 = 2.0x (0 = default 20, max 100)")
	cmd.Uint64Var(&s.BrutalGroupID, "brutal-group-id", 0, "brutal connection group id; 0 = per-connection only")
	cmd.BoolVar(&s.BrutalGroupRemote, "brutal-group-from-remote", false, "Derive the brutal group from the peer's address instead of brutal-group-id (server only)")
	cmd.BoolVar(&s.BrutalBWExchange, "brutal-bw-exchange", false, "Enable the _BrutalBwExchange bandwidth exchange protocol")
	cmd.Uint64Var(&s.BrutalBWAdvertise, "brutal-bw-advertise", 0, "bytes/s this side can ingest, advertised to the peer (requires brutal-bw-exchange)")
	cmd.IntVar(&s.BrutalBWInterval, "brutal-bw-interval", 0, "Seconds between bandwidth exchange attempts (0 = 60)")
}

// genConfig is the single entry point both gen-config and gen-systemd use to
// turn flags into a ready-to-run config, so the two cannot diverge.
func genConfig(s *genSpec) (*FileConfig, *configCheck) {
	cfg, err := s.build()
	if err != nil {
		return nil, &configCheck{problems: []string{err.Error()}}
	}
	return cfg, checkConfig(cfg, s.PSKExplicit)
}

// ---------------------------------------------------------------------------
// gen-config
// ---------------------------------------------------------------------------

func runGenConfig(args []string) {
	cmd := flag.NewFlagSet("gen-config", flag.ExitOnError)
	cmd.Usage = func() {
		fmt.Fprintf(cmd.Output(), "Usage: xhttptunnel gen-config [flags]\n\n")
		fmt.Fprintln(cmd.Output(), "Write a ready-to-run server or client configuration. stdout carries JSON only, so the output can be piped; every message goes to stderr.")
		fmt.Fprintln(cmd.Output(), "\nFlags:")
		cmd.PrintDefaults()
	}
	outPath := cmd.String("o", "", "Write the config to this file with mode 0600 instead of printing it")
	withDocs := cmd.Bool("docs", true, "Include the _description and _fields documentation keys")

	var s genSpec
	bindGenConfigFlags(cmd, &s)
	_ = cmd.Parse(args)
	s.Changed = changedFlags(cmd)

	cfg, check := genConfig(&s)
	for _, w := range check.warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if check.err() != nil {
		fmt.Fprintln(os.Stderr, check.err())
		os.Exit(2)
	}

	if s.PSKGenerated != "" {
		fmt.Fprintf(os.Stderr, "generated PSK: %s\n", s.PSKGenerated)
		fmt.Fprintln(os.Stderr, "record it now: the config stores it, but this is the only time it is printed in full")
	}

	data, err := renderConfig(cfg, *withDocs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render config: %v\n", err)
		os.Exit(2)
	}
	if *outPath != "" {
		if err := writeFileAtomic(*outPath, data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *outPath, err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (mode 0600, %d bytes)\n", *outPath, len(data))
		return
	}
	os.Stdout.Write(data)
}

// ---------------------------------------------------------------------------
// gen-systemd
// ---------------------------------------------------------------------------

func runGenSystemd(args []string) {
	cmd := flag.NewFlagSet("gen-systemd", flag.ExitOnError)
	cmd.Usage = func() {
		fmt.Fprintf(cmd.Output(), "Usage: xhttptunnel gen-systemd [flags]\n\n")
		fmt.Fprintln(cmd.Output(), "Write a hardened systemd unit for the xhttptunnel server or client. By default only the unit is printed; -emit-config also writes the config file the unit runs.")
		fmt.Fprintln(cmd.Output(), "\nFlags:")
		cmd.PrintDefaults()
	}

	binPath := cmd.String("bin", "/usr/local/bin/xhttptunnel", "Path to the xhttptunnel binary")
	unitName := cmd.String("unit-name", "xhttptunnel", "Systemd service name")
	configPath := cmd.String("config", "", "Config file the unit runs with (default /etc/xhttptunnel/config.<mode>.json)")
	unitOut := cmd.String("o", "", "Write the unit file here instead of printing it")
	user := cmd.String("user", "root", "User the service runs as")
	hardening := cmd.Bool("hardening", true, "Emit the systemd sandbox directives (requires systemd 240+)")
	emitConfig := cmd.Bool("emit-config", false, "Also write the config file the unit launches")
	force := cmd.Bool("force", false, "Overwrite an existing config file with -emit-config")

	var s genSpec
	bindGenConfigFlags(cmd, &s)
	_ = cmd.Parse(args)
	s.Changed = changedFlags(cmd)

	mode := strings.ToLower(strings.TrimSpace(s.Mode))
	if mode != "server" && mode != "client" {
		fmt.Fprintf(os.Stderr, "-mode must be \"server\" or \"client\", got %q\n", s.Mode)
		os.Exit(2)
	}
	if *configPath == "" {
		*configPath = fmt.Sprintf("/etc/xhttptunnel/config.%s.json", mode)
	}

	cfg, check := genConfig(&s)
	for _, w := range check.warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if check.err() != nil {
		fmt.Fprintln(os.Stderr, check.err())
		os.Exit(2)
	}
	if !*emitConfig {
		fmt.Fprintln(os.Stderr, "note: stdout carries the unit only; pass -emit-config to also write "+*configPath)
	}
	if *emitConfig {
		if _, err := os.Stat(*configPath); err == nil && !*force {
			fmt.Fprintf(os.Stderr, "warning: %s already exists and was left untouched; re-run with -force to replace it\n", *configPath)
		} else {
			data, err := renderConfig(cfg, true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "render config: %v\n", err)
				os.Exit(2)
			}
			if err := writeFileAtomic(*configPath, data, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "write %s: %v\n", *configPath, err)
				os.Exit(2)
			}
			fmt.Fprintf(os.Stderr, "wrote %s (mode 0600, %d bytes)\n", *configPath, len(data))
			if s.PSKGenerated != "" {
				fmt.Fprintf(os.Stderr, "generated PSK: %s\n", s.PSKGenerated)
			}
		}
	}

	unit := renderSystemdUnit(unitSystemdSpec{
		Mode:       mode,
		BinPath:    *binPath,
		ConfigPath: *configPath,
		User:       *user,
		Hardening:  *hardening,
		UnitName:   *unitName,
	})

	if *unitOut != "" {
		if err := writeFileAtomic(*unitOut, []byte(unit), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *unitOut, err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (mode 0644, %d bytes)\n", *unitOut, len(unit))
		return
	}
	os.Stdout.WriteString(unit)
}

// unitSystemdSpec is the resolved input for one unit file.
type unitSystemdSpec struct {
	Mode       string
	BinPath    string
	ConfigPath string
	User       string
	Hardening  bool
	UnitName   string
}

// linuxDir is the directory of a config path rendered with forward slashes, so
// the unit is valid on Linux regardless of which OS the generator ran on.
// path.Dir alone would leave Windows backslashes behind, which systemd reads as
// escapes.
func linuxDir(p string) string {
	return filepath.ToSlash(filepath.Dir(p))
}

// sdQuote wraps an argument so systemd parses it as one token. Space, backslash
// and both quote styles are escaped; parentheses as well, because systemd treats
// them as grouping characters inside a unit file. Everything is quoted, not only
// paths that look dangerous, so a later edit cannot silently break a unit.
func sdQuote(arg string) string {
	var b strings.Builder
	b.Grow(len(arg) + 2)
	b.WriteByte('"')
	for _, r := range arg {
		switch r {
		case '\\', '"', '\'', '(', ')':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// renderSystemdUnit emits a unit that actually loads. Only directives available
// since systemd 240 (2019) are used, so this loads on Debian 10 / Ubuntu 18.04
// and newer. Newer ones such as ProtectProc= and ProcSubset= are deliberately
// omitted: an unknown directive makes systemd refuse to load the whole unit.
func renderSystemdUnit(sp unitSystemdSpec) string {
	role := "server"
	wantNetwork := "network.target"
	if sp.Mode == "client" {
		role = "client"
		// A client that boots before the NIC is up only burns RestartSec cycles
		// until the network arrives; waiting on network-online is shorter.
		wantNetwork = "network-online.target"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=xhttptunnel Split-HTTP streaming tunnel %s\n", role)
	b.WriteString("Documentation=https://github.com/NNdroid/xhttptunnel\n")
	fmt.Fprintf(&b, "After=%s\nWants=%s\n", wantNetwork, wantNetwork)
	b.WriteString("StartLimitIntervalSec=60\nStartLimitBurst=5\n\n")

	b.WriteString("[Service]\nType=simple\n")
	if sp.User != "" {
		fmt.Fprintf(&b, "User=%s\n", sp.User)
	}
	// The self-signed cert generator writes cert.pem/key.pem into the working
	// directory, so pin it next to the config or those would land in / .
	configDir := linuxDir(sp.ConfigPath)
	fmt.Fprintf(&b, "WorkingDirectory=%s\n", sdQuote(configDir))
	fmt.Fprintf(&b, "ExecStart=%s\n", strings.Join([]string{
		sdQuote(sp.BinPath), sdQuote("-c"), sdQuote(sp.ConfigPath),
	}, " "))
	b.WriteString("Restart=always\nRestartSec=3s\nTimeoutStopSec=15s\n")
	b.WriteString("StandardOutput=journal\nStandardError=journal\n")
	fmt.Fprintf(&b, "SyslogIdentifier=%s\n", sp.UnitName)
	b.WriteString("LimitNOFILE=1048576\n")

	if sp.Hardening {
		b.WriteString("\n# Sandbox. CapabilityBoundingSet= drops every capability, which is all a\n")
		b.WriteString("# plain tunneled TCP/UDP relay needs. ProtectSystem=strict makes the whole\n")
		b.WriteString("# tree read-only apart from ReadWritePaths, which is where the config and\n")
		b.WriteString("# the generated cert.pem/key.pem live.\n")
		b.WriteString("NoNewPrivileges=true\n")
		b.WriteString("ProtectSystem=strict\n")
		b.WriteString("ProtectHome=true\n")
		b.WriteString("PrivateTmp=true\n")
		b.WriteString("PrivateDevices=true\n")
		b.WriteString("ProtectKernelTunables=true\n")
		b.WriteString("ProtectKernelModules=true\n")
		b.WriteString("ProtectControlGroups=true\n")
		b.WriteString("RestrictSUIDSGID=true\n")
		b.WriteString("RestrictNamespaces=true\n")
		b.WriteString("RestrictRealtime=true\n")
		b.WriteString("MemoryDenyWriteExecute=true\n")
		b.WriteString("LockPersonality=true\n")
		b.WriteString("SystemCallArchitectures=native\n")
		b.WriteString("CapabilityBoundingSet=\n")
		b.WriteString("AmbientCapabilities=\n")
		fmt.Fprintf(&b, "ReadWritePaths=%s\n", sdQuote(linuxDir(sp.ConfigPath)))
	}

	b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// gen-nginx
// ---------------------------------------------------------------------------

// nginxOptions is the fully-resolved input for one nginx snippet. Keeping it a
// value type means renderNginx is pure and testable without a process exit.
type nginxOptions struct {
	Domain       string
	Path         string
	Backend      string
	Scheme       string
	UpstreamName string
	ChunkKB      int
	HeadroomKB   int
	ServerBlock  bool
	TLS          bool
	TLSPort      int
	HTTPPort     int
	HTTP2        bool
	Cert         string
	CertKey      string
	TokenHeader  string
}

func (o nginxOptions) render() (string, error) {
	if err := checkNginxInput(o.Path, o.Backend, o.ChunkKB, o.HeadroomKB, o.UpstreamName); err != nil {
		return "", err
	}
	if o.TLS && !o.ServerBlock {
		return "", fmt.Errorf("-tls requires -server-block: the ssl listen line needs a server{} block to live in")
	}

	backendScheme := strings.ToLower(strings.TrimSpace(o.Scheme))
	if backendScheme == "auto" {
		backendScheme = autoBackendScheme(o.Backend)
	}
	if backendScheme != "http" && backendScheme != "https" {
		return "", fmt.Errorf("-scheme %q must be http or https", o.Scheme)
	}
	emitBlock := o.ServerBlock || o.TLS

	// nginx counts k as 1024 bytes while chunk_size_kb counts 1000, so the
	// limit is computed in bytes and converted at the end.
	bodyKB := int((int64(o.ChunkKB)*1000 + int64(o.HeadroomKB)*1024 + 1023) / 1024)

	var b strings.Builder
	b.WriteString("# xhttptunnel origin — generated by `xhttptunnel gen-nginx`.\n")
	b.WriteString("# The upstream block and the location belong together; keep them in the\n")
	b.WriteString("# same file, or #include the one containing both.\n\n")
	fmt.Fprintf(&b, "upstream %s {\n", o.UpstreamName)
	fmt.Fprintf(&b, "    server %s;\n", hostBracketed(o.Backend))
	b.WriteString("    # Idle pool for the poll path. nginx will not reuse a single-server\n")
	b.WriteString("    # connection without an upstream block, so this is what turns each poll\n")
	b.WriteString("    # into a reused socket instead of a fresh connect per request.\n")
	b.WriteString("    keepalive 128;\n")
	b.WriteString("    keepalive_timeout 60s;\n")
	b.WriteString("    keepalive_requests 10000;\n")
	b.WriteString("}\n\n")

	if emitBlock {
		listen := fmt.Sprintf("listen %d", o.HTTPPort)
		if o.TLS {
			listen = fmt.Sprintf("listen %d ssl", o.TLSPort)
			if o.HTTP2 {
				listen += " http2"
			}
		}
		b.WriteString("server {\n")
		fmt.Fprintf(&b, "    %s;\n", listen)
		fmt.Fprintf(&b, "    server_name %s;\n\n", o.Domain)
		if o.TLS {
			fmt.Fprintf(&b, "    ssl_certificate %s;\n", o.Cert)
			fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", o.CertKey)
			b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
			b.WriteString("    ssl_session_cache shared:xhttptunnel:10m;\n")
			b.WriteString("    ssl_session_timeout 1d;\n\n")
		}
		b.WriteString(locationBlock(o.Path, o.UpstreamName, backendScheme, bodyKB, o.TokenHeader, 1))
		b.WriteString("}\n")
	} else {
		b.WriteString(locationBlock(o.Path, o.UpstreamName, backendScheme, bodyKB, o.TokenHeader, 0))
	}

	return b.String(), nil
}

func runGenNginx(args []string) {
	cmd := flag.NewFlagSet("gen-nginx", flag.ExitOnError)
	cmd.Usage = func() {
		fmt.Fprintf(cmd.Output(), "Usage: xhttptunnel gen-nginx [flags]\n\n")
		fmt.Fprintln(cmd.Output(), "Write an nginx reverse proxy for a tunnel origin. The default is an upstream block plus a location snippet for inside an existing server block; -server-block adds the server{} wrapper, -tls adds the ssl listen line.")
		fmt.Fprintln(cmd.Output(), "\nFlags:")
		cmd.PrintDefaults()
	}
	outPath := cmd.String("o", "", "Write the config to this file instead of printing it")

	opts, err := nginxOptionsFromFlags(cmd, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out, err := opts.render()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *outPath != "" {
		if err := writeFileAtomic(*outPath, []byte(out), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *outPath, err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (mode 0644, %d bytes)\n", *outPath, len(out))
		return
	}
	os.Stdout.WriteString(out)
}

// nginxOptionsFromFlags binds the gen-nginx flags, so a test can exercise the
// same flag surface the CLI exposes.
func nginxOptionsFromFlags(cmd *flag.FlagSet, args []string) (nginxOptions, error) {
	domain := cmd.String("domain", "example.com", "Server name, used by -server-block")
	path := cmd.String("path", "/stream", "Tunnel path")
	backend := cmd.String("backend", "127.0.0.1:8443", "Origin host:port")
	scheme := cmd.String("scheme", "auto", "Backend scheme: auto, http or https")
	upstreamName := cmd.String("upstream-name", "xhttptunnel_backend", "Name of the upstream block")
	chunkKB := cmd.Int("chunk-size-kb", 256, "Tunnel chunk_size_kb; sizes client_max_body_size")
	headroomKB := cmd.Int("body-headroom-kb", 128, "Request overhead allowed above the chunk size")
	serverBlock := cmd.Bool("server-block", false, "Wrap the location in a server{} block")
	tls := cmd.Bool("tls", false, "Use an ssl listen line (implies -server-block)")
	tlsPort := cmd.Int("tls-port", 443, "Frontend TLS port")
	httpPort := cmd.Int("http-port", 80, "Frontend plain HTTP port when -tls is off")
	http2 := cmd.Bool("http2", false, "Enable h2 on the frontend listen line")
	certPath := cmd.String("cert", "/etc/nginx/ssl/fullchain.pem", "Frontend certificate path with -tls")
	keyPath := cmd.String("cert-key", "/etc/nginx/ssl/privkey.pem", "Frontend private key path with -tls")
	tokenHeader := cmd.String("token-header", "X-Auth-Token", "Header the token is read from")

	if err := cmd.Parse(args); err != nil {
		return nginxOptions{}, err
	}
	return nginxOptions{
		Domain: *domain, Path: *path, Backend: *backend, Scheme: *scheme,
		UpstreamName: *upstreamName, ChunkKB: *chunkKB, HeadroomKB: *headroomKB,
		ServerBlock: *serverBlock, TLS: *tls, TLSPort: *tlsPort, HTTPPort: *httpPort,
		HTTP2: *http2, Cert: *certPath, CertKey: *keyPath, TokenHeader: *tokenHeader,
	}, nil
}

// locationBlock renders the location, indented one extra level when nested in a
// server{} block.
func locationBlock(path, upstreamName, scheme string, bodyKB int, tokenHeader string, depth int) string {
	frame := strings.Repeat("    ", depth)
	pad := frame + "    "
	var b strings.Builder
	fmt.Fprintf(&b, "%slocation %s {\n", frame, path)
	b.WriteString(pad + "# The tunnel streams arbitrarily long bodies, so both buffering stages are\n")
	b.WriteString(pad + "# off: nginx pipes straight to the origin instead of staging in temp files.\n")
	b.WriteString(pad + "proxy_buffering off;\n")
	b.WriteString(pad + "proxy_request_buffering off;\n\n")
	b.WriteString(pad + "# One poll request carries at most chunk_size_kb plus request overhead, so\n")
	b.WriteString(pad + "# this sits just above the chunk rather than at 0 (unlimited), which would\n")
	b.WriteString(pad + "# let a single request hold megabytes of body per connection.\n")
	fmt.Fprintf(&b, "%sclient_max_body_size %dk;\n\n", pad, bodyKB)
	b.WriteString(pad + "proxy_http_version 1.1;\n")
	b.WriteString(pad + "# Required to make nginx actually use the upstream keepalive pool above.\n")
	b.WriteString(pad + "# Without it nginx sends Connection: close and opens a fresh upstream socket\n")
	b.WriteString(pad + "# per request, the single biggest throughput hit on the poll path.\n")
	b.WriteString(pad + "proxy_set_header Connection \"\";\n\n")
	fmt.Fprintf(&b, "%sproxy_pass %s://%s;\n\n", pad, scheme, upstreamName)
	b.WriteString(pad + "proxy_set_header Host $host;\n")
	b.WriteString(pad + "proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString(pad + "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	fmt.Fprintf(&b, "%sproxy_set_header %s $http_%s;\n", pad, tokenHeader, httpArg(tokenHeader))
	b.WriteString(pad + "# trust_proxy_headers must be on server-side for these to be trusted.\n\n")
	b.WriteString(pad + "proxy_connect_timeout 10s;\n")
	b.WriteString(pad + "proxy_read_timeout 86400s;\n")
	b.WriteString(pad + "proxy_send_timeout 86400s;\n\n")
	b.WriteString(pad + "# A retried POST would replay tunnel bytes at another origin. The pool holds\n")
	b.WriteString(pad + "# one server today, but this keeps the setting honest if one is added.\n")
	b.WriteString(pad + "proxy_next_upstream off;\n")
	fmt.Fprintf(&b, "%s}\n", frame)
	return b.String()
}

// httpArg turns X-Auth-Token into x_auth_token for nginx's $http_ variable
// namespace: lowercase, dashes to underscores.
func httpArg(header string) string {
	return strings.ReplaceAll(strings.ToLower(header), "-", "_")
}

func checkNginxInput(path, backend string, chunkKB, headroomKB int, upstreamName string) error {
	if !strings.HasPrefix(strings.TrimSpace(path), "/") {
		return fmt.Errorf("-path %q must start with \"/\"", path)
	}
	if _, _, ok := splitHostPort(backend); !ok {
		return fmt.Errorf("-backend %q must be host:port; an IPv6 literal is fine with or without brackets", backend)
	}
	if strings.TrimSpace(upstreamName) == "" || strings.ContainsAny(upstreamName, " \t;{}") {
		return fmt.Errorf("-upstream-name %q must be a single nginx identifier", upstreamName)
	}
	if chunkKB != 0 && (chunkKB < 16 || chunkKB > 900) {
		return fmt.Errorf("-chunk-size-kb %d must be 16-900 to match the tunnel's clamped range", chunkKB)
	}
	if headroomKB < 0 {
		return fmt.Errorf("-body-headroom-kb %d must be >= 0", headroomKB)
	}
	return nil
}

// autoBackendScheme picks https for a hostname and http for an address or
// localhost: a named origin is usually TLS-terminated at the edge, a loopback
// one is the local tunnel process speaking plain HTTP.
func autoBackendScheme(backend string) string {
	host, port, ok := splitHostPort(backend)
	if !ok {
		host = backend
	} else {
		if port == "443" {
			return "https"
		}
		host = strings.Trim(host, "[]")
	}
	if host == "localhost" || net.ParseIP(host) != nil {
		return "http"
	}
	return "https"
}

// splitHostPort is net.SplitHostPort plus recovery for a bare IPv6 literal,
// which carries no brackets and so cannot be parsed as host:port.
func splitHostPort(addr string) (host, port string, ok bool) {
	if host, port, err := net.SplitHostPort(addr); err == nil {
		return host, port, true
	}
	// net.SplitHostPort rejects a bracketed IPv6 literal written without a port,
	// but the runtime matcher reads "[::1]" as "that host on any port" — the
	// bracketed form of "host:". Accept it here too, otherwise the generator
	// would refuse a rule the server happily honours.
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]")
		if end < 0 || addr[end+1:] != "" {
			return "", "", false
		}
		return addr[1:end], "", true
	}
	idx := strings.LastIndex(addr, ":")
	if idx <= 0 || idx == len(addr)-1 {
		return "", "", false
	}
	host, port = addr[:idx], addr[idx+1:]
	if net.ParseIP(host) == nil {
		return "", "", false
	}
	return host, port, true
}

// hostBracketed renders host:port with an IPv6 literal bracketed, the form
// nginx requires.
func hostBracketed(addr string) string {
	host, port, ok := splitHostPort(addr)
	if !ok {
		return addr
	}
	if host == "" {
		return ":" + port
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + port
}
