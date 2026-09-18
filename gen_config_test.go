package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// mustSpec binds the real flag surface, parses args, and records which flags the
// caller actually set. An empty mode leaves the flag default in place.
func mustSpec(t *testing.T, args ...string) *genSpec {
	t.Helper()
	cmd := flag.NewFlagSet("test", flag.ContinueOnError)
	cmd.SetOutput(io.Discard)
	var s genSpec
	bindGenConfigFlags(cmd, &s)
	if err := cmd.Parse(args); err != nil {
		t.Fatalf("flag parse %v: %v", args, err)
	}
	s.Changed = changedFlags(cmd)
	return &s
}

func mustBuild(t *testing.T, s *genSpec) *FileConfig {
	t.Helper()
	cfg, err := s.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return cfg
}

func mustRender(t *testing.T, cfg *FileConfig, docs bool) []byte {
	t.Helper()
	data, err := renderConfig(cfg, docs)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return data
}

func jsonKeys(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func keySet(m map[string]any) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

// setEqual ignores order and returns the symmetric difference.
func setEqual(a, b map[string]bool) ([]string, bool) {
	var diff []string
	for k := range a {
		if _, ok := b[k]; !ok {
			diff = append(diff, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			diff = append(diff, k)
		}
	}
	return diff, len(diff) == 0
}

func TestGenConfigServerDefaults(t *testing.T) {
	s := mustSpec(t, "-mode", "server")
	cfg := mustBuild(t, s)
	if err := checkConfig(cfg, s.PSKExplicit).err(); err != nil {
		t.Fatalf("the default server config failed its own validation: %v", err)
	}

	data := mustRender(t, cfg, true)
	if !json.Valid(data) {
		t.Fatalf("rendered server config is not valid JSON:\n%s", data)
	}

	want := []string{
		"_description", "_fields", "mode", "listen", "path", "target", "psk", "selfsign",
		"selfsign_cn", "cert", "key", "fallback", "allowed_targets", "max_sessions",
		"max_sessions_per_ip", "health_path", "min_proto_version", "chunk_size_kb",
		"trust_proxy_headers", "brutal", "dump", "log_level",
	}
	m := jsonKeys(t, data)
	if len(m) != len(want) {
		t.Errorf("server config has %d keys, want %d", len(m), len(want))
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("server config missing key %q", k)
		}
	}

	if cfg.Listen != ":8443" || cfg.Path != "/stream" || cfg.Target != "tcp://127.0.0.1:22" {
		t.Errorf("unexpected server defaults: listen=%q path=%q target=%q", cfg.Listen, cfg.Path, cfg.Target)
	}
	if cfg.SelfSign != true || cfg.SelfSignCN != "www.bing.com" || cfg.Fallback != "https://www.bing.com" {
		t.Errorf("unexpected self-sign defaults: selfsign=%v cn=%q fallback=%q", cfg.SelfSign, cfg.SelfSignCN, cfg.Fallback)
	}
	if len(cfg.AllowedTargets) != 2 || cfg.AllowedTargets[0] != "127.0.0.1:" || cfg.AllowedTargets[1] != "localhost:" {
		t.Errorf("allowed_targets = %v, want the loopback policy", cfg.AllowedTargets)
	}
	if cfg.MaxSessions != 2000 || cfg.MaxSessionsPerIP != 50 || cfg.ChunkSizeKB != 256 {
		t.Errorf("limits = sessions %d per-ip %d chunk %d", cfg.MaxSessions, cfg.MaxSessionsPerIP, cfg.ChunkSizeKB)
	}
	if cfg.MinProtoVersion != 0 || cfg.HealthPath != "" {
		t.Errorf("health_path=%q min_proto_version=%d, both must default off", cfg.HealthPath, cfg.MinProtoVersion)
	}
	// Brutal must default fully off: a fresh config costs nothing and calls no
	// setsockopt, so operators opt in explicitly.
	if b := cfg.Brutal; b.Enabled || b.Rate != 0 || b.GroupID != 0 || b.GroupFromRemote ||
		b.BWExchange || b.BWAdvertise != 0 {
		t.Errorf("brutal defaults are not fully off: %+v", b)
	}
	if len(cfg.PSK) != 64 {
		t.Fatalf("generated PSK is %d chars, want 64 hex", len(cfg.PSK))
	}
	for _, c := range cfg.PSK {
		if !strings.Contains("0123456789abcdef", string(c)) {
			t.Fatalf("generated PSK %q is not lower-case hex", cfg.PSK)
		}
	}
	if other := mustBuild(t, mustSpec(t, "-mode", "server")); other.PSK == cfg.PSK {
		t.Error("two default server configs generated the same PSK")
	}
}

func TestGenConfigClientDefaults(t *testing.T) {
	s := mustSpec(t, "-mode", "client")
	cfg := mustBuild(t, s)
	if err := checkConfig(cfg, s.PSKExplicit).err(); err != nil {
		t.Fatalf("the default client config failed its own validation: %v", err)
	}
	if !json.Valid(mustRender(t, cfg, true)) {
		t.Fatal("rendered client config is not valid JSON")
	}
	if cfg.Listen != "tcp://127.0.0.1:1080" || cfg.Target != "127.0.0.1:22" {
		t.Errorf("unexpected client defaults: listen=%q target=%q", cfg.Listen, cfg.Target)
	}
	if cfg.ServerURL != "https://127.0.0.1:8443/stream" {
		t.Errorf("server = %q", cfg.ServerURL)
	}
	if cfg.ALPN != "auto" || cfg.StreamMode != "auto" || cfg.ChunkSizeKB != 256 {
		t.Errorf("transport = alpn %q stream %q chunk %d", cfg.ALPN, cfg.StreamMode, cfg.ChunkSizeKB)
	}
	if cfg.IdleTimeout != 900 || cfg.MaxConns != 512 {
		t.Errorf("client limits = idle %d conns %d", cfg.IdleTimeout, cfg.MaxConns)
	}
	// A client must not invent a secret: it keeps the placeholder so the binary
	// refuses to start rather than failing every handshake.
	if cfg.PSK != placeholderPSK {
		t.Errorf("client PSK = %q, want the placeholder", cfg.PSK)
	}
	if s.PSKGenerated != "" {
		t.Error("client mode must not generate a PSK")
	}

	// The default client is not directly runnable against the default server:
	// the server impersonates www.bing.com while the client inherits 127.0.0.1
	// as its SNI. The warning must name both halves of the problem.
	warns := strings.Join(checkConfig(cfg, false).warnings, " ")
	if !strings.Contains(warns, "fingerprint") || !strings.Contains(warns, "hostname verification") {
		t.Errorf("the default client config does not warn about the missing TLS pin: %q", warns)
	}
}

func TestClientTLSWarningDisappearsWhenPinned(t *testing.T) {
	// A pinned, SNI-disguised client is a complete configuration: no warning
	// about verification is owed to the operator.
	s := mustSpec(t, "-mode", "client", "-psk", "secret",
		"-fingerprint", "aa", "-sni", "www.bing.com", "-host", "www.bing.com")
	cfg := mustBuild(t, s)
	warns := strings.Join(checkConfig(cfg, s.PSKExplicit).warnings, " ")
	if strings.Contains(warns, "fingerprint") {
		t.Errorf("a pinned client still warns about the missing pin: %q", warns)
	}
}

func TestClientTargetMustStayBare(t *testing.T) {
	cfg := mustBuild(t, mustSpec(t, "-mode", "client", "-target", "tcp://10.0.0.5:22", "-psk", "real-secret"))
	err := checkConfig(cfg, false).err()
	if err == nil {
		t.Fatal("a tcp:// client target passed validation; the server would deny it")
	}
	if !strings.Contains(err.Error(), "bare") {
		t.Errorf("error does not explain the bare host:port rule: %v", err)
	}
	// The server config keeps the tcp:// scheme, which is where it belongs.
	cfg = mustBuild(t, mustSpec(t, "-mode", "server", "-target", "tcp://10.0.0.5:22", "-psk", "s"))
	if err := checkConfig(cfg, false).err(); err != nil {
		t.Errorf("a server tcp:// target was rejected: %v", err)
	}
}

func TestGenConfigValidationMatrix(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad alpn", []string{"-mode", "client", "-alpn", "h4", "-psk", "s"}, "alpn"},
		{"bad stream_mode", []string{"-mode", "client", "-stream-mode", "fast", "-psk", "s"}, "stream_mode"},
		{"bad log_level", []string{"-log-level", "verbose", "-psk", "s"}, "log_level"},
		{"chunk too small", []string{"-chunk-size-kb", "4", "-psk", "s"}, "chunk_size_kb"},
		{"chunk too large", []string{"-chunk-size-kb", "1200", "-psk", "s"}, "chunk_size_kb"},
		{"negative max_sessions", []string{"-max-sessions", "-1", "-psk", "s"}, "max_sessions"},
		{"negative idle_timeout", []string{"-mode", "client", "-idle-timeout", "-5", "-psk", "s"}, "idle_timeout"},
		{"negative min_proto_version", []string{"-min-proto-version", "-1", "-psk", "s"}, "min_proto_version"},
		{"health_path no slash", []string{"-health-path", "healthz", "-psk", "s"}, "health_path"},
		{"path no slash", []string{"-path", "stream", "-psk", "s"}, "path"},
		{"bad listen port", []string{"-listen", ":99999", "-psk", "s"}, "listen"},
		{"bad listen form", []string{"-listen", "8443", "-psk", "s"}, "listen"},
		{"bad allowed target", []string{"-allowed-targets", "22", "-psk", "s"}, "allowed_targets"},
		{"bad allowed target port", []string{"-allowed-targets", ":0", "-psk", "s"}, "allowed_targets"},
		{"bad allowed target scheme", []string{"-allowed-targets", "grpc://1.2.3.4:22", "-psk", "s"}, "allowed_targets"},
		{"bad allowed target host", []string{"-allowed-targets", "tcp://bad host:22", "-psk", "s"}, "allowed_targets"},
		{"bad server url", []string{"-mode", "client", "-server", "ftp://x", "-psk", "s"}, "server"},
		{"bad selfsign cn", []string{"-selfsign-cn", "bad host", "-psk", "s"}, "selfsign_cn"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mustSpec(t, tc.args...)
			cfg := mustBuild(t, s)
			err := checkConfig(cfg, s.PSKExplicit).err()
			if err == nil {
				t.Fatalf("invalid input %v passed validation", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

func TestGenConfigRejectsUnknownPskMode(t *testing.T) {
	s := mustSpec(t, "-psk-mode", "guess")
	if _, err := s.build(); err == nil {
		t.Fatal("an unknown -psk-mode was accepted")
	}
}

func TestGenConfigRejectsUnknownMode(t *testing.T) {
	for _, mode := range []string{"", "proxy", "tunnel"} {
		s := mustSpec(t, "-mode", mode)
		if _, err := s.build(); err == nil {
			t.Errorf("-mode %q was accepted", mode)
		}
	}
}

func TestOpenMode(t *testing.T) {
	cfg := mustBuild(t, mustSpec(t, "-psk", ""))
	if cfg.PSK != "" {
		t.Fatalf("psk = %q, want empty for open mode", cfg.PSK)
	}
	check := checkConfig(cfg, false)
	if check.err() != nil {
		t.Fatalf("open mode must be legal: %v", check.err())
	}
	if !check.warned() {
		t.Errorf("open mode must warn about unauthenticated sessions; warnings = %v", check.warnings)
	}
	if joined := strings.Join(check.warnings, " "); !strings.Contains(joined, "unauthenticated") {
		t.Errorf("open-mode warning is not about authentication: %v", check.warnings)
	}
}

func TestPublishedExampleTokensAreRejected(t *testing.T) {
	for _, token := range []string{placeholderPSK, "my-secret-token", "change-me-before-use"} {
		// An explicitly typed example token is a hard error: the operator pasted
		// documentation instead of a secret.
		s := mustSpec(t, "-psk", token)
		cfg := mustBuild(t, s)
		if err := checkConfig(cfg, s.PSKExplicit).err(); err == nil {
			t.Errorf("published example token %q was accepted", token)
		}
	}
}

func TestPskModePlaceholderOnServer(t *testing.T) {
	// A deliberate template: legal to generate, illegal to run. The generator
	// warns; the binary's own isPlaceholderPSK check is the hard refusal.
	s := mustSpec(t, "-psk-mode", "placeholder")
	cfg := mustBuild(t, s)
	if cfg.PSK != placeholderPSK {
		t.Errorf("psk = %q, want the placeholder", cfg.PSK)
	}
	check := checkConfig(cfg, s.PSKExplicit)
	if check.err() != nil {
		t.Fatalf("a requested template must still be generated: %v", check.err())
	}
	joined := strings.Join(check.warnings, " ")
	if !strings.Contains(joined, "placeholder") || !strings.Contains(joined, "refuse to start") {
		t.Errorf("the placeholder warning is unclear: %v", check.warnings)
	}
}

func TestPskFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	secret := "file-secret-0123456789\n"
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := mustBuild(t, mustSpec(t, "-psk-file", path))
	if cfg.PSK != strings.TrimSpace(secret) {
		t.Errorf("psk = %q, want the trimmed file contents", cfg.PSK)
	}
	if _, err := mustSpec(t, "-psk-file", filepath.Join(dir, "missing")).build(); err == nil {
		t.Error("a missing -psk-file did not fail")
	}
}

func TestPskModeOpenAndRandom(t *testing.T) {
	cfg := mustBuild(t, mustSpec(t, "-psk-mode", "open"))
	if cfg.PSK != "" {
		t.Errorf("psk = %q, want empty", cfg.PSK)
	}
	cfg = mustBuild(t, mustSpec(t, "-mode", "client", "-psk-mode", "random"))
	if len(cfg.PSK) != 64 {
		t.Errorf("psk = %q, want 64 hex chars", cfg.PSK)
	}
}

func TestExplicitPskBeatsPskMode(t *testing.T) {
	cfg := mustBuild(t, mustSpec(t, "-psk", "operator-secret", "-psk-mode", "random"))
	if cfg.PSK != "operator-secret" {
		t.Errorf("psk = %q, want the explicit -psk value", cfg.PSK)
	}
}

func TestAllowedTargetsShorthand(t *testing.T) {
	cases := []struct {
		in   string
		args []string
		want []string
	}{
		{"unset defaults to the loopback policy", []string{}, []string{"127.0.0.1:", "localhost:"}},
		{"loopback", []string{"-allowed-targets", "loopback"}, []string{"127.0.0.1:", "localhost:"}},
		{"all opens the policy", []string{"-allowed-targets", "all"}, []string{}},
		{"comma list", []string{"-allowed-targets", "10.0.0.5:22, :3306, db.local:"}, []string{"10.0.0.5:22", ":3306", "db.local:"}},
		{"scheme-prefixed list is kept verbatim", []string{"-allowed-targets", "tcp://example.com:443, udp://:53, tcp://*: , udp://*:"}, []string{"tcp://example.com:443", "udp://:53", "tcp://*:", "udp://*:"}},
		{"blanks and trailing commas are dropped", []string{"-allowed-targets", "1.2.3.4:22,, "}, []string{"1.2.3.4:22"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			cfg := mustBuild(t, mustSpec(t, append(tc.args, "-psk", "s")...))
			if len(cfg.AllowedTargets) != len(tc.want) {
				t.Fatalf("allowed_targets = %v, want %v", cfg.AllowedTargets, tc.want)
			}
			for i := range cfg.AllowedTargets {
				if cfg.AllowedTargets[i] != tc.want[i] {
					t.Errorf("allowed_targets[%d] = %q, want %q", i, cfg.AllowedTargets[i], tc.want[i])
				}
			}
		})
	}
}

func TestCheckAllowedTargetEntry(t *testing.T) {
	accepted := []string{
		// The five forms the syntax is meant to cover.
		"tcp://example.com:443",
		"udp://:53",
		"tcp://192.168.1.10:",
		"tcp://*:",
		"udp://*:",
		// Scheme spelling is case-insensitive and the rest of the grammar is
		// unchanged.
		"TCP://example.com:443",
		"UDP://:53",
		"127.0.0.1:22",
		":8080",
		"db.local:5432",
		"192.168.1.10:",
		"host:65535",
		"tcp://[::1]:22",
		"udp://[::1]:53",
		// Bracketed IPv6 without a port is the bracketed form of "host:": that
		// host on any port. The runtime matcher has always honoured it, and the
		// generator used to refuse it, so an installer could not validate a
		// rule the server would accept.
		"[::1]",
		"tcp://[::1]",
		"*",
		"*:",
		":*",
		"  udp://:53  ",
	}
	for _, entry := range accepted {
		t.Run("accepts "+entry, func(t *testing.T) {
			if err := checkAllowedTargetEntry(entry); err != nil {
				t.Errorf("checkAllowedTargetEntry(%q) = %v, want nil", entry, err)
			}
		})
	}

	rejected := []struct{ entry, want string }{
		{"", "empty entry"},
		{"   ", "empty entry"},
		{"grpc://1.2.3.4:22", "has scheme"},
		{"http://1.2.3.4:22", "has scheme"},
		// A bare name is ambiguous with a forgotten port number.
		{"22", "must be"},
		{"db", "must be"},
		{"tcp://db", "must be"},
		{"tcp://", "must be"},
		{"tcp:///", "must be"},
		{":0", "port in 1-65535"},
		{":65536", "port in 1-65535"},
		{":abc", "port in 1-65535"},
		{"1.2.3.4:0", "port in 1-65535"},
		{"tcp://1.2.3.4:65536", "port in 1-65535"},
		{"tcp://bad host:22", "invalid host"},
		{"udp://has/evil:22", "invalid host"},
		{"[g::1]", "invalid host"},
		// A bracketed address with nothing after the bracket is "any port";
		// a garbage port after it is still caught.
		{"[::1]:extra", "port in 1-65535"},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.entry, func(t *testing.T) {
			err := checkAllowedTargetEntry(tc.entry)
			if err == nil {
				t.Fatalf("checkAllowedTargetEntry(%q) = nil, want an error", tc.entry)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

func TestClientSelfSignCNSpreadsToSNIAndHost(t *testing.T) {
	cfg := mustBuild(t, mustSpec(t, "-mode", "client", "-selfsign-cn", "cdn.amazon.com", "-psk", "s"))
	if cfg.SNI != "cdn.amazon.com" || cfg.Host != "cdn.amazon.com" {
		t.Errorf("sni=%q host=%q, want the disguise on both", cfg.SNI, cfg.Host)
	}
	cfg = mustBuild(t, mustSpec(t, "-mode", "client", "-selfsign-cn", "cdn.amazon.com", "-sni", "kept.example", "-psk", "s"))
	if cfg.SNI != "kept.example" || cfg.Host != "cdn.amazon.com" {
		t.Errorf("an explicit sni must win: sni=%q host=%q", cfg.SNI, cfg.Host)
	}
}

func TestRenderedConfigRoundTrips(t *testing.T) {
	for _, mode := range []string{"server", "client"} {
		cfg := mustBuild(t, mustSpec(t, "-mode", mode))
		data := mustRender(t, cfg, true)
		// The engine must load exactly what the generator writes, including the
		// _description/_fields extras it ignores.
		var got FileConfig
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("%s: the engine cannot parse the generated file: %v", mode, err)
		}
		if got.Mode != cfg.Mode || got.Listen != cfg.Listen || got.Target != cfg.Target || got.PSK != cfg.PSK {
			t.Errorf("%s: the round trip lost values: %+v", mode, got)
		}
	}
}

func TestRenderedConfigMatchesRepoSamples(t *testing.T) {
	cases := []struct {
		mode   string
		sample string
	}{
		{"server", "config.server.json"},
		{"client", "config.client.json"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			raw, err := os.ReadFile(tc.sample)
			if err != nil {
				t.Skipf("sample %s not present: %v", tc.sample, err)
			}
			sample := jsonKeys(t, raw)
			// A hand-edited sample must never ship a rule the runtime would
			// silently drop, so the entries are checked with the same validator
			// the generator applies. Only the server sample carries the list.
			if entries, ok := sample["allowed_targets"].([]any); ok {
				for _, entry := range entries {
					if s, ok := entry.(string); ok {
						if err := checkAllowedTargetEntry(s); err != nil {
							t.Errorf("%s ships an allowed_targets entry the runtime would drop: %v", tc.sample, err)
						}
					}
				}
			}
			cfg := mustBuild(t, mustSpec(t, "-mode", tc.mode))
			generated := jsonKeys(t, mustRender(t, cfg, true))

			strip := func(m map[string]any) map[string]bool {
				out := keySet(m)
				delete(out, "_description")
				delete(out, "_fields")
				return out
			}
			if diff, ok := setEqual(strip(generated), strip(sample)); !ok {
				t.Errorf("generated %s config fields drifted from %s: %v", tc.mode, tc.sample, diff)
			}
			// The documentation map must stay in step too, so a new field cannot
			// land in the JSON without a _fields entry.
			if diff, ok := setEqual(keySet(jsonKeys(t, mustMarshal(t, generated["_fields"]))), keySet(jsonKeys(t, mustMarshal(t, sample["_fields"])))); !ok {
				t.Errorf("generated _fields drifted from %s: %v", tc.sample, diff)
			}
			// Nested objects would slip through the two set comparisons above,
			// which only look at the top level, so walk every object-valued key
			// and compare its member set as well.
			for k, gv := range generated {
				gObj, gOK := gv.(map[string]any)
				sObj, sOK := sample[k].(map[string]any)
				if !gOK || !sOK {
					continue
				}
				if diff, ok := setEqual(keySet(gObj), keySet(sObj)); !ok {
					t.Errorf("%s %q members drifted from %s: %v", tc.mode, k, tc.sample, diff)
				}
			}
		})
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestRenderConfigJSONShape(t *testing.T) {
	data, err := renderConfigJSON([]jsonLine{
		{key: "_fields", docs: []stringDoc{{key: "a", value: "one"}, {key: "b", value: "two"}}},
		{key: "allowed_targets", val: []string{"127.0.0.1:", "localhost:"}},
		{key: "n", val: 7},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("not valid JSON:\n%s", data)
	}
	m := jsonKeys(t, data)
	if len(m) != 3 {
		t.Errorf("keys = %v", m)
	}
	// Slice order must survive rendering, not alphabetical sort order.
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "{\n  \"_fields\"") {
		t.Errorf("first key is not the first slice entry:\n%s", data)
	}
	if !strings.Contains(string(data), "  \"n\": 7") {
		t.Errorf("scalar line shape changed:\n%s", data)
	}
}

func TestRenderSystemdUnitServer(t *testing.T) {
	unit := renderSystemdUnit(unitSystemdSpec{
		Mode: "server", BinPath: "/usr/local/bin/xhttptunnel",
		ConfigPath: "/etc/xhttptunnel/config.server.json", User: "root", Hardening: true, UnitName: "xhttptunnel",
	})
	mustContain := func(s string) {
		if !strings.Contains(unit, s) {
			t.Errorf("unit is missing %q\n%s", s, unit)
		}
	}
	mustContain("[Unit]")
	mustContain("[Service]")
	mustContain("[Install]")
	mustContain("After=network.target")
	mustContain("Wants=network.target")
	mustContain("StartLimitIntervalSec=60")
	mustContain("StartLimitBurst=5")
	mustContain("Type=simple")
	mustContain("User=root")
	// WorkingDirectory is what makes a self-signed cert.pem/key.pem land next to
	// the config instead of in / . Quoted, so a config directory with a space
	// still reaches systemd as one path.
	mustContain(`WorkingDirectory="/etc/xhttptunnel"`)
	// Every argument quoted, so a path with a space stays one token.
	mustContain(`ExecStart="/usr/local/bin/xhttptunnel" "-c" "/etc/xhttptunnel/config.server.json"`)
	mustContain("Restart=always")
	mustContain("RestartSec=3s")
	mustContain("TimeoutStopSec=15s")
	mustContain("StandardOutput=journal")
	mustContain("StandardError=journal")
	mustContain("SyslogIdentifier=xhttptunnel")
	mustContain("LimitNOFILE=1048576")
	for _, d := range []string{
		"NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true",
		"PrivateDevices=true", "ProtectKernelTunables=true", "ProtectKernelModules=true",
		"ProtectControlGroups=true", "RestrictSUIDSGID=true", "RestrictNamespaces=true",
		"RestrictRealtime=true", "MemoryDenyWriteExecute=true", "LockPersonality=true",
		"SystemCallArchitectures=native", "CapabilityBoundingSet=", "AmbientCapabilities=",
		`ReadWritePaths="/etc/xhttptunnel"`,
	} {
		mustContain(d)
	}
	mustContain("WantedBy=multi-user.target")

	// The old generator printed a bare JSON config after the unit, which made the
	// whole output unloadable as a unit file. The unit must stay a pure unit.
	if strings.Contains(unit, "psk") || strings.Contains(unit, `"mode"`) || strings.Contains(unit, "{") {
		t.Errorf("unit leaks config JSON into a .service file:\n%s", unit)
	}
	if !strings.HasPrefix(unit, "[Unit]") {
		t.Errorf("unit does not start with [Unit]: %q", unit[:min(40, len(unit))])
	}
	if strings.Contains(unit, "\r") {
		t.Error("unit contains CR")
	}
}

func TestRenderSystemdUnitClientWaitsForNetwork(t *testing.T) {
	unit := renderSystemdUnit(unitSystemdSpec{
		Mode: "client", BinPath: "/opt/xhttptunnel", ConfigPath: "/etc/xhttptunnel/config.client.json",
		User: "xhttp", Hardening: true, UnitName: "xhttptunnel-client",
	})
	for _, s := range []string{
		"After=network-online.target", "Wants=network-online.target", "User=xhttp",
		`WorkingDirectory="/etc/xhttptunnel"`, "SyslogIdentifier=xhttptunnel-client",
		"streaming tunnel client",
	} {
		if !strings.Contains(unit, s) {
			t.Errorf("client unit missing %q\n%s", s, unit)
		}
	}
	if strings.Contains(unit, "After=network.target") {
		t.Errorf("client unit still targets bare network.target:\n%s", unit)
	}
}

func TestRenderSystemdUnitNoHardeningAndEmptyUser(t *testing.T) {
	unit := renderSystemdUnit(unitSystemdSpec{
		Mode: "server", BinPath: "/b", ConfigPath: "/etc/xhttptunnel/config.server.json",
		User: "", Hardening: false, UnitName: "xhttptunnel",
	})
	for _, s := range []string{"NoNewPrivileges", "ProtectSystem", "ReadWritePaths", "User="} {
		if strings.Contains(unit, s) {
			t.Errorf("unit still contains %q after disabling hardening:\n%s", s, unit)
		}
	}
}

func TestRenderSystemdUnitQuotesPaths(t *testing.T) {
	unit := renderSystemdUnit(unitSystemdSpec{
		Mode:       "server",
		BinPath:    "/opt/x http/xhttptunnel",
		ConfigPath: `/etc/x http/conf "my".json`,
		User:       "", Hardening: false, UnitName: "xhttptunnel",
	})
	if !strings.Contains(unit, `ExecStart="/opt/x http/xhttptunnel" "-c" "/etc/x http/conf \"my\".json"`) {
		t.Errorf("ExecStart quoting is wrong:\n%s", unit)
	}
	// The config's own directory is /etc/x http: "conf "my".json" is the file.
	if !strings.Contains(unit, `WorkingDirectory="/etc/x http"`) {
		t.Errorf("WorkingDirectory did not keep the space inside one quoted path:\n%s", unit)
	}
}

func TestRenderSystemdUnitConfigDirDrivesReadWritePaths(t *testing.T) {
	unit := renderSystemdUnit(unitSystemdSpec{
		Mode: "server", BinPath: "/b", ConfigPath: "/srv/tunnel/cfg/config.server.json",
		User: "u", Hardening: true, UnitName: "x",
	})
	if !strings.Contains(unit, `WorkingDirectory="/srv/tunnel/cfg"`) || !strings.Contains(unit, `ReadWritePaths="/srv/tunnel/cfg"`) {
		t.Errorf("config directory did not drive both directives:\n%s", unit)
	}
}

// nginxOutput runs the real gen-nginx flag surface without the process-level
// os.Exit, so the generator is exercised exactly as an operator types it.
func nginxOutput(t *testing.T, args ...string) string {
	t.Helper()
	cmd := flag.NewFlagSet("gen-nginx", flag.ContinueOnError)
	cmd.SetOutput(io.Discard)
	opts, err := nginxOptionsFromFlags(cmd, args)
	if err != nil {
		t.Fatalf("flags %v: %v", args, err)
	}
	out, err := opts.render()
	if err != nil {
		t.Fatalf("render %v: %v", args, err)
	}
	return out
}

func TestNginxDefaultSnippet(t *testing.T) {
	out := nginxOutput(t, "-backend", "127.0.0.1:8443")
	mustContain := func(s string) {
		if !strings.Contains(out, s) {
			t.Errorf("nginx output is missing %q\n%s", s, out)
		}
	}
	mustContain("upstream xhttptunnel_backend {")
	mustContain("server 127.0.0.1:8443;")
	mustContain("keepalive 128;")
	mustContain("keepalive_timeout 60s;")
	mustContain("keepalive_requests 10000;")
	mustContain("location /stream {")
	mustContain("proxy_buffering off;")
	mustContain("proxy_request_buffering off;")
	// 256 * 1000 + 128 * 1024 = 387072 bytes, exactly 378 of nginx's 1024-byte k.
	mustContain("client_max_body_size 378k;")
	mustContain("proxy_http_version 1.1;")
	mustContain(`proxy_set_header Connection "";`)
	mustContain("proxy_pass http://xhttptunnel_backend;")
	mustContain("proxy_set_header Host $host;")
	mustContain("proxy_set_header X-Real-IP $remote_addr;")
	mustContain("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
	mustContain("proxy_set_header X-Auth-Token $http_x_auth_token;")
	mustContain("proxy_next_upstream off;")
	mustContain("proxy_connect_timeout 10s;")
	mustContain("proxy_read_timeout 86400s;")
	mustContain("proxy_send_timeout 86400s;")

	if strings.Contains(out, "server {") {
		t.Errorf("the default output must not emit a server{} block:\n%s", out)
	}
}

func TestNginxIPv6Backend(t *testing.T) {
	out := nginxOutput(t, "-backend", "[::1]:8443")
	if !strings.Contains(out, "server [::1]:8443;") {
		t.Errorf("the IPv6 backend was not bracketed:\n%s", out)
	}
	if strings.Contains(out, "server ::1:") {
		t.Error("an unbracketed IPv6 literal in the upstream")
	}
}

func TestNginxChunkSizeScalesTheBodyLimit(t *testing.T) {
	// chunk_size_kb counts 1000-byte kilobytes while nginx counts 1024-byte k,
	// so the limit is chunk*1000 + headroom*1024 bytes rounded up to a whole k.
	// Both directions are asserted: the limit must cover chunk+headroom, and it
	// must be the smallest nginx value that does, so a request of exactly one
	// chunk is never rejected and no slack is wasted.
	for _, tc := range []struct {
		chunk int
		want  string
	}{
		{16, "144k"},
		{256, "378k"},
		{900, "1007k"},
	} {
		out := nginxOutput(t, "-chunk-size-kb", strconv.Itoa(tc.chunk))
		if !strings.Contains(out, "client_max_body_size "+tc.want+";") {
			t.Errorf("chunk %d did not produce %s:\n%s", tc.chunk, tc.want, out)
		}
		gotKB, err := strconv.Atoi(strings.TrimSuffix(tc.want, "k"))
		if err != nil {
			t.Fatalf("unparseable expectation %q", tc.want)
		}
		need := tc.chunk*1000 + 128*1024
		if gotKB*1024 < need {
			t.Errorf("chunk %d: %s is %d bytes, below chunk+headroom %d", tc.chunk, tc.want, gotKB*1024, need)
		}
		if (gotKB-1)*1024 >= need {
			t.Errorf("chunk %d: %s is larger than the %d bytes required", tc.chunk, tc.want, need)
		}
	}
}

func TestNginxServerBlock(t *testing.T) {
	out := nginxOutput(t, "-server-block", "-domain", "tunnel.example.net", "-path", "/xhttp", "-tls", "-http2", "-token-header", "X-My-Token")
	mustContain := func(s string) {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q\n%s", s, out)
		}
	}
	mustContain("server {")
	mustContain("listen 443 ssl http2;")
	mustContain("server_name tunnel.example.net;")
	mustContain("ssl_certificate /etc/nginx/ssl/fullchain.pem;")
	mustContain("ssl_certificate_key /etc/nginx/ssl/privkey.pem;")
	mustContain("ssl_protocols TLSv1.2 TLSv1.3;")
	mustContain("ssl_session_cache shared:xhttptunnel:10m;")
	mustContain("    location /xhttp {")
	mustContain("        proxy_pass http://xhttptunnel_backend;")
	mustContain("        proxy_set_header X-My-Token $http_x_my_token;")
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Errorf("the server block is not closed:\n%s", out)
	}
}

func TestNginxPlainHTTPFrontend(t *testing.T) {
	out := nginxOutput(t, "-server-block")
	if !strings.Contains(out, "listen 80;") {
		t.Errorf("the plain frontend is missing listen 80:\n%s", out)
	}
	if strings.Contains(out, "ssl") {
		t.Errorf("the plain frontend mentions ssl:\n%s", out)
	}
}

func TestNginxExplicitScheme(t *testing.T) {
	out := nginxOutput(t, "-backend", "origin.local:8443", "-scheme", "http")
	if !strings.Contains(out, "proxy_pass http://xhttptunnel_backend;") {
		t.Errorf("an explicit -scheme http was ignored:\n%s", out)
	}
	out = nginxOutput(t, "-backend", "127.0.0.1:8443", "-scheme", "https")
	if !strings.Contains(out, "proxy_pass https://xhttptunnel_backend;") {
		t.Errorf("an explicit -scheme https was ignored:\n%s", out)
	}
}

func TestNginxInputValidation(t *testing.T) {
	for _, args := range [][]string{
		{"-path", "stream"},
		{"-backend", "127.0.0.1"},
		{"-backend", "http://127.0.0.1:8443"},
		{"-chunk-size-kb", "4"},
		{"-chunk-size-kb", "1200"},
		{"-body-headroom-kb", "-1"},
		{"-upstream-name", "bad name"},
		{"-tls"},
		{"-scheme", "ftp", "-backend", "127.0.0.1:8443"},
	} {
		cmd := flag.NewFlagSet("t", flag.ContinueOnError)
		cmd.SetOutput(io.Discard)
		opts, err := nginxOptionsFromFlags(cmd, args)
		if err == nil {
			_, err = opts.render()
		}
		if err == nil {
			t.Errorf("nginx accepted invalid args %v", args)
		}
	}
}

func TestAutoBackendScheme(t *testing.T) {
	for _, tc := range []struct {
		backend string
		want    string
	}{
		{"127.0.0.1:8443", "http"},
		{"[::1]:8443", "http"},
		{"10.0.0.5:8443", "http"},
		{"localhost:8443", "http"},
		{"127.0.0.1:443", "https"},
		{"origin.example.com:8443", "https"},
		{"origin.example.com:443", "https"},
		{"localhost:443", "https"},
	} {
		if got := autoBackendScheme(tc.backend); got != tc.want {
			t.Errorf("autoBackendScheme(%q) = %q, want %q", tc.backend, got, tc.want)
		}
	}
}

func TestHostBracketed(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"127.0.0.1:8443", "127.0.0.1:8443"},
		{"[::1]:8443", "[::1]:8443"},
		{"::1:8443", "[::1]:8443"},
		{"db.example:22", "db.example:22"},
		{":8443", ":8443"},
		{"not-an-address", "not-an-address"},
	} {
		if got := hostBracketed(tc.in); got != tc.want {
			t.Errorf("hostBracketed(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHttpArg(t *testing.T) {
	if got := httpArg("X-Auth-Token"); got != "x_auth_token" {
		t.Errorf("httpArg = %q", got)
	}
	if got := httpArg("X-My-Token"); got != "x_my_token" {
		t.Errorf("httpArg = %q", got)
	}
}

func TestSplitAddr(t *testing.T) {
	for _, tc := range []struct {
		in, scheme, host string
		port             int
		ok               bool
	}{
		{":8443", "", "", 8443, true},
		{"127.0.0.1:8443", "", "127.0.0.1", 8443, true},
		{"[::1]:8443", "", "::1", 8443, true},
		{"tcp://127.0.0.1:8443", "tcp", "127.0.0.1", 8443, true},
		{"tcp+udp://:8443", "tcp+udp", "", 8443, true},
		{"udp://10.0.0.1:53", "udp", "10.0.0.1", 53, true},
		{"8443", "", "", 0, false},
		{":8443extra", "", "", 0, false},
		{"[::1", "", "", 0, false},
	} {
		scheme, host, port, ok := splitAddr(tc.in)
		if scheme != tc.scheme || host != tc.host || port != tc.port || ok != tc.ok {
			t.Errorf("splitAddr(%q) = %q %q %d %v, want %q %q %d %v",
				tc.in, scheme, host, port, ok, tc.scheme, tc.host, tc.port, tc.ok)
		}
	}
}

func TestHostIllegal(t *testing.T) {
	for _, tc := range []struct {
		host string
		bad  bool
	}{
		{"", true},
		{"localhost", false},
		{"db.example.com", false},
		{"::1", false},
		{"127.0.0.1", false},
		{"bad host", true},
		{"has/slash", true},
		{"a:b", true},
		{"a@b", true},
		{"under_score", false},
	} {
		if got := hostIllegal(tc.host); got != tc.bad {
			t.Errorf("hostIllegal(%q) = %v, want %v", tc.host, got, tc.bad)
		}
	}
	if !hostIllegal(strings.Repeat("a", 254)) {
		t.Error("a 254-character name must be rejected")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	want := []byte(`{"psk":"s"}`)
	if err := writeFileAtomic(path, want, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows chmod maps only to the read-only attribute, which os.FileMode
	// does not expose, so the bit mask is only asserted on Unix.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %o, want 0600", info.Mode().Perm())
	}

	if err := writeFileAtomic(path, []byte(`{"psk":"t"}`), 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if got, _ = os.ReadFile(path); string(got) != `{"psk":"t"}` {
		t.Errorf("the overwrite did not land: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".gen-") {
			t.Errorf("leftover temp entry %q", e.Name())
		}
	}
}

func TestWriteFileAtomicFailureKeepsTheOldFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	if err := writeFileAtomic(target, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Writing into a directory that does not exist must fail without touching
	// the pre-existing target.
	if err := writeFileAtomic(filepath.Join(dir, "no", "such", "config.json"), []byte("{}"), 0o600); err == nil {
		t.Error("expected an error writing into a missing directory")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != `{"a":1}` {
		t.Errorf("the pre-existing file was disturbed: %q %v", got, err)
	}
}

func TestLinuxDir(t *testing.T) {
	// The unit is consumed on Linux, so the directory must come out with forward
	// slashes no matter which OS generated it.
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"/etc/xhttptunnel/config.server.json", "/etc/xhttptunnel"},
		{`/etc/x http/conf "my".json`, "/etc/x http"},
		{`C:\xhttptunnel\config.json`, "C:/xhttptunnel"},
	} {
		if got := linuxDir(tc.in); got != tc.want {
			t.Errorf("linuxDir(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestChangedFlags(t *testing.T) {
	cmd := flag.NewFlagSet("t", flag.ContinueOnError)
	cmd.SetOutput(io.Discard)
	cmd.String("psk", "", "")
	cmd.String("listen", "", "")
	if err := cmd.Parse([]string{"-psk", ""}); err != nil {
		t.Fatal(err)
	}
	changed := changedFlags(cmd)
	if !changed["psk"] {
		t.Error("an explicit -psk \"\" must register as changed, or open mode is undetectable")
	}
	if changed["listen"] {
		t.Error("an unset flag registered as changed")
	}
}

func TestGenSystemdConfigPathDefault(t *testing.T) {
	// The unit must point at install.sh's config.<mode>.json convention so the
	// two entry points stay consistent.
	unit := renderSystemdUnit(unitSystemdSpec{
		Mode: "client", BinPath: "/b", ConfigPath: "/etc/xhttptunnel/config.client.json",
		User: "root", Hardening: true, UnitName: "xhttptunnel",
	})
	if !strings.Contains(unit, `"-c" "/etc/xhttptunnel/config.client.json"`) {
		t.Errorf("client unit does not reference the install.sh config path:\n%s", unit)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
