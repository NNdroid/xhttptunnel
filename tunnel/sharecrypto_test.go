package tunnel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// Android ShareCryptoUtils.isEncryptedPayload detects an envelope by the presence of v, s, i, c.
func TestEnvelopeShapeMatchesAndroid(t *testing.T) {
	plain := []byte(`{"name":"t","sshAddr":"1.2.3.4:22","tunnelType":"xhttp"}`)
	uri, _, err := encryptStunURI(plain, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "stun://") {
		t.Fatalf("expected stun:// prefix, got %s", uri)
	}
	payload := strings.TrimPrefix(uri, "stun://")
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"v", "s", "i", "c"} {
		if _, ok := env[k]; !ok {
			t.Fatalf("envelope missing key %q (Android needs v,s,i,c)", k)
		}
	}
	if env["v"].(float64) != 1 {
		t.Fatalf("v should be 1, got %v", env["v"])
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte(`{"name":"BigNode","privateKey":"` + strings.Repeat("A", 5000) + `"}`)
	uri, pin, err := encryptStunURI(plain, "")
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.TrimPrefix(uri, "stun://")
	raw, _ := base64.StdEncoding.DecodeString(payload)
	var env map[string]any
	_ = json.Unmarshal(raw, &env)
	if int(env["g"].(float64)) != 1 {
		t.Fatalf("expected gzip flag g=1 for large payload, got %v", env["g"])
	}
	dec, err := decryptStunURI(uri, pin)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if dec != string(plain) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestDecryptWrongPinFails(t *testing.T) {
	uri, _, err := encryptStunURI([]byte("hello world"), "123456")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptStunURI(uri, "000000"); err == nil {
		t.Fatal("expected wrong-pin decryption to fail")
	}
}

func TestProvidedPinHonored(t *testing.T) {
	_, pin, err := encryptStunURI([]byte("x"), "654321")
	if err != nil {
		t.Fatal(err)
	}
	if pin != "654321" {
		t.Fatalf("provided PIN not honored: got %s", pin)
	}
}

// sealEnvelope builds a share payload with a caller-chosen PBKDF2 iteration
// count, optionally omitting the "it" field, so the reader's iteration handling
// can be exercised without going through encryptStunURI.
func sealEnvelope(t *testing.T, pin string, iterations int, plain string, includeIt bool) string {
	t.Helper()
	salt := bytes.Repeat([]byte{0x11}, shareSaltLen)
	iv := bytes.Repeat([]byte{0x22}, shareIvLen)
	key := pbkdf2.Key([]byte(pin), salt, iterations, shareKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	env := shareEnvelope{
		V: 1,
		S: base64.StdEncoding.EncodeToString(salt),
		I: base64.StdEncoding.EncodeToString(iv),
		C: base64.StdEncoding.EncodeToString(gcm.Seal(nil, iv, []byte(plain), nil)),
	}
	if includeIt {
		env.It = iterations
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return "stun://" + base64.StdEncoding.EncodeToString(b)
}

// TestEnvelopeCarriesIterations pins the "it" field: ShareCryptoUtils defaults
// an absent value to 10000 but writes 200000 for cloud backups, so a payload we
// emit must state its count explicitly instead of relying on that default.
func TestEnvelopeCarriesIterations(t *testing.T) {
	uri, _, err := encryptStunURI([]byte(`{"name":"t"}`), "123456")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "stun://"))
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	it, ok := env["it"].(float64)
	if !ok {
		t.Fatal(`envelope has no "it" field`)
	}
	if int(it) != shareIterations {
		t.Fatalf("it = %v, want %d", it, shareIterations)
	}
}

// TestDecryptHonorsEnvelopeIterations covers both directions of the "it" field:
// a legacy envelope without it still opens with 10000, a 200k envelope opens
// only when the field is honoured, and a payload that *lies* about its count
// fails instead of yielding garbage.
func TestDecryptHonorsEnvelopeIterations(t *testing.T) {
	const plain = `{"name":"backup-node"}`

	legacy := sealEnvelope(t, "123456", shareIterations, plain, false)
	if got, err := decryptStunURI(legacy, "123456"); err != nil || got != plain {
		t.Fatalf("legacy envelope without it: got %q err %v", got, err)
	}

	backup := sealEnvelope(t, "123456", 200_000, plain, true)
	if got, err := decryptStunURI(backup, "123456"); err != nil || got != plain {
		t.Fatalf("it=200000 envelope: got %q err %v", got, err)
	}

	lying := sealEnvelope(t, "123456", 200_000, plain, false)
	if _, err := decryptStunURI(lying, "123456"); err == nil {
		t.Fatal("a payload whose it field does not match its KDF must not decrypt")
	}
}

func TestPbkdf2MatchesRFC7914(t *testing.T) {
	out := pbkdf2.Key([]byte("passwd"), []byte("salt"), 1, 64, sha256.New)
	want, _ := hex.DecodeString("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
	if !equalBytes(out, want) {
		t.Fatalf("PBKDF2 mismatch:\n got %x\nwant %x", out, want)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
