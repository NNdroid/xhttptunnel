package tunnel

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCertFingerprintRoundTrip proves that the pin gen-uri derives from a
// certificate file is the value the client's VerifyPeerCertificate callback
// compares against: the pin must pass for the very certificate it was hashed
// from and fail for anything else, otherwise a shared URI would pin nothing.
func TestCertFingerprintRoundTrip(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := GenerateSelfSignedCert(certFile, keyFile, "localhost"); err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	defer os.Remove(keyFile)

	pin, err := CertFingerprint(certFile)
	if err != nil {
		t.Fatalf("CertFingerprint: %v", err)
	}
	// SHA-256 is 32 bytes: 64 hex chars plus 31 separating colons.
	if strings.Count(pin, ":") != 31 || len(pin) != 95 {
		t.Fatalf("pin %q is not 32 bytes of colon-separated hex", pin)
	}

	der, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(der)
	if block == nil {
		t.Fatal("the generated certificate has no PEM block")
	}

	if err := verifyFingerprint(pin)([][]byte{block.Bytes}, nil); err != nil {
		t.Fatalf("a freshly derived pin must verify its own certificate: %v", err)
	}
	wrong := strings.Repeat("00:", 31) + "00"
	if err := verifyFingerprint(wrong)([][]byte{block.Bytes}, nil); err == nil {
		t.Fatal("a wrong pin was accepted")
	}
}

// TestCertFingerprintRejectsBadInput covers the failures an operator actually
// hits: a missing file and a file that has no PEM block.
func TestCertFingerprintRejectsBadInput(t *testing.T) {
	if _, err := CertFingerprint("/no/such/cert.pem"); err == nil {
		t.Fatal("a missing certificate file was accepted")
	}

	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := CertFingerprint(plain); err == nil {
		t.Fatal("a file without a PEM block was accepted")
	}
}
