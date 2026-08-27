package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// verifyFingerprint 验证服务器证书指纹防 MITM
func verifyFingerprint(expectedHex string) func([][]byte, [][]*x509.Certificate) error {
	if expectedHex == "" {
		return nil
	}
	expectedHex = strings.ReplaceAll(expectedHex, ":", "")
	expectedHex = strings.ReplaceAll(expectedHex, " ", "")
	expectedBytes, err := hex.DecodeString(expectedHex)
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if err != nil {
			return fmt.Errorf("invalid expected fingerprint format: %v", err)
		}
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificates presented")
		}
		hash := sha256.Sum256(rawCerts[0])
		if !bytes.Equal(hash[:], expectedBytes) {
			return fmt.Errorf("certificate fingerprint mismatch:\nGot: %x\nExp: %x", hash, expectedBytes)
		}
		return nil
	}
}

// generateSelfSignedCert 生成有效期为 10 年的高仿真自签名证书并保存
func generateSelfSignedCert(certPath, keyPath, commonName string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	if commonName == "" {
		commonName = "localhost"
	}

	// Use a neutral SAN. Do NOT impersonate third-party domains (e.g. amazonaws.com)
	// — that only invites phishing / MITM confusion; SNI disguise is handled separately
	// via configuration, not the certificate subject.
	dnsNames := []string{commonName, "*." + commonName}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"Washington"},
			Locality:           []string{"Seattle"},
			Organization:       []string{"Amazon.com, Inc."},
			OrganizationalUnit: []string{"Amazon Web Services", "Server CA 1B"},
			CommonName:         commonName,
		},
		Issuer: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Amazon"},
			OrganizationalUnit: []string{"Server CA 1B"},
			CommonName:         "Amazon RSA 2048 M02",
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 390),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}

	return nil
}
