package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rsaimpl "crypto-practice-4/internal/rsa"
)

func TestRunKeygenEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "public.json")
	privatePath := filepath.Join(dir, "private.json")
	inputPath := filepath.Join(dir, "plain.bin")
	cipherPath := filepath.Join(dir, "cipher.bin")
	outputPath := filepath.Join(dir, "decrypted.bin")

	input := []byte{0x00, 0x01, 0x02, 0xff, 0x10, 0x00}
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	if code := Run([]string{"keygen", "--bits", "128", "--public", publicPath, "--private", privatePath}, stdout, stderr); code != 0 {
		t.Fatalf("keygen failed: %s", stderr.String())
	}
	if code := Run([]string{"encrypt", "--in", inputPath, "--out", cipherPath, "--public", publicPath}, stdout, stderr); code != 0 {
		t.Fatalf("encrypt failed: %s", stderr.String())
	}
	if code := Run([]string{"decrypt", "--in", cipherPath, "--out", outputPath, "--private", privatePath}, stdout, stderr); code != 0 {
		t.Fatalf("decrypt failed: %s", stderr.String())
	}

	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(output, input) {
		t.Fatalf("round trip mismatch: got %x want %x", output, input)
	}
}

func TestRunDecryptRejectsCorruptedCiphertext(t *testing.T) {
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "public.json")
	privatePath := filepath.Join(dir, "private.json")
	inputPath := filepath.Join(dir, "plain.bin")
	cipherPath := filepath.Join(dir, "cipher.bin")

	key, err := rsaimpl.GenerateKey(128)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if err := rsaimpl.WritePublicKey(publicPath, &key.PublicKey); err != nil {
		t.Fatalf("WritePublicKey failed: %v", err)
	}
	if err := rsaimpl.WritePrivateKey(privatePath, key); err != nil {
		t.Fatalf("WritePrivateKey failed: %v", err)
	}
	if err := os.WriteFile(inputPath, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	if code := Run([]string{"encrypt", "--in", inputPath, "--out", cipherPath, "--public", publicPath}, stdout, stderr); code != 0 {
		t.Fatalf("encrypt failed: %s", stderr.String())
	}

	ciphertext, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	ciphertext = ciphertext[:len(ciphertext)-1]
	if err := os.WriteFile(cipherPath, ciphertext, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if code := Run([]string{"decrypt", "--in", cipherPath, "--out", filepath.Join(dir, "out.bin"), "--private", privatePath}, stdout, stderr); code == 0 {
		t.Fatalf("decrypt unexpectedly succeeded")
	}
}

func TestRunFactorAttack(t *testing.T) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	code := Run([]string{"attack", "factor", "--n", "3233", "--e", "17"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("attack failed: %s", stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "p=53") || !strings.Contains(output, "q=61") {
		t.Fatalf("unexpected attack output: %s", output)
	}
	if !strings.Contains(output, "d=2753") {
		t.Fatalf("missing recovered private exponent: %s", output)
	}
}
