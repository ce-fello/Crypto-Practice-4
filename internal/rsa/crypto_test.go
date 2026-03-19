package rsa

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptBinaryData(t *testing.T) {
	key, err := GenerateKey(128)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	plaintext := []byte{0x00, 0x10, 0x20, 0x00, 0xff, 0x01, 0x02, 0x03}
	ciphertext, err := Encrypt(&key.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted payload mismatch: got %x want %x", decrypted, plaintext)
	}
}

func TestKeyJSONRoundTrip(t *testing.T) {
	key, err := GenerateKey(128)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	dir := t.TempDir()
	publicPath := filepath.Join(dir, "public.json")
	privatePath := filepath.Join(dir, "private.json")

	if err := WritePublicKey(publicPath, &key.PublicKey); err != nil {
		t.Fatalf("WritePublicKey failed: %v", err)
	}
	if err := WritePrivateKey(privatePath, key); err != nil {
		t.Fatalf("WritePrivateKey failed: %v", err)
	}

	publicKey, err := ReadPublicKey(publicPath)
	if err != nil {
		t.Fatalf("ReadPublicKey failed: %v", err)
	}
	privateKey, err := ReadPrivateKey(privatePath)
	if err != nil {
		t.Fatalf("ReadPrivateKey failed: %v", err)
	}

	if publicKey.N.Cmp(key.N) != 0 || publicKey.E.Cmp(key.E) != 0 {
		t.Fatalf("public key round trip mismatch")
	}
	if privateKey.D.Cmp(key.D) != 0 || privateKey.P.Cmp(key.P) != 0 || privateKey.Q.Cmp(key.Q) != 0 {
		t.Fatalf("private key round trip mismatch")
	}
}
