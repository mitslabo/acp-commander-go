package acp

import (
	"encoding/hex"
	"testing"
)

func TestEncryptACPPasswordKnownVector(t *testing.T) {
	key := []byte{0x6A, 0xE2, 0xAD, 0x78}
	out, err := EncryptACPPassword("ap_servd", key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := hex.EncodeToString(out)
	want := "19a4f79baf7bc4dd"
	if got != want {
		t.Fatalf("encrypted bytes mismatch: got %s want %s", got, want)
	}
}

func TestEncryptACPPasswordLengthLimit(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04}
	_, err := EncryptACPPassword("1234567890123456789012345", key)
	if err == nil {
		t.Fatal("expected error for password length > 24")
	}
}
