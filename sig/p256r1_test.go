package sig

import (
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestGenKey(t *testing.T) {
	kp, err := NewP256R1()
	if err != nil {
		t.Errorf("TestGenKey: NewP256R1 error: %v\n", err)
	}
	bigX := new(big.Int).SetBytes(kp.pk.(*P256R1PubKey).X)
	bigY := new(big.Int).SetBytes(kp.pk.(*P256R1PubKey).Y)
	if !elliptic.P256().IsOnCurve(bigX, bigY) {
		t.Errorf("TestGenKey: public key is not in curve")
	}

	pk := kp.PrivateKey().PublicKey()

	if !pk.EqualTo(kp.PublicKey()) {
		t.Errorf("TestGenKey: gen PublicKey from private key error")
	}
}

func TestSign(t *testing.T) {
	msg := "77e74f1786b1f97c3b14100325201cc890906d0164d001b9210d4d28e217198a"

	kp, err := NewP256R1()
	if err != nil {
		t.Errorf("testSign: NewP256R1 error: %v\n", err)
	}

	M, _ := hex.DecodeString(msg)
	RS, err := kp.PrivateKey().Sign(M)
	if err != nil {
		t.Errorf("TestSign: Sign error, %v\n", err)
	}

	if err := kp.PublicKey().Verify(M, RS); err != nil {
		t.Errorf("TestSign: verify error.\n")
	}

	M[1] = 0xFF
	if err := kp.PublicKey().Verify(M, RS); err == nil {
		t.Errorf("TestSign: verify error.\n")
	}
}

func TestCompress(t *testing.T) {
	kp, err := NewP256R1()
	if err != nil {
		t.Errorf("TestCompress: NewP256R1 error: %v\n", err)
	}

	compressedX, err := kp.pk.(*P256R1PubKey).Compress(true)
	if err != nil {
		t.Errorf("TestCompress: Compress error: %v\n", err)
	}

	var deCompressX P256R1PubKey
	if err = deCompressX.DeCompress(compressedX); err != nil {
		t.Errorf("TestCompress: DeCompress error: %v\n", err)
	}

	if !deCompressX.EqualTo(kp.pk) {
		t.Errorf("TestCompress: EqualTo error: %v\n", err)
	}

}
