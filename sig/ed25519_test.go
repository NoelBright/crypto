package sig

import (
	"encoding/hex"
	"testing"
)

func TestGenKeys(t *testing.T) {
	kp, err := NewED25519()
	if err != nil {
		t.Errorf("TestGenKey: NewED25519 error: %v\n", err)
	}
	pk := kp.PrivateKey().PublicKey()
	if !pk.EqualTo(kp.PublicKey()) {
		t.Errorf("TestGenKey: Get PublicKey error: %v\n", err)
	}
}

func TestSignVerify(t *testing.T) {
	msg := "77e74f1786b1f97c3b14100325201cc890906d0164d001b9210d4d28e217198a"
	kp, err := NewED25519()
	if err != nil {
		t.Errorf("TestSign: NewED25519 error: %v\n", err)
	}

	M, _ := hex.DecodeString(msg)
	RS, err := kp.PrivateKey().Sign(M)
	if err != nil {
		t.Errorf("TestSign: Sign error, %v\n", err)
	}

	if err := kp.PublicKey().Verify(M, RS); err != nil {
		t.Errorf("TestSign: verify error,%v\n", err)
	}

	M[0] = 0xFF
	if err := kp.PublicKey().Verify(M, RS); err == nil {
		t.Errorf("TestSign: verify error,%v\n", err)
	}
}

func TestED25519Compress(t *testing.T) {
	kp, err := NewED25519()
	if err != nil {
		t.Errorf("TestCompress: NewED25519 error: %v\n", err)
	}

	compressedX, err := kp.pk.(*ED25519PubKey).Compress(true)
	if err != nil {
		t.Errorf("TestCompress: Compress error: %v\n", err)
	}

	var deCompressX ED25519PubKey
	if err = deCompressX.DeCompress(compressedX); err != nil {
		t.Errorf("TestCompress: DeCompress error: %v\n", err)
	}

	if !deCompressX.EqualTo(kp.pk) {
		t.Errorf("TestCompress: EqualTo error: %v\n", err)
	}

}
