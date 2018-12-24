package sig

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/ed25519"
)

const (
	ED25519_PUBLICKEYSIZE  = 32
	ED25519_PRIVATEKEYSIZE = 64
	ED25519_SIGNATURESIZE  = 64
)

func NewED25519() (*Keypair, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("NewEd25519: Generate key pair error")
	}

	pk := &ED25519PubKey{
		PK: pubKey[:],
	}
	sk := &ED25519PrivKey{
		SK: privKey[:],
	}

	return &Keypair{
		pk: pk,
		sk: sk,
	}, nil

}

func (pk *ED25519PubKey) Verify(data []byte, signature []byte) error {
	//pubKey := [32]byte{}
	//sig := [64]byte{}
	//copy(pubKey[:], pk.PK[0:32])
	//copy(sig[:], signature[0:64])
	if !ed25519.Verify(pk.PK, data, signature) {
		return errors.New("ED25519PubKey.Verify: failed.")
	}

	return nil
}

func (pk *ED25519PubKey) EqualTo(that PubKey) bool {
	return pk.Equal(that)
}

func (sk *ED25519PrivKey) Sign(data []byte) ([]byte, error) {
	//privKey := [64]byte{}
	//copy(privKey[:], sk.SK[0:64])
	return ed25519.Sign(sk.SK, data), nil
}

func (sk *ED25519PrivKey) PublicKey() PubKey {
	return &ED25519PubKey{
		PK: sk.SK[32:],
	}
}
