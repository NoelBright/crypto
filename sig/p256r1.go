package sig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

const (
	P256R1_PRIVATEKEYLEN = 32
	P256R1_PUBLICKEYLEN  = 32
	P256R1_SIGNRLEN      = 32
	P256R1_SIGNSLEN      = 32
	P256R1_SIGNATURELEN  = 64
)

func NewP256R1() (*Keypair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("NewP256R1: Generate key pair error")
	}

	//TODO pk and sk alignment
	pk := P256R1PubKey{
		X: privateKey.PublicKey.X.Bytes(),
		Y: privateKey.PublicKey.Y.Bytes(),
	}

	sk := P256R1PrivKey{
		D: privateKey.D.Bytes(),
	}

	return &Keypair{
		pk: &pk,
		sk: &sk,
	}, nil
}

func (pk *P256R1PubKey) Verify(data []byte, signature []byte) error {
	len := len(signature)
	if len != P256R1_SIGNATURELEN {
		return fmt.Errorf("Verify: Unknown signature length: %d\n", len)
	}

	r := new(big.Int).SetBytes(signature[:len/2])
	s := new(big.Int).SetBytes(signature[len/2:])

	digest := sha256.Sum256(data)

	pub := new(ecdsa.PublicKey)
	pub.Curve = elliptic.P256()

	pub.X = new(big.Int).SetBytes(pk.X)
	pub.Y = new(big.Int).SetBytes(pk.Y)

	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("P256R1PubKey.Verify: failed.")
	}

	return nil
}

func (pk *P256R1PubKey) EqualTo(that PubKey) bool {
	return pk.Equal(that)
}

func (sk *P256R1PrivKey) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data) // TODO  new func
	privateKey := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(sk.D),
	}
	privateKey.Curve = elliptic.P256()

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("Sign: p256r1 sign error: %v\n", err)
	}

	signature := make([]byte, P256R1_SIGNATURELEN)

	copy(signature[P256R1_SIGNRLEN-len(r.Bytes()):], r.Bytes())
	copy(signature[P256R1_SIGNATURELEN-len(s.Bytes()):], s.Bytes())

	return signature, nil
}

func (sk *P256R1PrivKey) PublicKey() PubKey {
	bigX, bigY := elliptic.P256().ScalarBaseMult(sk.D)

	return &P256R1PubKey{
		X: bigX.Bytes(),
		Y: bigY.Bytes(),
	}
}

func (pk *P256R1PubKey) EncodePoint(isCommpressed bool) ([]byte, error) {
	//if X is infinity, then Y cann't be computed, so here used "||"
	if nil == pk.X || nil == pk.Y {
		infinity := make([]byte, INFINITYLEN)
		return infinity, nil
	}

	var encodedData []byte
	copy(encodedData[COMPRESSEDLEN-len(pk.X):COMPRESSEDLEN], pk.X)

	if isCommpressed {
		encodedData = make([]byte, COMPRESSEDLEN)
		if pk.Y[len(pk.Y)-1]&1 == 0 {
			encodedData[0] = COMPEVENFLAG
		} else {
			encodedData[0] = COMPODDFLAG
		}
	} else {
		encodedData = make([]byte, NOCOMPRESSEDLEN)
		copy(encodedData[NOCOMPRESSEDLEN-len(pk.Y):], pk.Y)
		encodedData[0] = NOCOMPRESSEDFLAG
	}

	return encodedData, nil
}
