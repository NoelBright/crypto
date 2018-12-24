package sig

type PubKey interface {
	EqualTo(pk PubKey) bool
	Compress(isCommpressed bool) ([]byte, error)
	DeCompress(encodeData []byte) error
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	Verify(data []byte, signature []byte) error
}

type PrivKey interface {
	PublicKey() PubKey
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	Sign(data []byte) ([]byte, error)
}

type Keypair struct {
	pk PubKey
	sk PrivKey
}

func (kp *Keypair) PublicKey() PubKey {
	return kp.pk
}

func (kp *Keypair) PrivateKey() PrivKey {
	return kp.sk
}
