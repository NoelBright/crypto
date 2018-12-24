package crypto

import "github.com/nknorg/crypto/sig"

type SIGALGO uint32

const (
	P256R1  SIGALGO = 1
	ED25519 SIGALGO = 2
)

var (
	sigAlgoes = make(map[SIGALGO]func() (*sig.Keypair, error), 0)
)

func (sa SIGALGO) New() (*sig.Keypair, error) {
	return sigAlgoes[sa]()
}

func init() {
	sigAlgoes[P256R1] = sig.NewP256R1
	sigAlgoes[ED25519] = sig.NewED25519
}
