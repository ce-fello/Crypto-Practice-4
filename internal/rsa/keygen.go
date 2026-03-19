package rsa

import (
	"crypto/rand"
	"math/big"
)

func GenerateKey(bits int) (*PrivateKey, error) {
	if bits < 32 {
		return nil, ErrInvalidKeySize
	}

	pBits := bits / 2
	qBits := bits - pBits
	defaultE := big.NewInt(65537)
	one := big.NewInt(1)

	for {
		p, err := rand.Prime(rand.Reader, pBits)
		if err != nil {
			return nil, err
		}
		q, err := rand.Prime(rand.Reader, qBits)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(
			new(big.Int).Sub(new(big.Int).Set(p), one),
			new(big.Int).Sub(new(big.Int).Set(q), one),
		)

		e := new(big.Int).Set(defaultE)
		if new(big.Int).GCD(nil, nil, e, phi).Cmp(one) != 0 {
			e = big.NewInt(3)
			for new(big.Int).GCD(nil, nil, e, phi).Cmp(one) != 0 {
				e.Add(e, big.NewInt(2))
			}
		}

		d, err := ModInverse(e, phi)
		if err != nil {
			continue
		}

		key := &PrivateKey{
			PublicKey: PublicKey{
				N: n,
				E: e,
			},
			D: d,
			P: p,
			Q: q,
		}
		if err := key.Validate(); err != nil {
			continue
		}
		return key, nil
	}
}
