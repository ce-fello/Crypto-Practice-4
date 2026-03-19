package attack

import (
	"errors"
	"fmt"
	"math/big"

	rsaimpl "crypto-practice-4/internal/rsa"
)

var ErrModulusTooLarge = errors.New("modulus is too large for the educational factorization attack")

func FactorSmallModulus(n *big.Int) (p, q *big.Int, err error) {
	if n == nil || n.Sign() <= 0 {
		return nil, nil, fmt.Errorf("invalid modulus")
	}
	if n.BitLen() > 64 {
		return nil, nil, ErrModulusTooLarge
	}

	two := big.NewInt(2)
	if new(big.Int).Mod(n, two).Sign() == 0 {
		return two, new(big.Int).Div(new(big.Int).Set(n), two), nil
	}

	limit := new(big.Int).Sqrt(n)
	divisor := big.NewInt(3)
	step := big.NewInt(2)
	zero := big.NewInt(0)

	for divisor.Cmp(limit) <= 0 {
		if new(big.Int).Mod(n, divisor).Cmp(zero) == 0 {
			return new(big.Int).Set(divisor), new(big.Int).Div(new(big.Int).Set(n), divisor), nil
		}
		divisor.Add(divisor, step)
	}

	return nil, nil, fmt.Errorf("failed to factor modulus")
}

func RecoverPrivateKey(pub *rsaimpl.PublicKey) (*rsaimpl.PrivateKey, error) {
	if err := pub.Validate(); err != nil {
		return nil, err
	}

	p, q, err := FactorSmallModulus(pub.N)
	if err != nil {
		return nil, err
	}

	one := big.NewInt(1)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(new(big.Int).Set(p), one),
		new(big.Int).Sub(new(big.Int).Set(q), one),
	)
	d, err := rsaimpl.ModInverse(pub.E, phi)
	if err != nil {
		return nil, err
	}

	return &rsaimpl.PrivateKey{
		PublicKey: rsaimpl.PublicKey{
			N: new(big.Int).Set(pub.N),
			E: new(big.Int).Set(pub.E),
		},
		D: d,
		P: p,
		Q: q,
	}, nil
}
