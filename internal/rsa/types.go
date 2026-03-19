package rsa

import (
	"errors"
	"math/big"
)

var (
	ErrInvalidKeySize    = errors.New("key size must be at least 32 bits")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

type PublicKey struct {
	N *big.Int
	E *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
	P *big.Int
	Q *big.Int
}

func (k *PublicKey) ModulusBytes() int {
	if k == nil || k.N == nil {
		return 0
	}
	return (k.N.BitLen() + 7) / 8
}

func (k *PublicKey) PlaintextBlockSize() int {
	modulusBytes := k.ModulusBytes()
	if modulusBytes < 2 {
		return 0
	}
	return modulusBytes - 1
}

func (k *PublicKey) Validate() error {
	if k == nil || k.N == nil || k.E == nil {
		return ErrInvalidPublicKey
	}
	if k.N.Sign() <= 0 || k.E.Sign() <= 0 {
		return ErrInvalidPublicKey
	}
	if k.PlaintextBlockSize() < 1 {
		return ErrInvalidPublicKey
	}
	return nil
}

func (k *PrivateKey) Validate() error {
	if k == nil || k.D == nil || k.P == nil || k.Q == nil {
		return ErrInvalidPrivateKey
	}
	if err := k.PublicKey.Validate(); err != nil {
		return ErrInvalidPrivateKey
	}
	if k.D.Sign() <= 0 || k.P.Sign() <= 0 || k.Q.Sign() <= 0 {
		return ErrInvalidPrivateKey
	}
	if new(big.Int).Mul(k.P, k.Q).Cmp(k.N) != 0 {
		return ErrInvalidPrivateKey
	}
	return nil
}
