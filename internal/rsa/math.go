package rsa

import "math/big"

func ExtendedGCD(a, b *big.Int) (gcd, x, y *big.Int) {
	oldR := new(big.Int).Set(a)
	r := new(big.Int).Set(b)
	oldS := big.NewInt(1)
	s := big.NewInt(0)
	oldT := big.NewInt(0)
	t := big.NewInt(1)
	zero := big.NewInt(0)

	for r.Cmp(zero) != 0 {
		q := new(big.Int).Div(new(big.Int).Set(oldR), r)

		nextR := new(big.Int).Sub(oldR, new(big.Int).Mul(q, r))
		oldR, r = r, nextR

		nextS := new(big.Int).Sub(oldS, new(big.Int).Mul(q, s))
		oldS, s = s, nextS

		nextT := new(big.Int).Sub(oldT, new(big.Int).Mul(q, t))
		oldT, t = t, nextT
	}

	return oldR, oldS, oldT
}

func ModInverse(a, modulus *big.Int) (*big.Int, error) {
	gcd, x, _ := ExtendedGCD(a, modulus)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, ErrInvalidPrivateKey
	}

	result := new(big.Int).Mod(x, modulus)
	if result.Sign() < 0 {
		result.Add(result, modulus)
	}
	return result, nil
}

func ModExp(base, exponent, modulus *big.Int) *big.Int {
	if modulus.Sign() == 0 {
		return big.NewInt(0)
	}

	result := big.NewInt(1)
	baseValue := new(big.Int).Mod(new(big.Int).Set(base), modulus)

	for i := exponent.BitLen() - 1; i >= 0; i-- {
		result.Mul(result, result)
		result.Mod(result, modulus)

		if exponent.Bit(i) == 1 {
			result.Mul(result, baseValue)
			result.Mod(result, modulus)
		}
	}

	return result
}

func leftPad(input []byte, size int) ([]byte, error) {
	if len(input) > size {
		return nil, ErrInvalidCiphertext
	}
	output := make([]byte, size)
	copy(output[size-len(input):], input)
	return output, nil
}
