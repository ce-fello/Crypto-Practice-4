package rsa

import (
	"math/big"
	"testing"
)

func TestExtendedGCD(t *testing.T) {
	a := big.NewInt(240)
	b := big.NewInt(46)

	gcd, x, y := ExtendedGCD(a, b)
	if gcd.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("unexpected gcd: %s", gcd)
	}

	lhs := new(big.Int).Add(
		new(big.Int).Mul(a, x),
		new(big.Int).Mul(b, y),
	)
	if lhs.Cmp(gcd) != 0 {
		t.Fatalf("Bezout identity failed: got %s, want %s", lhs, gcd)
	}
}

func TestModExp(t *testing.T) {
	base := big.NewInt(4)
	exponent := big.NewInt(13)
	modulus := big.NewInt(497)

	got := ModExp(base, exponent, modulus)
	want := big.NewInt(445)
	if got.Cmp(want) != 0 {
		t.Fatalf("unexpected result: got %s want %s", got, want)
	}
}
