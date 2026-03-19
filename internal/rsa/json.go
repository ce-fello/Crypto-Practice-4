package rsa

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
)

type publicKeyJSON struct {
	N string `json:"n"`
	E string `json:"e"`
}

type privateKeyJSON struct {
	N string `json:"n"`
	E string `json:"e"`
	D string `json:"d"`
	P string `json:"p"`
	Q string `json:"q"`
}

func WritePublicKey(path string, key *PublicKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	payload := publicKeyJSON{
		N: key.N.String(),
		E: key.E.String(),
	}
	return writeJSON(path, payload)
}

func WritePrivateKey(path string, key *PrivateKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	payload := privateKeyJSON{
		N: key.N.String(),
		E: key.E.String(),
		D: key.D.String(),
		P: key.P.String(),
		Q: key.Q.String(),
	}
	return writeJSON(path, payload)
}

func ReadPublicKey(path string) (*PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var payload publicKeyJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	key := &PublicKey{
		N: parseBigInt(payload.N),
		E: parseBigInt(payload.E),
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return key, nil
}

func ReadPrivateKey(path string) (*PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var payload privateKeyJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	key := &PrivateKey{
		PublicKey: PublicKey{
			N: parseBigInt(payload.N),
			E: parseBigInt(payload.E),
		},
		D: parseBigInt(payload.D),
		P: parseBigInt(payload.P),
		Q: parseBigInt(payload.Q),
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return key, nil
}

func writeJSON(path string, payload any) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func parseBigInt(value string) *big.Int {
	if value == "" {
		return nil
	}
	result, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil
	}
	return result
}

func IsKeyError(err error) bool {
	return errors.Is(err, ErrInvalidPublicKey) || errors.Is(err, ErrInvalidPrivateKey)
}
