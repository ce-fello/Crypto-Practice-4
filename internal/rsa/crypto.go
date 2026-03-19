package rsa

import (
	"encoding/binary"
	"math/big"
)

const lengthHeaderSize = 8

func Encrypt(pub *PublicKey, plaintext []byte) ([]byte, error) {
	if err := pub.Validate(); err != nil {
		return nil, err
	}

	modulusBytes := pub.ModulusBytes()
	blockSize := pub.PlaintextBlockSize()
	ciphertext := make([]byte, lengthHeaderSize)
	binary.BigEndian.PutUint64(ciphertext[:lengthHeaderSize], uint64(len(plaintext)))

	if len(plaintext) == 0 {
		return ciphertext, nil
	}

	for offset := 0; offset < len(plaintext); offset += blockSize {
		end := minInt(offset+blockSize, len(plaintext))
		block := plaintext[offset:end]
		message := new(big.Int).SetBytes(block)
		if message.Cmp(pub.N) >= 0 {
			return nil, ErrInvalidPublicKey
		}

		encryptedBlock := ModExp(message, pub.E, pub.N)
		encodedBlock, err := leftPad(encryptedBlock.Bytes(), modulusBytes)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, encodedBlock...)
	}

	return ciphertext, nil
}

func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	if err := priv.Validate(); err != nil {
		return nil, err
	}
	if len(ciphertext) < lengthHeaderSize {
		return nil, ErrInvalidCiphertext
	}

	plaintextLen := binary.BigEndian.Uint64(ciphertext[:lengthHeaderSize])
	modulusBytes := priv.ModulusBytes()
	blockSize := priv.PlaintextBlockSize()
	encryptedPayload := ciphertext[lengthHeaderSize:]
	maxInt := uint64(^uint(0) >> 1)

	if plaintextLen == 0 {
		if len(encryptedPayload) != 0 {
			return nil, ErrInvalidCiphertext
		}
		return []byte{}, nil
	}
	if plaintextLen > maxInt {
		return nil, ErrInvalidCiphertext
	}

	blockCount := (plaintextLen + uint64(blockSize) - 1) / uint64(blockSize)
	expectedSize := blockCount * uint64(modulusBytes)
	if expectedSize > maxInt || expectedSize != uint64(len(encryptedPayload)) {
		return nil, ErrInvalidCiphertext
	}

	plaintext := make([]byte, 0, int(plaintextLen))
	for index := 0; index < int(blockCount); index++ {
		offset := index * modulusBytes
		block := encryptedPayload[offset : offset+modulusBytes]
		encryptedValue := new(big.Int).SetBytes(block)
		if encryptedValue.Cmp(priv.N) >= 0 {
			return nil, ErrInvalidCiphertext
		}

		decryptedValue := ModExp(encryptedValue, priv.D, priv.N)
		targetSize := blockSize
		if uint64(index) == blockCount-1 {
			remainder := int(plaintextLen % uint64(blockSize))
			if remainder != 0 {
				targetSize = remainder
			}
		}

		decodedBlock, err := leftPad(decryptedValue.Bytes(), targetSize)
		if err != nil {
			return nil, ErrInvalidCiphertext
		}
		plaintext = append(plaintext, decodedBlock...)
	}

	if len(plaintext) != int(plaintextLen) {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
