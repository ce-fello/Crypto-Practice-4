# RSA Study Project

This repository contains a study implementation of the RSA public-key cryptosystem written in Go. The project was built for an academic assignment on public-key cryptography and focuses on clarity of the underlying number-theoretic algorithms rather than production security.

The application exposes a CLI with four workflows:

- `keygen` generates an RSA key pair and stores it as JSON.
- `encrypt` encrypts any file with the public key.
- `decrypt` decrypts a ciphertext file with the private key.
- `attack factor` demonstrates an educational attack against a deliberately small RSA modulus.

## Architecture

The code is split into three layers:

- `cmd/rsa-cli` contains the executable entrypoint.
- `internal/cli` parses CLI arguments, validates command combinations, and orchestrates file I/O.
- `internal/rsa` implements key generation, modular arithmetic, JSON key serialization, and RSA block encryption/decryption.
- `internal/attack` contains the small-modulus factorization attack and private-key recovery flow.

The RSA implementation uses `math/big` for arbitrary-precision arithmetic and manually implements:

- the extended Euclidean algorithm;
- modular inverse;
- fast modular exponentiation;
- RSA key generation from two random primes;
- block-based file encryption and decryption.

## Ciphertext Format

The ciphertext format is binary-safe and intentionally simple:

1. The first 8 bytes store the original plaintext length as an unsigned big-endian integer.
2. The remaining bytes are RSA-encrypted blocks of fixed size equal to the modulus size in bytes.

Plaintext blocks use size `k-1`, where `k` is the modulus size in bytes. This guarantees that every block interpreted as an integer is smaller than the RSA modulus.

## Usage

Generate a key pair:

```bash
go run ./cmd/rsa-cli keygen --bits 2048 --public public_key.json --private private_key.json
```

Encrypt a file:

```bash
go run ./cmd/rsa-cli encrypt --in message.txt --out message.enc --public public_key.json
```

Decrypt a file:

```bash
go run ./cmd/rsa-cli decrypt --in message.enc --out message.dec --private private_key.json
```

Run the educational factorization attack:

```bash
go run ./cmd/rsa-cli attack factor --n 3233 --e 17
```

Or recover the private key from a JSON public key file:

```bash
go run ./cmd/rsa-cli attack factor --public public_key.json
```

## Testing

Run all tests with:

```bash
go test ./...
```

## Report Generation

Generate the final `.docx` report based on the template from the repository root:

```bash
.venv/bin/python scripts/generate_report.py
```

The script creates `report.docx`, validates the resulting ZIP/OOXML structure, and checks that macOS `textutil` can read the generated file without errors.

## Limitations

This project is intentionally educational.

- It does not implement OAEP, PKCS#1 v1.5, or any other padding scheme.
- Ciphertext length leaks the plaintext size.
- The factorization attack is intentionally restricted to small moduli and exists only for demonstration.
- The implementation must not be used to protect real-world data.
