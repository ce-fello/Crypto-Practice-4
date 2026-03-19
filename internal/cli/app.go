package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"

	"crypto-practice-4/internal/attack"
	rsaimpl "crypto-practice-4/internal/rsa"
)

const usage = `Usage:
  rsa-cli keygen --bits <size> --public <path> --private <path>
  rsa-cli encrypt --in <path> --out <path> --public <path>
  rsa-cli decrypt --in <path> --out <path> --private <path>
  rsa-cli attack factor --public <path> [--cipher <path> --out <path>]
  rsa-cli attack factor --n <decimal> --e <decimal> [--cipher <path> --out <path>]
`

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 1
	}

	var err error
	switch args[0] {
	case "keygen":
		err = runKeygen(args[1:], stdout)
	case "encrypt":
		err = runEncrypt(args[1:])
	case "decrypt":
		err = runDecrypt(args[1:])
	case "attack":
		err = runAttack(args[1:], stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}

	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func runKeygen(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	bits := fs.Int("bits", 2048, "RSA modulus size in bits")
	publicPath := fs.String("public", "public_key.json", "path to the public key file")
	privatePath := fs.String("private", "private_key.json", "path to the private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	key, err := rsaimpl.GenerateKey(*bits)
	if err != nil {
		return err
	}
	if err := rsaimpl.WritePublicKey(*publicPath, &key.PublicKey); err != nil {
		return err
	}
	if err := rsaimpl.WritePrivateKey(*privatePath, key); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "generated RSA key pair (%d bits)\n", key.N.BitLen())
	fmt.Fprintf(stdout, "public key: %s\n", *publicPath)
	fmt.Fprintf(stdout, "private key: %s\n", *privatePath)
	return nil
}

func runEncrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inputPath := fs.String("in", "", "path to plaintext file")
	outputPath := fs.String("out", "", "path to ciphertext file")
	publicPath := fs.String("public", "", "path to public key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *outputPath == "" || *publicPath == "" {
		return errors.New("encrypt requires --in, --out and --public")
	}

	key, err := rsaimpl.ReadPublicKey(*publicPath)
	if err != nil {
		return err
	}
	plaintext, err := os.ReadFile(*inputPath)
	if err != nil {
		return err
	}
	ciphertext, err := rsaimpl.Encrypt(key, plaintext)
	if err != nil {
		return err
	}
	return os.WriteFile(*outputPath, ciphertext, 0o600)
}

func runDecrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inputPath := fs.String("in", "", "path to ciphertext file")
	outputPath := fs.String("out", "", "path to plaintext output file")
	privatePath := fs.String("private", "", "path to private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *outputPath == "" || *privatePath == "" {
		return errors.New("decrypt requires --in, --out and --private")
	}

	key, err := rsaimpl.ReadPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	ciphertext, err := os.ReadFile(*inputPath)
	if err != nil {
		return err
	}
	plaintext, err := rsaimpl.Decrypt(key, ciphertext)
	if err != nil {
		return err
	}
	return os.WriteFile(*outputPath, plaintext, 0o600)
}

func runAttack(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("attack requires a subcommand")
	}

	switch args[0] {
	case "factor":
		return runFactorAttack(args[1:], stdout)
	default:
		return fmt.Errorf("unknown attack %q", args[0])
	}
}

func runFactorAttack(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("factor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	publicPath := fs.String("public", "", "path to public key file")
	nValue := fs.String("n", "", "RSA modulus in decimal form")
	eValue := fs.String("e", "", "RSA public exponent in decimal form")
	cipherPath := fs.String("cipher", "", "optional ciphertext to decrypt after recovering the private key")
	outputPath := fs.String("out", "", "optional path for decrypted data")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pub, err := loadPublicKey(*publicPath, *nValue, *eValue)
	if err != nil {
		return err
	}
	priv, err := attack.RecoverPrivateKey(pub)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "recovered factors:\n")
	fmt.Fprintf(stdout, "p=%s\n", priv.P.String())
	fmt.Fprintf(stdout, "q=%s\n", priv.Q.String())
	fmt.Fprintf(stdout, "d=%s\n", priv.D.String())

	if *cipherPath == "" && *outputPath == "" {
		return nil
	}
	if *cipherPath == "" || *outputPath == "" {
		return errors.New("attack decryption requires both --cipher and --out")
	}

	ciphertext, err := os.ReadFile(*cipherPath)
	if err != nil {
		return err
	}
	plaintext, err := rsaimpl.Decrypt(priv, ciphertext)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outputPath, plaintext, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "decrypted payload written to %s\n", *outputPath)
	return nil
}

func loadPublicKey(publicPath, nValue, eValue string) (*rsaimpl.PublicKey, error) {
	switch {
	case publicPath != "" && (nValue != "" || eValue != ""):
		return nil, errors.New("use either --public or --n/--e")
	case publicPath != "":
		return rsaimpl.ReadPublicKey(publicPath)
	case nValue != "" && eValue != "":
		n, ok := new(big.Int).SetString(nValue, 10)
		if !ok {
			return nil, errors.New("invalid decimal modulus")
		}
		e, ok := new(big.Int).SetString(eValue, 10)
		if !ok {
			return nil, errors.New("invalid decimal exponent")
		}
		pub := &rsaimpl.PublicKey{N: n, E: e}
		return pub, pub.Validate()
	default:
		return nil, errors.New("factor attack requires either --public or --n/--e")
	}
}
