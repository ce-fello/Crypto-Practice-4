package main

import (
	"crypto-practice-4/internal/cli"
	"os"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
