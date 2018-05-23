package main

import (
	"fmt"
	"os"

	"github.com/ericchiang/kube-oidc/cmd/kube-oidc-login/app"
)

func main() {
	if err := app.New().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
