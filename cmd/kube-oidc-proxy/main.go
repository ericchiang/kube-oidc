package main

import (
	"fmt"
	"os"

	"github.com/ericchiang/kube-oidc/internal/app"
)

func main() {
	if err := app.NewKubeOIDCProxy().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
