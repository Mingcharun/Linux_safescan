package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Mingcharun/Linux_safescan/gscan-go/internal/app"
	"github.com/Mingcharun/Linux_safescan/gscan-go/internal/config"
)

func main() {
	ctx := context.Background()

	opts, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if err := app.Run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
