package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/app"
	"github.com/Mingcharun/Linux_safescan/internal/config"
)

func main() {
	opts, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "argument error:", err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
	defer cancel()
	if err := app.Run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
