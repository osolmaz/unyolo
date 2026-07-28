package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/osolmaz/unyolo/internal/tooling/coverage"
)

func main() {
	minimum := flag.Float64("minimum", 85, "minimum total statement coverage percentage")
	directory := flag.String("directory", ".", "Go module directory")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	total, err := coverage.Run(ctx, *directory, *minimum)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Total coverage: %.1f%%\n", total)
}
