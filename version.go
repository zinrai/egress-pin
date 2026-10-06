package main

import "fmt"

// Variables rather than constants: goreleaser overwrites them with -ldflags -X
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printVersion() {
	fmt.Printf("egress-pin version %s\n", version)
	fmt.Printf("commit: %s\n", commit)
	fmt.Printf("built: %s\n", date)
}
