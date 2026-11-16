package main

import "fmt"

// version is set at build time with:
//
//	-ldflags "-X main.version=v0.1.0"
//
// It stays "dev" for local builds.
var version = "dev"

func main() {
	fmt.Println(version)
}
