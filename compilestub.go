//go:build compilestub

package main

import _ "github.com/mattn/go-sqlite3"

// this exists to pre-compile the sqlite3 module, so that the docker build can
// cache the result.

func main() {}
