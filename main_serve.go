package main

import "gopkg.in/alecthomas/kingpin.v2"

type serveConfig struct {
	addr string
}

func serveCommand(app *kingpin.Application) (cmd *kingpin.CmdClause, run func() error) {
	serve := app.Command("serve", "Run the IDP as a server")

	return serve, nil
}
