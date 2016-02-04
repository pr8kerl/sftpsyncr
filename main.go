package main

import (
	"github.com/mitchellh/cli"
	"log"
	"os"
)

var (
	profile  string
	version  string = "sftpsyncr version 0.1."
	commit   string = "unset"
	xferverb string = "unset"
)

func main() {

	version = version + commit

	c := cli.NewCLI("sftpsyncr", version)
	c.Args = os.Args[1:]

	c.Commands = map[string]cli.CommandFactory{
		"push": pushCmdFactory,
		"pull": pullCmdFactory,
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err.Error())
	}

	os.Exit(exitStatus)
}
