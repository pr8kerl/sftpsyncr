package main

import (
	"github.com/mitchellh/cli"
	"log"
	"os"
)

var (
	config  Config
	profile string
	debug   bool = false
)

func init() {
	log.SetFlags(log.LstdFlags)
	// log.SetPrefix(basename + ": ")
}

func main() {

	c := cli.NewCLI("sftpsyncr", "0.0.1")
	c.Args = os.Args[1:]

	c.Commands = map[string]cli.CommandFactory{
		"push": pushCmdFactory,
		//                "pull": pullCmdFactory(),
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(os.Stderr, err.Error())
	}

	os.Exit(exitStatus)
}
