package main

import (
	"flag"
	"github.com/mitchellh/cli"
	"log"
	"os"
	"path/filepath"
)

type PullCommand struct {
	Ui cli.Ui
}

func pullCmdFactory() (cli.Command, error) {

	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}

	return &PullCommand{
		Ui: &cli.ColoredUi{
			Ui:          ui,
			OutputColor: cli.UiColorBlue,
		},
	}, nil
}

func (c *PullCommand) Run(args []string) int {

	// flags
	var cfgfile string
	cmdFlags := flag.NewFlagSet("pull", flag.ContinueOnError)
	cmdFlags.StringVar(&profile, "profile", "default", "sftp session profile to use")
	cmdFlags.StringVar(&cfgfile, "config", "config.ini", "config file in git config ini format")
	if err := cmdFlags.Parse(args); err != nil {
		return 1
	}
	cmdFlags.Usage = func() { c.Ui.Output(c.Help()) }

	// config
	err := InitialiseConfig(cfgfile)
	if err != nil {
		log.Fatalf("error : failed to initialise config : %s", err)
		return 1
	}

	sess, err := NewSftpSession(&config, profile)
	if err != nil {
		log.Printf("%s\n", err)
		return 1
	}
	defer sess.Close()

	// build remote file list
	err = sess.WalkRemote()
	if err != nil {
		log.Printf("unable to walk remote server: %v", err)
		return 95
	}

	// if file list connect
	if len(sess.RemoteFiles) > 0 {

		// build local file list
		filepath.Walk(config.Profile[profile].LocalDir, sess.WalkLocal)

		// for each remote file, if it isn't on local, pull
		for path := range sess.RemoteFiles {

			var lsize, rsize int64 = 0, 0
			_, lexists := sess.LocalFiles[path]

			rfile := sess.RemoteFiles[path]
			rsize = rfile.Size()

			if debug {
				log.Printf("DEBUG processing remote path : %s, %d\n", path, rsize)
			}

			if lexists {
				lsize = sess.LocalFiles[path].Size()
			}

			// ignore if it is on local
			if lexists && lsize == rsize {

				if debug {
					log.Printf("DEBUG path %s already exists on local with size %d bytes\n", path, lsize)
				}

				continue

			} else {

				// if it isn't on local and it's a different size, pull it
				// prepend the remote dir to the remote file path
				rfilepath := filepath.Join(config.Profile[profile].RemoteDir, path)
				// prepend the local dir to the local file path
				lfilepath := filepath.Join(config.Profile[profile].LocalDir, path)
				if rfile.IsDir() {
					log.Printf("pull directory %s\n", rfilepath)
					//sess.MkDirRemote(rfile)
					// test for local directory
					if _, err := os.Stat(lfilepath); err != nil {
						if os.IsNotExist(err) {
							// dir does not exist
							err = os.Mkdir(lfilepath, rfile.Mode())
							if err != nil {
								log.Printf("error creating local directory path : %s, %s\n", lfilepath, err)
							}
							if debug {
								log.Printf("DEBUG created dir %s\n", lfilepath)
							}
						}
					}
				} else {
					log.Printf("pull file %s size %d\n", rfilepath, rsize)

					err := sess.Pull(rfilepath, rsize, lfilepath)
					if err != nil {
						log.Printf("error pulling file : %s %s\n", path, err)
						// bail??
					}
				}
			}
		}
	} else {
		log.Println("nothing to pull")
	}

	return 0

}

func (c *PullCommand) Help() string {
	return "help: pull files from a remote sftp server"
}

func (c *PullCommand) Synopsis() string {
	return "synopsis: pull files from a remote sftp server"
}
