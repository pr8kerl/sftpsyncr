package main

import (
	"flag"
	"github.com/mitchellh/cli"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type PushCommand struct {
	Ui   cli.Ui
	good []string
	bad  []FileError
}

func pushCmdFactory() (cli.Command, error) {

	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}

	// initialise good/bad slices - capacity 128 by default
	fgood := make([]string, 0, 128)
	fbad := make([]FileError, 0, 128)

	return &PushCommand{
		Ui: &cli.ColoredUi{
			Ui:          ui,
			OutputColor: cli.UiColorBlue,
		},
		good: fgood,
		bad:  fbad,
	}, nil
}

func (c *PushCommand) Run(args []string) int {

	// flags
	var cfgfile string
	cmdFlags := flag.NewFlagSet("push", flag.ContinueOnError)
	cmdFlags.StringVar(&profile, "profile", "default", "sftp session profile to use")
	cmdFlags.StringVar(&cfgfile, "config", "config.ini", "config file in git config ini format")
	if err := cmdFlags.Parse(args); err != nil {
		return 1
	}
	cmdFlags.Usage = func() { c.Ui.Output(c.Help()) }

	// config
	section, err := InitialiseConfig(cfgfile)
	if err != nil {
		log.Fatalf("error : failed to initialise config : %s", err)
		return 1
	}

	sess, err := NewSftpSession(section)
	if err != nil {
		log.Printf("%s\n", err)
		return 1
	}
	defer sess.Close()

	// build local file list
	filepath.Walk(config.Profile[profile].LocalDir, sess.WalkLocal)

	// if file list connect
	if len(sess.LocalFiles) > 0 {

		// build remote file list
		err = sess.WalkRemote()
		if err != nil {
			log.Printf("unable to walk remote server: %v", err)
			return 95
		}

		// check remote dest directory
		if _, ok := sess.RemoteFiles["."]; ok {
			if debug {
				log.Printf("DEBUG remote directory %s already exists on remote\n", config.Profile[profile].RemoteDir)
			}
		} else {
			err = sess.MkDirRemote(config.Profile[profile].RemoteDir, 0700)
		}

		// for each local file, if it isn't on remote, send
		for path := range sess.LocalFiles {

			var lsize, rsize int64 = 0, 0
			rfinfo, rexists := sess.RemoteFiles[path]
			lfinfo := sess.LocalFiles[path]

			lsize = lfinfo.Size()

			if debug {
				log.Printf("DEBUG processing local path : %s, %d\n", path, lsize)
			}

			if rexists {
				rsize = rfinfo.Size()
			}

			// ignore if it is on remote
			if rexists && lsize == rsize {

				if debug {
					log.Printf("DEBUG path %s already exists on remote with size %d bytes\n", path, lsize)
				}

				continue

			} else {

				// if it isn't on remote and it's a different size, send it
				// prepend the remote dir to the remote file path
				rfile := filepath.Join(config.Profile[profile].RemoteDir, path)
				// prepend the local dir to the local file path
				lfilepath := filepath.Join(config.Profile[profile].LocalDir, path)
				mode := lfinfo.Mode()
				if lfinfo.IsDir() {
					log.Printf("push directory %s\n", rfile)
					sess.MkDirRemote(rfile, mode)
				} else {

					if sess.section.Encrypt && !strings.HasSuffix(lfilepath, sess.section.EncryptSuffix) {
						lfilepath, lfinfo, err = sess.EncryptFile(lfilepath)
						if err != nil {
							log.Printf("push error encrypting file : %s, %s\n", lfilepath, err)
							c.bad = append(c.bad, FileError{path: path, err: err})
							continue
						}
						lsize = lfinfo.Size()
						log.Printf("push encrypted file: %s\n", lfilepath)
						rfile = rfile + sess.section.EncryptSuffix
					}

					log.Printf("push file %s size %d\n", rfile, lsize)
					err := sess.Push(lfilepath, rfile, lsize, mode)
					if err != nil {
						log.Printf("error pushing file : %s %s\n", path, err)
						c.bad = append(c.bad, FileError{path: path, err: err})
						// bail??
						continue
					}
					c.good = append(c.good, path)
				}
			}
		}
		// summarise results
		if len(c.good) > 0 {
			log.Printf("%d files successfully pushed\n", len(c.good))
			for i := range c.good {
				log.Printf("pushed: %s\n", c.good[i])
			}
		}
		if len(c.bad) > 0 {
			log.Printf("%d files had errors\n", len(c.bad))
			for i := range c.bad {
				log.Printf("not pushed: %s %s\n", c.bad[i].path, c.bad[i].err.Error())
			}
		}

	} else {
		log.Println("nothing to push")
	}

	return 0

}

func (c *PushCommand) Help() string {
	return "help: push files to a remote sftp server"
}

func (c *PushCommand) Synopsis() string {
	return "synopsis: push files to a remote sftp server"
}
