package main

import (
	"flag"
	"github.com/mitchellh/cli"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PullCommand struct {
	Ui   cli.Ui
	good []string
	bad  []FileError
}

func pullCmdFactory() (cli.Command, error) {

	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}

	// initialise good/bad slices - capacity 128 by default
	fgood := make([]string, 0, 128)
	fbad := make([]FileError, 0, 128)

	return &PullCommand{
		Ui: &cli.ColoredUi{
			Ui:          ui,
			OutputColor: cli.UiColorBlue,
		},
		good: fgood,
		bad:  fbad,
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

	// build remote file list
	err = sess.WalkRemote()
	if err != nil {
		log.Printf("unable to walk remote server: %v\n", err)
		return 95
	}

	// if file list connect
	if len(sess.RemoteFiles) > 0 {

		// build local file list
		filepath.Walk(sess.section.LocalDir, sess.WalkLocal)

		// if stable check enabled, wait StableDuration seconds
		if stable {
			log.Printf("stable check enabled - pausing for %d to confirm remote file size stability\n", stableblock)
			time.Sleep(time.Duration(stableblock) * time.Second)
			log.Printf("stable check pause complete.\n")
		}

		// for each remote file, if it isn't on local, pull
		for path := range sess.RemoteFiles {

			var lsize, rsize int64 = 0, 0
			var archivepath string
			lfinfo, lexists := sess.LocalFiles[path]

			rfinfo := sess.RemoteFiles[path]
			rsize = rfinfo.Size()

			if debug {
				log.Printf("DEBUG processing remote path : %s, %d\n", path, rsize)
			}

			if lexists {
				lsize = lfinfo.Size()
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
				rfilepath := filepath.Join(sess.section.RemoteDir, path)
				// prepend the local dir to the local file path
				lfilepath := filepath.Join(sess.section.LocalDir, path)

				if archive {
					archivepath = filepath.Join(sess.section.ArchiveDir, path)
				}

				rmode := rfinfo.Mode()
				if rfinfo.IsDir() {
					log.Printf("pull directory %s\n", rfilepath)
					// test for local directory
					if _, err := os.Stat(lfilepath); err != nil {
						if os.IsNotExist(err) {
							// dir does not exist
							err = os.Mkdir(lfilepath, rmode)
							if err != nil {
								log.Printf("error creating local directory path : %s, %s\n", lfilepath, err)
							}
							if debug {
								log.Printf("DEBUG created dir %s\n", lfilepath)
							}
						}
					}
					if archive {
						if _, err := os.Stat(archivepath); err != nil {
							if os.IsNotExist(err) {
								// dir does not exist
								err = os.Mkdir(archivepath, rmode)
								if err != nil {
									log.Printf("error creating archive directory path : %s, %s\n", archivepath, err)
								}
								if debug {
									log.Printf("DEBUG created archive dir %s\n", archivepath)
								}
							}
						}
					}
				} else {

					if stable {
						csize, err := sess.GetRemoteSize(rfilepath)
						if err != nil {
							log.Printf("error checking remote file size, skipping : %s\n", err)
						}
						if csize != rsize {
							log.Printf("file %s size is not stable, skipping. current size: %d bytes, initial size: %d\n", path, csize, rsize)
							continue
						}
					}

					err := sess.Pull(rfilepath, lfilepath, rsize, rmode)
					if err != nil {
						log.Printf("error pulling file : %s %s\n", path, err)
						c.bad = append(c.bad, FileError{path: path, err: err})
						// bail??
						continue
					}
					if archive {
						// copy lfilepath to archivepath
						err := sess.CopyFile(lfilepath, archivepath)
						if err != nil {
							log.Printf("error archiving file : %s %s\n", path, err)
							c.bad = append(c.bad, FileError{path: path, err: err})
							continue
						}
						if debug {
							log.Printf("DEBUG archive file %s\n", archivepath)
						}
					}
					if sess.section.Decrypt {
						if strings.HasSuffix(lfilepath, sess.section.DecryptSuffix) {
							newfile, err := sess.DecryptFile(lfilepath)
							if err != nil {
								log.Printf("pull error decrypting file : %s\n", err)
								c.bad = append(c.bad, FileError{path: path, err: err})
								continue
							}
							log.Printf("pull decrypted file %s to %s\n", lfilepath, newfile)
						}

					}
					if clean {
						err := sess.RemoveRemote(rfilepath)
						if err != nil {
							log.Printf("error removing remote file : %s %s\n", path, err)
							c.bad = append(c.bad, FileError{path: path, err: err})
							continue
						}
					}
					c.good = append(c.good, path)
				}
			}
		}

		// summarise results
		if len(c.good) > 0 {
			log.Printf("%d files successfully pulled\n", len(c.good))
			for i := range c.good {
				log.Printf("pulled: %s\n", c.good[i])
			}
		}
		if len(c.bad) > 0 {
			log.Printf("%d files had errors\n", len(c.bad))
			for i := range c.bad {
				log.Printf("not pulled: %s %s\n", c.bad[i].path, c.bad[i].err.Error())
			}
			return 1
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
