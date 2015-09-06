// streaming-write-benchmark benchmarks the peformance of writing
// from /dev/zero on the client to /dev/null on the server via io.Copy.
package main

import (
	"io"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/pkg/sftp"
)

var (
	USER string
	HOST string
	PORT int = 22
	PASS string
	SIZE int = 32768
)

func remoteMkdir(client *sftp.Client, rdir string) error {
	return nil
}

func send(client *sftp.Client, lfile string, size int64, rfile string) error {

	// open file on remote host
	w, err := client.OpenFile(rfile, syscall.O_WRONLY)
	if err != nil {
		return err
	}
	defer w.Close()

	f, err := os.Open(lfile)
	if err != nil {
		return err
	}
	defer f.Close()

	log.Printf("writing %v bytes", size)
	t1 := time.Now()
	n, err := io.Copy(w, io.LimitReader(f, size))
	if err != nil {
		return err
	}
	if n != size {
		log.Fatalf("copy: expected %v bytes, got %d", size, n)
	}
	log.Printf("wrote %v bytes in %s", size, time.Since(t1))

	return nil
}
