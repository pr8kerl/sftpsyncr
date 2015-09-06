// streaming-write-benchmark benchmarks the peformance of writing
// from /dev/zero on the client to /dev/null on the server via io.Copy.
package main

import (
	"github.com/pkg/sftp"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
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

func walkRemote(client *sftp.Client, rdir string, rfmap *map[string]os.FileInfo) error {

	walker := client.Walk(rdir)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			log.Println(err)
			continue
		}
		rstat := walker.Stat()

		// only add the file to the list if it matches regexp
		if matched := fileregexp.MatchString(rstat.Name()); matched {
			p := walker.Path()
			rel, _ := filepath.Rel(rdir, p)
			(*rfmap)[rel] = rstat
		}

		log.Printf("remote path: %s,\tsize: %d", walker.Path(), rstat.Size())

		//              log.Println(walker.Path())
		//    Name() string       // base name of the file
		//    Size() int64        // length in bytes for regular files; system-dependent for others
		//    Mode() FileMode     // file mode bits
		//    ModTime() time.Time // modification time
		//    IsDir() bool        // abbreviation for Mode().IsDir()
		//    Sys() interface{}   // underlying data source (can return nil)
	}

	return nil

}
func mkdir(client *sftp.Client, rdir string) error {
	err := client.Mkdir(rdir)
	if err != nil {
		return err
	}
	return nil
}

func send(client *sftp.Client, lfile string, size int64, rfile string) error {

	// open file on remote host
	w, err := client.Create(rfile)
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
