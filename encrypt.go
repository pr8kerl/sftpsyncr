package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"io/ioutil"
	"log"
	"os"
)

// create gpg keys with
// $ gpg --gen-key
// ensure you correct paths and passphrase

const mySecretString = "this is so very secret!"
const prefix, passphrase = "/home/ians", "C00kyPu55"
const secretKeyring = prefix + "/.gnupg/secring.gpg"
const publicKeyring = prefix + "/.gnupg/pubring.gpg"
const myKeyId = "641E9413"

var receiver uint64 = 5

func encTest(secretString string) (string, error) {
	log.Println("Secret to hide:", secretString)
	log.Println("Public Keyring:", publicKeyring)

	// Read in public key
	keyringFileBuffer, err := os.Open(publicKeyring)
	if err != nil {
		return "", fmt.Errorf("open KeyRing error: %s\n", err.Error())
	}
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", fmt.Errorf("ReadKeyRing error: %s\n", err.Error())
	}
	mykey := getKeyByIdShortString(entityList, myKeyId)
	if mykey == nil {
		return "", fmt.Errorf("cannot find key with ID : %s\n", myKeyId)
	}

	// encrypt string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, []*openpgp.Entity{mykey}, nil, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write([]byte(mySecretString))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	// Encode to base64
	bytes, err := ioutil.ReadAll(buf)
	if err != nil {
		return "", err
	}
	encStr := base64.StdEncoding.EncodeToString(bytes)

	// Output encrypted/encoded string
	log.Println("Encrypted Secret:", encStr)

	return encStr, nil
}

func decTest(encString string) (string, error) {

	log.Println("Secret Keyring:", secretKeyring)
	log.Println("Passphrase:", passphrase)

	// init some vars
	//var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}

	mykey := getKeyByIdShortString(entityList, myKeyId)
	if mykey == nil {
		return "", fmt.Errorf("cannot find key with ID : %s\n", myKeyId)
	}

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	passphraseByte := []byte(passphrase)
	log.Println("Decrypting private key using passphrase")
	mykey.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range mykey.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}
	log.Println("Finished decrypting private key using passphrase")

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}

func getKeyByEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == email {
				return entity
			}
		}
	}
	return nil
}

func getKeyByIdShortString(keyring openpgp.EntityList, keyidstr string) *openpgp.Entity {
	for _, entity := range keyring {
		//kid := entity.PrimaryKey.KeyId
		kid := entity.PrimaryKey.KeyIdShortString()
		if kid == keyidstr {
			fmt.Printf("my key id: %s\n", kid)
			return entity
		}
	}
	return nil
}

func main() {
	bkeyid, err := hex.DecodeString(myKeyId)
	if err != nil {
		log.Fatal(err)
	}
	bksize := binary.Size(bkeyid)
	fmt.Printf("binary key size: %v\n", bksize)
	kid, _ := binary.Varint(bkeyid)
	fmt.Printf("binary key id: %v\n", kid)
	// next read KeyById from entityList
	encStr, err := encTest(mySecretString)
	if err != nil {
		log.Fatal(err)
	}
	decStr, err := decTest(encStr)
	if err != nil {
		log.Fatal(err)
	}
	// should be done
	log.Println("Decrypted Secret:", decStr)
}
