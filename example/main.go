package main

import (
	"bytes"
	"crypto/crypto"
	"encoding/base64"
	"io"
	"io/ioutil"
	"os"

	log "github.com/vdparikh/logrus"
)

/*
## Creating RSA Public/Private Key Pair
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private_key.pem -out private_key.pem
openssl rsa -pubout -in private_key.pem -out public_key.pem
*/

func main() {
	key := []byte("1234543444555666")
	cryptValue := "This is a long text which will be encrypted"
	err := ioutil.WriteFile("/tmp/temp_file", []byte(cryptValue), 0644)

	log.Info("Performing Operations on ", cryptValue)
	// AES Encrypt
	encryptedValue, err := crypto.AesEncrypt([]byte(cryptValue), key)
	if err == nil {
		log.Print("Encrypted Value: ", encryptedValue)
	}
	
	// AES Decrypt
	decryptedValue, err := crypto.AesDecrypt(encryptedValue, key)
	if err == nil {
		log.Println("Decrypted Value: ", string(decryptedValue))
	}

	// HMAC Value
	hmacValue := crypto.HmacValue([]byte(cryptValue), key)
	if err == nil {
		log.Println("HMAC Value: ", hmacValue)
	}

	// Checksum of Content
	checksum := crypto.Checksum([]byte(cryptValue))
	if err == nil {
		log.Println("Checksum Value: ", checksum)
	}

	// Checksum for a file. Use this operation if the file is large as it much faster and cleaner
	checksumFile := crypto.ChecksumFile("/tmp/temp_file")
	if err == nil {
		log.Println("Checksum File Value: ", checksumFile)
	}

	// RSA Encrypt using public key
	pubKeyBytes := readFile("public_key.pem")
	rsaEncryptedValue, err := crypto.RsaEncrypt([]byte(cryptValue), pubKeyBytes)
	if err == nil {
		rsaEncryptedValueEncoded := base64.StdEncoding.EncodeToString(rsaEncryptedValue)
		log.Println("RSA Encrypted Value: ", rsaEncryptedValueEncoded)
	}

	// RSA Decrypt using Private Key
	privKeyBytes := readFile("private_key.pem")
	rsaDecryptedValue, err := crypto.RsaDecrypt(rsaEncryptedValue, privKeyBytes)
	if err == nil {
		log.Println("RSA Encrypted Value: ", string(rsaDecryptedValue))
	}

}

// Util function to read a file and return bytes
func readFile(filename string) []byte {
	buf := bytes.NewBuffer(nil)
	f, _ := os.Open(filename)
	io.Copy(buf, f)
	f.Close()

	s := buf.Bytes()
	return s
}
