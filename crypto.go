package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/ugorji/go/codec"
)

const ivLen = 16

type encryptionObject struct {
	KEK        string `codec:"k"`
	Iv         []byte `codec:"i"`
	Ciphertext []byte `codec:"c"`
}

func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func msgPack(obj encryptionObject) ([]byte, error) {
	var b []byte
	mh := new(codec.MsgpackHandle)
	var enc *codec.Encoder
	enc = codec.NewEncoderBytes(&b, mh)

	err := enc.Encode(obj)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func msgUnpack(obj []byte) (encryptionObject, error) {
	mh := new(codec.MsgpackHandle)
	dec := codec.NewDecoderBytes(obj, mh)

	var item encryptionObject
	err := dec.Decode(&item)
	return item, err
}

// AesEncrypt ...
func AesEncrypt(data []byte, aesKey []byte) (string, error) {

	// Random IV
	iv := make([]byte, ivLen)
	_, err := rand.Read(iv)
	if err != nil {
		return "", err
	}

	// Pad Plaintext
	padded := pad([]byte(data))
	ciphertext := make([]byte, len(padded))

	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(aesBlock, iv)
	mode.CryptBlocks(ciphertext, padded)

	// msgpack the KEK, IV and Ciphertext
	obj := encryptionObject{
		Iv:         iv,
		Ciphertext: ciphertext,
	}
	packed, err := msgPack(obj)
	return base64.StdEncoding.EncodeToString(packed), err
}

// AesDecrypt ...
func AesDecrypt(input string, aesKey []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}

	obj, err := msgUnpack(decoded)
	if err != nil {
		return nil, err
	}

	padded := make([]byte, len(obj.Ciphertext))
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(aesBlock, obj.Iv)
	mode.CryptBlocks(padded, obj.Ciphertext)

	return unpad(padded), nil
}

// HmacValue ...
func HmacValue(data []byte, hmacKey []byte) string {
	h512 := hmac.New(sha512.New, hmacKey[:])
	io.WriteString(h512, string(data))
	hexDigest := fmt.Sprintf("%x", h512.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(hexDigest))
}

// Checksum ...
func Checksum(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// ChecksumFile ...
func ChecksumFile(filename string) string {
	h := sha256.New()

	f, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RsaEncrypt ...
func RsaEncrypt(data []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("Public Key Error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, data)
}

// RsaDecrypt ...
func RsaDecrypt(ciphertext []byte, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("Private Key Error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
