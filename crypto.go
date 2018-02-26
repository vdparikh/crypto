package crypto

import (
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
	"os"
)

// AesEncrypt ...
func AesEncrypt(data []byte, aesKey []byte) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// AesDecrypt ...
func AesDecrypt(data string, aesKey []byte) ([]byte, error) {
	decoded, _ := base64.StdEncoding.DecodeString(data)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	if len(decoded) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := decoded[:aes.BlockSize]
	decoded = decoded[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(decoded, decoded)

	return []byte(fmt.Sprintf("%s", decoded)), nil
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
		return ""
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
