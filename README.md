# crypto
A base crypto package for GoLang. Provides easy crypto operations for - AES, HMAC, Checksum and RSA Encrypt Decrypt

```
go get -u github.com/vdparikh/crypto
```

### Tests
```
go test -v
=== RUN   TestAesEncryptDecrypt
--- PASS: TestAesEncryptDecrypt (0.00s)
=== RUN   TestRsaEncryptDecrypt
--- PASS: TestRsaEncryptDecrypt (0.00s)
=== RUN   TestHmac
--- PASS: TestHmac (0.00s)
=== RUN   TestChecksum
--- PASS: TestChecksum (0.00s)
PASS
ok  	crypto/crypto	0.029s
```

### Benchmarks
```
go test -bench=.
goos: darwin
goarch: amd64
pkg: crypto/crypto
BenchmarkAesEncrypt-8   	  300000	      3470 ns/op
BenchmarkAesDecrypt-8   	 1000000	      2313 ns/op
BenchmarkRsaEncrypt-8   	 2000000	       670 ns/op
BenchmarkRsaDecrypt-8   	 1000000	      1207 ns/op
BenchmarkHmac-8         	  500000	      2650 ns/op
BenchmarkChecksum-8     	 3000000	       525 ns/op
PASS
ok  	crypto/crypto	10.192s
```


### Usage
Checkout the example file in the `example` folder
```go
package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/vdparikh/crypto"
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

	log.Println("Performing Operations on ", cryptValue)
	// AES Encrypt
	encryptedValue, err := crypto.AesEncrypt([]byte(cryptValue), key)
	if err == nil {
		log.Print("Encrypted Value: ", encryptedValue)
	}

	decryptedValue, err := crypto.AesDecrypt(encryptedValue, key)
	if err == nil {
		log.Println("Decrypted Value: ", string(decryptedValue))
	}

	hmacValue := crypto.HmacValue([]byte(cryptValue), key)
	if err == nil {
		log.Println("HMAC Value: ", hmacValue)
	}

	checksum := crypto.Checksum([]byte(cryptValue))
	if err == nil {
		log.Println("Checksum Value: ", checksum)
	}

	checksumFile := crypto.ChecksumFile("/tmp/temp_file")
	if err == nil {
		log.Println("Checksum File Value: ", checksumFile)
	}

	pubKeyBytes := readFile("public_key.pem")
	rsaEncryptedValue, err := crypto.RsaEncrypt([]byte(cryptValue), pubKeyBytes)
	if err == nil {
		rsaEncryptedValueEncoded := base64.StdEncoding.EncodeToString(rsaEncryptedValue)
		log.Println("RSA Encrypted Value: ", rsaEncryptedValueEncoded)
	}

	privKeyBytes := readFile("private_key.pem")
	rsaDecryptedValue, err := crypto.RsaDecrypt(rsaEncryptedValue, privKeyBytes)
	if err == nil {
		log.Println("RSA Encrypted Value: ", string(rsaDecryptedValue))
	}

}

func readFile(filename string) []byte {
	buf := bytes.NewBuffer(nil)
	f, _ := os.Open(filename)
	io.Copy(buf, f)
	f.Close()

	s := buf.Bytes()
	return s
}
```


### Sample Script Output
```shell
go run main.go 
INFO[0000] Performing Operations on This is a long text which will be encrypted 
INFO[0000] Encrypted Value: g6Fj2gAwOKX9QpLyER/5yhLh8it7sw8wxOrlFe2o/AHDd+N/HequAMJXA2Pau2CwhXB68rRvoWmwZaukNK5L2zp3RWbUxd+UDaFroA== 
INFO[0000] Decrypted Value:  This is a long text which will be encrypted 
INFO[0000] HMAC Value:  ZTFiNTFlYTQyYWFmNzI2ZTY5MDQ5NzYzODQ4OTU3MzEwOWQyNTNlNjhjMmMwN2U1MDVhZGE0ZThhNjkwMWI0YjVjMDAzOWNjMmZlNzQ3NDdhYjI3OWJjZTM5NTk1MjFiNDU1OTA5YjI4ZGRlZDEzYjYxMmE5NjI0OTJjMmNhNjY= 
INFO[0000] Checksum Value:  091d3d091d2e8359cb56a881a3e2c92c5a6708996a017dcbf17979119fb630ca 
INFO[0000] Checksum File Value:  091d3d091d2e8359cb56a881a3e2c92c5a6708996a017dcbf17979119fb630ca 
INFO[0000] RSA Encrypted Value:  nKVVuCY7bPzNvfCx+NCa/3QYiliinc2Jhuvf7ZQTc87ZvcDOWiQwvXfkicLLv9WqqjmvzxWGTqxeJvN9Gw9SzRUAadgeQapS4VRR5VoTYsIEs8ye9yyyWzeAf6tp1bsj6GclE3MozPYcC4GMeeyGsrVb1JReNboUxZYOYd5wdqAwwG9MJtaq7pO2rFE7vkP3TGBlP53DzjAttFTilGV/2IbvyRmGUZsuyrKc4nJt+wvzPUVulzMcnqD9wRBPkAJ66SnxK/floYeCLt7U006om+xr19R+JKjLtzO9SDy8YNsv5++jUYhKcjfcts3BSExqO+HhJ5inswr9uRsOvJrvPg== 
INFO[0000] RSA Encrypted Value:  This is a long text which will be encrypted 
```
