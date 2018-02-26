package crypto

import (
	"testing"
)

var (
	key              = []byte("1234543444555666")
	data             = "This is a long text which will be encrypted"
	encryptedData    = "g6Fj2gAwOKX9QpLyER/5yhLh8it7sw8wxOrlFe2o/AHDd+N/HequAMJXA2Pau2CwhXB68rRvoWmwZaukNK5L2zp3RWbUxd+UDaFroA=="
	rsaEncryptedData = "nKVVuCY7bPzNvfCx+NCa/3QYiliinc2Jhuvf7ZQTc87ZvcDOWiQwvXfkicLLv9WqqjmvzxWGTqxeJvN9Gw9SzRUAadgeQapS4VRR5VoTYsIEs8ye9yyyWzeAf6tp1bsj6GclE3MozPYcC4GMeeyGsrVb1JReNboUxZYOYd5wdqAwwG9MJtaq7pO2rFE7vkP3TGBlP53DzjAttFTilGV/2IbvyRmGUZsuyrKc4nJt+wvzPUVulzMcnqD9wRBPkAJ66SnxK/floYeCLt7U006om+xr19R+JKjLtzO9SDy8YNsv5++jUYhKcjfcts3BSExqO+HhJ5inswr9uRsOvJrvPg=="
	pubKey           = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsGPLhjbq7qy4IP7C6g5S
698/QLgIcXhBsQ6ZbvjmVBkLE+gh4AImMUjtvcTL/783snb4irWvFlJSzfwWmF8b
V0+swnaxf1rddlAWwE8KrBkIVXFWa/kTQ/ma6Tc3WY3/rJnb3c81Mf9guG9d7zHc
VjvjnQN/GrRn4KX/YVeLtqrih342HncfqKmGfyRgD/hwY/oHdD/sjOEEXBVe1Jqi
bHGAHFzoNbAmE9XsZ/QQ9pQuZl6+o6iLeV5satXYWVQffJEf6b4x3ptJ5Vc204ni
QXgIwNyaBBp98cH6zvBNlZcRb5pqFLEXCmeXkDF1rxharVR8rOUX5JB2w7+oQ5yc
lQIDAQAB
-----END PUBLIC KEY-----`)
	privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsGPLhjbq7qy4IP7C6g5S698/QLgIcXhBsQ6ZbvjmVBkLE+gh
4AImMUjtvcTL/783snb4irWvFlJSzfwWmF8bV0+swnaxf1rddlAWwE8KrBkIVXFW
a/kTQ/ma6Tc3WY3/rJnb3c81Mf9guG9d7zHcVjvjnQN/GrRn4KX/YVeLtqrih342
HncfqKmGfyRgD/hwY/oHdD/sjOEEXBVe1JqibHGAHFzoNbAmE9XsZ/QQ9pQuZl6+
o6iLeV5satXYWVQffJEf6b4x3ptJ5Vc204niQXgIwNyaBBp98cH6zvBNlZcRb5pq
FLEXCmeXkDF1rxharVR8rOUX5JB2w7+oQ5yclQIDAQABAoIBABoi/3JoytEI+NOy
zFEARFs9HlNJsb6Wki1ZO3UNHpwRhemyOOrHhr9AzjGTaqL/w5IHPPbYyxPkqO5q
zzJOzW9XmALMsapsXWp9nZFrZOpxXyHCBItFQgyNfN3X17TGbL83oTOx03EQJVXO
8r1RxxNkFmsarIfZeZb5IelbnpE3a/FFQTVCr2feXPXAeAxsnDmOd8fp+zNpczGy
oLk8GSuGvzlFb95bBXqo/ZNQYzmSUpKE7hKChLDTHzYfWj1XGnN3UpDuYzjiKdec
p+HA57GjnP7HxD4HFrq0P8eRCOmk5tOn3ovaEkZxcJblH/QkgdxFCyAWJOy6v1SP
G9QOYqECgYEA41NBJ5d0KlFnh+ZA/eD4tBtmUbl1viRiPiyAVHnE/RQeCnII9x6Z
P5knxbKBTKWeZWDKcTOIFZO5x5mCf2o0j8hGN/ImMChHCsDACCDMBcMMAXQimjba
jk4DGmiEtGNDgJUzL9t+CIOAf7hQxRwnmbJoLEUOrjTUinVJdgoKw4kCgYEAxqO+
dFmDiLBksPVhc4GSw8rQCxRLZ3HjpR/Lzy0TN20McoceDe9/MTJ2eAAvZepfJljR
GoxKxBqHq9LQNsb3EzVkgKy6MahEnw2kgizoegSYgrcumN03X/kUWvYSKpc32Nvp
81gACw9b9FM0vD7H/5GwaNbyF62Uv243Vt0Pca0CgYAwtBCcg+Vef6xXwGwiOIXw
SIKGdd6VC0SFH5GrB5+9vQampEHpeAPLTWvo/lKXclBaVf9pe2nnfYvrCKed1spG
F9l7eQTXgnmeAyfhVe2AOoai9RfIxIHUxUAC82ujHjVDIjQiR7tb5ZitRHcBlAOj
+UY6Xd1EU4tJ0tEXWhVuSQKBgQChdXtba18k/ev6gpnBn3LCPto4Bzj7TnFxSJUL
Q2I5TSQu+3EMdr12KcRt6gic2JKawtrEr4AeQkpA+cxQmg0+ycl1ZfC6aEHO3vH2
9bXJaG7m4Sq5Cib2lalb/mPpxpyYYriZGdB/LO7be76DvKwoKi2wKfcCFA+yQk4t
BuaEyQKBgQDQS/GEcfk08JRXcGdvvfTbdzzI3LWUplyPwJsaHDzUJaK9Uv91nprN
77cETQt4A3XWAluzB/oLYG2yt8qgL/jXN9XHpQw8TSCoKZ2v0mDHF3U8pd47ilEi
yTqUmux0Hw4KbKKyDLKgk2haJZ45pB7tpQh6xClC4UNOYjGvDsv4mA==
-----END RSA PRIVATE KEY-----`)
)

func TestAesEncryptDecrypt(t *testing.T) {
	encryptedValue, _ := AesEncrypt([]byte(data), key)
	decryptedValue, _ := AesDecrypt(encryptedValue, key)
	if data != string(decryptedValue) {
		t.Errorf("AES Encrypt/Decrypt was incorrect, Got: %s, Want: %s.", decryptedValue, data)
	}
}

func TestRsaEncryptDecrypt(t *testing.T) {
	encryptedValue, _ := RsaEncrypt([]byte(data), pubKey)
	decryptedValue, _ := RsaDecrypt(encryptedValue, privateKey)
	if data != string(decryptedValue) {
		t.Errorf("RSA Encrypt/Decrypt was incorrect, Got: %s, Want: %s.", decryptedValue, data)
	}
}

func TestHmac(t *testing.T) {
	expectedHmacValue := "NWM0OTE1YjgyMjdkYmUxMzllYjc1ZDljODU2MjRiZDFjOGFlMjhmYzY2MjU5NmQ5OGUyOGYwNjc4NzNjYjY0YzYzMzgwZmU5ZDAyMDg0NGRjZWRkZWE1NDYyYTlmOTExNzI5ODBhYWE4Y2I3ZDU0MWM5YzQ2NGI2NTc2ZTYyYzM="
	hmacValue := HmacValue([]byte(data), pubKey)
	if hmacValue != expectedHmacValue {
		t.Errorf("Hmac was incorrect, Got: %s, Want: %s.", hmacValue, expectedHmacValue)
	}
}

func TestChecksum(t *testing.T) {
	expectedCheckValue := "091d3d091d2e8359cb56a881a3e2c92c5a6708996a017dcbf17979119fb630ca"
	checksum := Checksum([]byte(data))
	if checksum != expectedCheckValue {
		t.Errorf("Checksum was incorrect, Got: %s, Want: %s.", checksum, expectedCheckValue)
	}
}

func BenchmarkAesEncrypt(b *testing.B) {
	// run the AESEncrypt function b.N times
	for n := 0; n < b.N; n++ {
		AesEncrypt([]byte(data), key)
	}
}

func BenchmarkAesDecrypt(b *testing.B) {
	// run the AesDecrypt function b.N times
	for n := 0; n < b.N; n++ {
		AesDecrypt(encryptedData, key)
	}
}

func BenchmarkRsaEncrypt(b *testing.B) {
	// run the RsaEncrypt function b.N times
	for n := 0; n < b.N; n++ {
		RsaEncrypt([]byte(data), pubKey)
	}
}

func BenchmarkRsaDecrypt(b *testing.B) {
	// run the RsaDescrypt function b.N times
	for n := 0; n < b.N; n++ {
		RsaDecrypt([]byte(rsaEncryptedData), privateKey)
	}
}

func BenchmarkHmac(b *testing.B) {
	// run the Hmac function b.N times
	for n := 0; n < b.N; n++ {
		HmacValue([]byte(data), key)
	}
}

func BenchmarkChecksum(b *testing.B) {
	// run the Checksum function b.N times
	for n := 0; n < b.N; n++ {
		Checksum([]byte(data))
	}
}
