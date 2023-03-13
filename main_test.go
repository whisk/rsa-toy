package main

import (
	"math"
	"reflect"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	private := PrivateKey{65473, 75827}
	public := PublicKey{75827, 60457}

	plaintext := "Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem"
	ciphertext := Encrypt(plaintext, public)
	decrypted_plaintext := Decrypt(ciphertext, private)

	if plaintext != decrypted_plaintext {
		t.Error("Decrypted plaintext does not match")
	}
}

func TestEncryptRandomized(t *testing.T) {
	public := PublicKey{75827, 60457}

	plaintext := "Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem"
	ciphertext1 := Encrypt(plaintext, public)
	ciphertext2 := Encrypt(plaintext, public)

	if reflect.DeepEqual(ciphertext1, ciphertext2) {
		t.Error("ciphertexts are equal, therefore randomization does not work")
	}
}

func TestGenerateKeysPair(t *testing.T) {
	for i := 0; i < 10; i++ {
		_, _, err := GenerateKeysPair()
		if err != nil {
			t.Error("Failed to generate keys pair: ", err)
		}
	}
}

func Test_genPrime_small(t *testing.T) {
	for i := 0; i < 100; i++ {
		p := genPrime(100, 1000)
		if p < 0 {
			t.Error("Failed to generate prime number")
		}
		for d := 2; d < int(math.Sqrt(float64(p)))+1; d++ {
			if p%d == 0 {
				t.Errorf("%d is not prime (divided by %d)", p, d)
			}
		}
	}
}

func Test_genPrime_big(t *testing.T) {
	for i := 0; i < 100; i++ {
		p := genPrime(100, 1000000)
		if p < 0 {
			t.Error("Failed to generate prime number")
		}
		for d := 2; d < int(math.Sqrt(float64(p)))+1; d++ {
			if p%d == 0 {
				t.Errorf("%d is not prime (divided by %d)", p, d)
			}
		}
	}
}
