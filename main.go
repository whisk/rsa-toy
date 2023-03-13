package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"
)

type PrivateKey struct {
	// see GenerateKeysPair for n and d values
	n, d int
}

type PublicKey struct {
	// see GenerateKeysPair for n and e values
	n, e int
}

// Generates a private and public key pair.
// Note that in theory, you cannot derive the public key knowing the private key. You can only generate them as a pair.
// In practice, the RSA private key file may contain intermediate values that allow computing the public key.
// See https://stackoverflow.com/a/1373088/7403220
func GenerateKeysPair() (private PrivateKey, public PublicKey, err error) {
	// generate two prime numbers that fit into a 16-bit integer and whose product fits into a 32-bit integer
	p := genPrime(100, 10000)
	q := genPrime(100, 10000)
	if p < 0 || q < 0 {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("Failed to generate prime numbers")
	}

	n := p * q
	phi := (p - 1) * (q - 1)
	// e < n, and e and phi must be coprimes. The simpliest way is to find a prime in range ( n/3, (p-1)(q-1) )
	// it is slow, as we are trying to generate quite a large prime
	e := genPrime(n/3+1, phi)
	if e < 0 {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("Failed to generate public e")
	}
	// we need only lx value
	_, d, _ := multInverse(e, phi)

	return PrivateKey{n: n, d: d}, PublicKey{n: n, e: e}, nil
}

// Encrypts a plaintext string using a public key and returns a slice of integers.
// We use a slice of integers for plaintexts as it has no practical use to store them as strings.
// Outputs different ciphertext each time as we use randomized padding, a countermeasure against some kinds of attacks.
// See OAEP (https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding) for more information.
func Encrypt(plaintext string, publicKey PublicKey) []int {
	res := make([]int, 0)
	buf := bytes.NewBufferString(plaintext)
	for {
		p, err := buf.ReadByte()
		if err != nil {
			break
		}
		// randomized padding
		r := byte(rand.Intn(255))
		a := hash1(r) ^ p
		b := hash2(a) ^ r

		t := (int(a) << 8) | int(b)

		c := expMod(int(t), publicKey.e, publicKey.n)
		res = append(res, c)
	}

	return res
}

// This function decrypts a given ciphertext (in the form of a slice of integers) using the private key,
// and returns the plaintext as a string.
func Decrypt(ciphertext []int, privateKey PrivateKey) string {
	buf := bytes.NewBufferString("")
	for _, c := range ciphertext {
		t := expMod(c, privateKey.d, privateKey.n)
		a := byte(t >> 8)
		b := byte(t) & 0b11111111
		r := hash2(a) ^ b
		p := hash1(r) ^ a

		buf.WriteByte(byte(p))
	}

	return buf.String()
}

// Arbitrary hash function.
// For good security, this function should have important hash-function properties like irreversibility and diffusion.
// However, to make randmized padding work, it could be any deterministic function. You could try:
// return x * 42
// return x
// return 1
// or anything!
func hash1(x byte) byte {
	x ^= x >> 4
	x *= 0x45
	x ^= x >> 4
	x *= 0x45
	x ^= x >> 4
	return x
}

// Another arbitrary hash function. See hash1 for an explanation
func hash2(x byte) byte {
	x ^= x >> 4
	x *= 0x3b
	x ^= x >> 4
	x *= 0x3b
	x ^= x >> 4
	return x
}

// Finds Base^Exp mod Mod efficiently
func expMod(base, exp, mod int) int {
	res := 1
	for exp > 0 {
		if exp%2 == 1 {
			res = (res * base) % mod
			exp -= 1
		} else {
			base = base * base % mod
			exp /= 2
		}
	}

	return res
}

// Finds gcd(a,b), lx, ly that gcd(a, b) = lx * a + ly * b
// Based on https://gist.github.com/JekaDeka/c9b0f5da16625e3c7bd1033356354579
func multInverse(a, b int) (int, int, int) {
	x := 0
	y := 1
	lx := 1
	ly := 0
	oa := a
	ob := b
	for b != 0 {
		q := a / b
		a, b = b, a%b
		x, lx = lx-q*x, x
		y, ly = ly-q*y, y
	}

	if lx < 0 {
		lx += ob
	}
	if ly < 0 {
		ly += oa
	}

	return a, lx, ly
}

// Generates a random prime number within the specified range using the Eratosthenes sieve algorithm
// Slow and memory-consuming but very simple.
func genPrime(min, max int) int {
	// 0 - prime, 1 - not prime
	sieve := make([]int8, max+1)
	sieve[1] = 1
	for i := 2; i <= max/2+1; i++ {
		if sieve[i] == 1 {
			continue
		}

		for j := i * 2; j <= max; j += i {
			sieve[j] = 1
		}
	}

	// pick a random prime from the sieve within a range
	// we select random x and search for the nearest prime both ways
	x := rand.Intn(max-min+1) + min
	i := 0
	for x+i <= max || x-i >= min {
		if x+i <= max && sieve[x+i] == 0 {
			return x + i
		}
		if x-i >= min && sieve[x-i] == 0 {
			return x - i
		}
		i++
	}

	// no prime numbers within the given range
	return -1
}

func main() {
	rand.Seed(time.Now().UnixMicro())

	private, public, err := GenerateKeysPair()
	fmt.Printf("Private key: %v, public key: %v\n", private, public)
	if err != nil {
		fmt.Println("Failed to generate key pair:", err.Error())
		return
	}

	original_plaintext := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
	ciphertext := Encrypt(original_plaintext, public)
	decrypted_plaintext := Decrypt(ciphertext, private)
	fmt.Println("Decrypted plaintext:", decrypted_plaintext)

	if original_plaintext == decrypted_plaintext {
		fmt.Println("It works!")
	}
}
