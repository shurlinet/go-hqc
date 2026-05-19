//go:build ignore

// Command gen_go_vectors generates HQC keygen and encaps output from Go
// and prints it as JSON lines for the C reverse-verify harness.
//
// Usage (default HQC-128):
//
//	go run tools/reverse-verify/gen_go_vectors.go | ./reverse_verify_hqc1
//	go run tools/reverse-verify/gen_go_vectors.go -param 192 | ./reverse_verify_hqc3
//	go run tools/reverse-verify/gen_go_vectors.go -param 256 | ./reverse_verify_hqc5
package main

import (
	"crypto/sha3"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/shurlinet/go-hqc"
)

func main() {
	param := flag.Int("param", 128, "HQC parameter set: 128, 192, or 256")
	flag.Parse()

	seeds := []string{
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		"303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f",
	}

	for _, seedHex := range seeds {
		entropy := mustDecode(seedHex)
		rng := newKATRNG(entropy)

		// Draw seed_kem from KATRNG (same as C's prng_get_bytes).
		seedKem := make([]byte, 32) // SeedSize is 32 for all param sets
		if _, err := io.ReadFull(rng, seedKem); err != nil {
			log.Fatal(err)
		}

		var pk, sk []byte
		var encSS, encCT []byte
		var destroy func()

		switch *param {
		case 128:
			dk, err := hqc.NewDecapsulationKey128(seedKem)
			if err != nil {
				log.Fatal(err)
			}
			pk = dk.EncapsulationKey().Bytes()
			sk = dk.Bytes()
			encSS, encCT = dk.EncapsulationKey().Encapsulate()
			destroy = dk.Destroy
		case 192:
			dk, err := hqc.NewDecapsulationKey192(seedKem)
			if err != nil {
				log.Fatal(err)
			}
			pk = dk.EncapsulationKey().Bytes()
			sk = dk.Bytes()
			encSS, encCT = dk.EncapsulationKey().Encapsulate()
			destroy = dk.Destroy
		case 256:
			dk, err := hqc.NewDecapsulationKey256(seedKem)
			if err != nil {
				log.Fatal(err)
			}
			pk = dk.EncapsulationKey().Bytes()
			sk = dk.Bytes()
			encSS, encCT = dk.EncapsulationKey().Encapsulate()
			destroy = dk.Destroy
		default:
			log.Fatalf("unsupported param: %d", *param)
		}

		fmt.Printf("{\"type\":\"keygen\",\"entropy\":\"%s\",\"pk\":\"%s\",\"sk\":\"%s\"}\n",
			hex.EncodeToString(entropy),
			hex.EncodeToString(pk),
			hex.EncodeToString(sk))

		fmt.Printf("{\"type\":\"encaps\",\"key_entropy\":\"%s\",\"ct\":\"%s\",\"ss\":\"%s\"}\n",
			hex.EncodeToString(entropy),
			hex.EncodeToString(encCT),
			hex.EncodeToString(encSS))

		destroy()
	}
}

type katRNG struct {
	state *sha3.SHAKE
}

func newKATRNG(entropy []byte) *katRNG {
	st := sha3.NewSHAKE256()
	st.Write(entropy)
	st.Write([]byte{0x00})
	return &katRNG{state: st}
}

func (r *katRNG) Read(p []byte) (int, error) {
	return r.state.Read(p)
}

func mustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}
