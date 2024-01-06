package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"math/big"
	"os"
)

/*
	CRYPTO SECTION
*/

func privKeyGen() *ecdsa.PrivateKey {
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Error generating the private key")
	}
	return privkey
}

func computePubKey(privkey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	pubkey, _ := privkey.Public().(*ecdsa.PublicKey)
	return pubkey
}

func pubkeyToByteSlice(pubkey *ecdsa.PublicKey) []byte {
	formatted := make([]byte, 64)
	pubkey.X.FillBytes(formatted[:32])
	pubkey.Y.FillBytes(formatted[32:])
	return formatted
}

func byteSliceToPubkey(byteslice []byte) *ecdsa.PublicKey {
	var x, y big.Int
	x.SetBytes(byteslice[:32])
	y.SetBytes(byteslice[32:])
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
}

func signByteSlice(data []byte, privkey *ecdsa.PrivateKey) []byte {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privkey, hashed[:])
	if err != nil {
		log.Fatal("Error signing the message")
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	logProgress("Computed signature : " + hex.EncodeToString(signature))
	return append(data, signature...)
}

func verify(data []byte, signature []byte, pubkey *ecdsa.PublicKey) bool {
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(pubkey, hashed[:], &r, &s)
}

func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

func decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}

var privkeyPEMpath = "./privkey.pem"
var pubkeyPEMpath = "./pubkey.pem"

func exportKey() {
	privcode, pubcode := encode(privkey, byteSliceToPubkey(pubkey))
	os.WriteFile(privkeyPEMpath, []byte(privcode), 0600)
	os.WriteFile(pubkeyPEMpath, []byte(pubcode), 0600)
}

func importKey() {
	privclear, _ := os.ReadFile(privkeyPEMpath)
	pubclear, _ := os.ReadFile(pubkeyPEMpath)
	var temp *ecdsa.PublicKey
	privkey, temp = decode(string(privclear), string(pubclear))
	pubkey = pubkeyToByteSlice(temp)
}
