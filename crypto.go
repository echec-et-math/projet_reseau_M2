package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"math/big"
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
	return append(data, signature...)
}

func verify(data []byte, signature []byte, pubkey *ecdsa.PublicKey) bool {
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(pubkey, hashed[:], &r, &s)
}

/*
	Setters for additional info throughout the requests
*/

/* func addHelloSignature(exchange *HelloExchange) {
	exchange.Signature = blablabla // TODO
} */

/* func addDatumSignature(datum *Datum) {
	datum.Signature = blablabla // TODO
} */

/* func addMsgSignature(msg *P2PMsg) {
	msg.Signature = blablabla // TODO
} */
