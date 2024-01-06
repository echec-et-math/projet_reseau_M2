package main

import (
	"encoding/binary"
	"fmt"
)

/*
	Custom struct converter for proper UDP datagram communication
*/

func helloToByteSlice(exchange *HelloExchange) []byte {
	k := binary.BigEndian.Uint16(exchange.Length) // TODO err handling
	fmt.Printf("Found length of Hello byte slice = %d\n", k)
	res := make([]byte, 11+len(exchange.Name)+len(exchange.Signature))
	for i := 0; i < 4; i++ {
		res[i] = exchange.Id[i]
	}
	res[4] = exchange.Type
	for i := 0; i < 2; i++ {
		res[5+i] = exchange.Length[i]
	}
	for i := 0; i < 4; i++ {
		res[7+i] = exchange.Extensions[i]
	}
	l := len(exchange.Name)
	for i := 0; i < l; i++ {
		res[11+i] = exchange.Name[i]
	}
	for i := 0; i < len(exchange.Signature); i++ {
		res[11+l+i] = exchange.Signature[i]
	}
	if debugmode {
		fmt.Println("Id: ", res[0:4])
		fmt.Println("type: ", res[4])
		fmt.Println("length: ", res[5:7])
		fmt.Println("body:", res[7:7+k])
		fmt.Println("signature : ", res[7+k:])
	}
	return res
}

func datumToByteSlice(datum *Datum) []byte {
	l := binary.BigEndian.Uint16(datum.Length) // TODO err handling
	fmt.Printf("Found length of Datum byte slice = %d\n", l)
	res := make([]byte, 7+l+uint16(len(datum.Signature)))
	for i := 0; i < 4; i++ {
		res[i] = datum.Id[i]
	}
	res[4] = datum.Type
	for i := 0; i < 2; i++ {
		res[5+i] = datum.Length[i]
	}
	for i := 0; i < 32; i++ {
		res[7+i] = datum.Hash[i]
	}
	for i := 0; i < int(l)-32; i++ {
		res[39+i] = datum.Value[i]
	}
	for i := 0; i < len(datum.Signature); i++ {
		res[uint16(7)+l+uint16(i)] = datum.Signature[i]
	}
	if debugmode {
		fmt.Println("Id: ", res[0:4])
		fmt.Println("type: ", res[4])
		fmt.Println("length: ", res[5:7])
		fmt.Println("body:", res[7:39])
		fmt.Println("datatype : ", res[39])
		fmt.Println("signature: ", res[40:])
	}
	return res
}

func requestToByteSlice(req *P2PMsg) []byte {
	l := binary.BigEndian.Uint16(req.Length) // TODO err handling
	fmt.Printf("Found length of byte slice = %d\n", l)
	res := make([]byte, uint16(7)+l+uint16(len(req.Signature)))
	for i := 0; i < 4; i++ {
		res[i] = req.Id[i]
	}
	res[4] = req.Type
	for i := 0; i < 2; i++ {
		res[5+i] = req.Length[i]
	}
	for i := 0; uint16(i) < l; i++ {
		res[7+i] = req.Body[i]
	}
	for i := 0; i < len(req.Signature); i++ {
		res[uint16(7)+l+uint16(i)] = req.Signature[i]
	}
	if debugmode {
		fmt.Println("Id: ", res[0:4])
		fmt.Println("type: ", res[4])
		fmt.Println("length: ", res[5:7])
		fmt.Println("body:", res[7:l+7])
		fmt.Println("signature : ", res[l+7:])
	}
	return res
}
