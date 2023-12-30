package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

/*
	Custom struct converter for proper UDP datagram communication
*/

func helloToByteSlice(exchange *HelloExchange) []byte {
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
	return res
}

func datumToByteSlice(datum *Datum) []byte {
	l, _ := strconv.Atoi(string(datum.Length)) // TODO err handling
	res := make([]byte, 7+l+len(datum.Signature))
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
	for i := 0; i < l-32; i++ {
		res[39+i] = datum.Value[i]
	}
	for i := 0; i < len(datum.Signature); i++ {
		res[7+l+i] = datum.Signature[i]
	}
	return res
}

func requestToByteSlice(req *P2PMsg) []byte {
	l := binary.BigEndian.Uint16(req.Length) // TODO err handling
	fmt.Printf("Found length of %d\n", l)
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
	return res
}
