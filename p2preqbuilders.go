package main

import (
	"encoding/binary"
	"encoding/hex"
)

/*
	Request builders for peer-to-peer communication
*/

func buildNoOpRequestOfGivenSize(size uint16, id uint32) *P2PMsg {
	buf := make([]byte, 4)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint32(buf, id)
	binary.BigEndian.PutUint16(buf2, size)
	return &P2PMsg{
		Id:     buf,
		Length: buf2,
		Body:   make([]byte, size),
	}
}

func buildNoOpRequest(id uint32) *P2PMsg {
	return buildNoOpRequestOfGivenSize(0, id)
}

func buildHelloRequest(name string, id uint32, extensions uint32) *HelloExchange {
	buf := make([]byte, 4)
	buf2 := make([]byte, 2)
	buf3 := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, id)
	binary.BigEndian.PutUint16(buf2, uint16(len(name)+4)) // +4 for extensions
	binary.BigEndian.PutUint32(buf3, extensions)
	return &HelloExchange{
		Id:         buf,
		Type:       2,
		Length:     buf2,
		Extensions: buf3,
		Name:       []byte(name),
	}
}

func buildHelloReply(id uint32) *HelloExchange {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(name)+4)) // +4 for extensions
	return &HelloExchange{
		Type:   129,
		Length: buf,
		Name:   []byte(name),
	}
}

func buildErrorMessage(msg string, id uint32) *P2PMsg {
	buf := make([]byte, 4)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint32(buf, id)
	binary.BigEndian.PutUint16(buf2, uint16(len(msg)))
	return &P2PMsg{
		Id:     buf,
		Type:   1,
		Length: buf2,
		Body:   []byte(msg),
	}
}

func buildErrorReply(msg string, id uint32) *P2PMsg {
	buf := make([]byte, 4)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint32(buf, id)
	binary.BigEndian.PutUint16(buf2, uint16(len(msg)))
	return &P2PMsg{
		Id:     buf,
		Type:   128,
		Length: buf2,
		Body:   []byte(msg),
	}
}

func buildPubkeyRequestNoPubkey(id uint32) *P2PMsg {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, id)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf2, uint16(0))
	return &P2PMsg{
		Id:     buf,
		Type:   3,
		Length: buf2,
	}
}

func buildPubkeyRequestWithPubkey(id uint32, pubkey []byte) *P2PMsg { // pubkey is 64 bytes long
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, id)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf2, uint16(64))
	return &P2PMsg{
		Id:     buf,
		Type:   3,
		Length: buf2,
		Body:   pubkey,
	}
}

func buildPubkeyReplyNoPubkey(id uint32) *P2PMsg {
	buf := make([]byte, 4)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint32(buf, id)
	binary.BigEndian.PutUint16(buf2, uint16(0))
	return &P2PMsg{
		Id:     buf,
		Type:   130,
		Length: buf2,
	}
}

func buildPubkeyReplyWithPubkey(pubkey []byte, id uint32) *P2PMsg { // pubkey is 64 bytes long
	buf := make([]byte, 4)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint32(buf, id)
	binary.BigEndian.PutUint16(buf2, uint16(64))
	return &P2PMsg{
		Id:     buf,
		Type:   130,
		Length: buf2,
		Body:   pubkey,
	}
}

/*
func buildRootReplyNoData() *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(32))
	return &P2PMsg{
		Type:   131,
		Length: buf,
		Body:   emptyStringHash,
	}
} */

func buildRootReply(roothash []byte, id uint32) *P2PMsg { // hash is 32 bytes long
	buf := make([]byte, 4)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint32(buf, id)
	binary.BigEndian.PutUint16(buf2, uint16(32))
	return &P2PMsg{
		Id:     buf,
		Type:   131,
		Length: buf2,
		Body:   roothash,
	}
}

func buildRootRequest(id uint32, roothash []byte) *P2PMsg { // hash is 32 bytes long
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, id)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf2, uint16(32))
	return &P2PMsg{
		Id:     buf,
		Type:   4,
		Length: buf2,
		Body:   roothash,
	}
}

func buildRootRequestNoData(id uint32) *P2PMsg {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, id)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf2, uint16(32))
	return &P2PMsg{
		Id:     buf,
		Type:   4,
		Length: buf2,
		Body:   emptyStringHash,
	}
}

func buildDatumRequest(datahash []byte, id uint32) *P2PMsg { // 32 bytes long
	logProgress("Building Datum request for hash : " + string(hex.EncodeToString(datahash)))
	buf := make([]byte, 4)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint32(buf, id)
	binary.BigEndian.PutUint16(buf2, uint16(32))
	return &P2PMsg{
		Id:     buf,
		Type:   5,
		Length: buf2,
		Body:   datahash,
	}
}

func buildNatTraversalRequestIPv4(ipv4addr []byte, port uint16, id uint32) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(6)) // ipv4 addr are on 4 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf2, port)
	buf3 := make([]byte, 4)
	binary.BigEndian.PutUint32(buf3, id)
	return &P2PMsg{
		Id:     buf3,
		Type:   6,
		Length: buf,
		Body:   append(ipv4addr, buf2...),
	}
}

func buildNatTraversalRequestIPv6(ipv6addr []byte, port uint16, id uint32) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(18)) // ipv6 addr are on 16 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf2, port)
	buf3 := make([]byte, 4)
	binary.BigEndian.PutUint32(buf3, id)
	return &P2PMsg{
		Id:     buf3,
		Type:   6,
		Length: buf,
		Body:   append(ipv6addr, buf2...),
	}
}

/*
	UNUSED FUNCTIONS FOR NOW
	(We do not currently store data and don't expect peers to contact us)
	(We do not support NAT traversal for now)
*/

func buildDatumReply(id []byte, value []byte, hash []byte) *Datum { // variable length, assumed storable on 2 bytes
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(value)+32)) // add the hash length to the total
	return &Datum{
		Id:     id,
		Type:   132,
		Length: buf,
		Hash:   hash, // 32 bytes
		Value:  value,
	}
}

func buildNatTraversalReplyIPv4(ipv4addr []byte, port uint16) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(6)) // ipv4 addr are on 4 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf2, port)
	return &P2PMsg{
		Type:   7,
		Length: buf,
		Body:   append(ipv4addr, buf2...),
	}
}

func buildNatTraversalReplyIPv6(ipv6addr []byte, port uint16, id uint32) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(18)) // ipv6 addr are on 16 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf2, port)
	return &P2PMsg{
		Type:   7,
		Length: buf,
		Body:   append(ipv6addr, buf2...),
	}
}
