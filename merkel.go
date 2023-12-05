package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

type P2PRequest struct {
	Id        []byte // 4 bytes
	Type      byte
	Length    []byte // 2 bytes
	Body      []byte // length bytes
	Signature []byte
}

type HelloExchange struct {
	Id         []byte // 4 bytes
	Type       byte
	Length     []byte // 2 bytes
	Extensions []byte // 4 bytes
	Name       []byte
	Signature  []byte
}

type Datum struct {
	Id        []byte // 4 bytes
	Type      byte
	Length    []byte // 2 bytes
	Hash      []byte // 32 bytes
	Value     []byte // Length - 32 bytes
	Signature []byte
}

type Node struct {
	Directory bool //directory or not
	Big       bool // a chunk or a big file, if directory is true then we ignore it
	nbchild   int
	Parent    *Node
	Childs    []*Node
	Hash      []byte //the hash of the node
	Data      []byte
}

func createFile(filepath string) Node {

	f, err := os.Open(filepath)

	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	buf := make([]byte, 1024)
	c := make([]Node, 32)
	var i, j int = 0, 0
	var bf []Node
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
			}
			break
		}
		if i == 32 {
			bf = append(bf, createBigFile(c, 32))
			i = 0
			j = j + 1
		}

		c[i] = createChunk(buf, n)
		i = i + 1
	}
	bf[j] = createBigFile(c, i+1)
	var bbf []Node
	for len(bf) > 32 {
		for a := 0; a < len(bf); a = a + 32 {
			bbf = append(bbf, createBigFile(c[a:32], 32))
		}
		bf = nil
		copy(bf, bbf) //copie dans bf bbf
	}
	return createBigFile(bf, len(bf))

}
func createChunk(content []byte, l int) Node {
	h := sha256.New()
	h.Write(content)
	return Node{
		Directory: false,
		Big:       false,
		Parent:    nil,
		Hash:      h.Sum(nil),
		Data:      content[0:l],
	}
}
func createBigFile(ch []Node, nb int) Node {
	s := []byte{}
	h := sha256.New()
	n := Node{
		Directory: false,
		Big:       true,
		nbchild:   nb,
	}
	for i := 1; i < nb; i++ {
		s = append(s, ch[i].Hash...)
		n.Childs[i] = &ch[i]
		n.Childs[i].Parent = &n
	}
	h.Write(s)
	n.Hash = h.Sum(nil)
	return n
}
func copyChunk(n *Node) *Node {
	return &Node{
		Directory: n.Directory,
		Big:       n.Big,
		nbchild:   n.nbchild,
		Parent:    n.Parent,
		Childs:    n.Childs,
		Hash:      n.Hash,
		Data:      n.Data,
	}
}
func AddChild(p Node, n Node) {

}

func buildNoOpRequestOfGivenSize(size uint16) *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, size)
	return &P2PRequest{
		Length: buf,
		Body:   make([]byte, size),
	}
}

func buildNoOpRequest() *P2PRequest {
	return buildNoOpRequestOfGivenSize(0)
}

func buildHelloRequest(name string) *HelloExchange {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(len(name)+4)) // +4 for extensions
	return &HelloExchange{
		Type:   2,
		Length: buf,
		Name:   []byte(name),
	}
}

func buildHelloReply(name string) *HelloExchange {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(len(name)+4)) // +4 for extensions
	return &HelloExchange{
		Type:   129,
		Length: buf,
		Name:   []byte(name),
	}
}

func buildErrorMessage(msg string) *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(len(msg)))
	return &P2PRequest{
		Type:   1,
		Length: buf,
		Body:   []byte(msg),
	}
}

func buildErrorReply(msg string) *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(len(msg)))
	return &P2PRequest{
		Type:   128,
		Length: buf,
		Body:   []byte(msg),
	}
}

func buildPubkeyRequestNoPubkey() *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(0))
	return &P2PRequest{
		Type:   3,
		Length: buf,
	}
}

func buildPubkeyRequestWithPubkey(pubkey []byte) *P2PRequest { // pubkey is 64 bytes long
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(64))
	return &P2PRequest{
		Type:   3,
		Length: buf,
		Body:   pubkey,
	}
}

func buildPubkeyReplyNoPubkey() *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(0))
	return &P2PRequest{
		Type:   130,
		Length: buf,
	}
}

func buildPubkeyReplyWithPubkey(pubkey []byte) *P2PRequest { // pubkey is 64 bytes long
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(64))
	return &P2PRequest{
		Type:   130,
		Length: buf,
		Body:   pubkey,
	}
}

/*
func buildRootRequestNoData() *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(32))
	return &P2PRequest{
		Type:   4,
		Length: buf,
		Body:   emptyStringHash,
	}
} */

func buildRootRequest(roothash []byte) *P2PRequest { // hash is 32 bytes long
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(32))
	return &P2PRequest{
		Type:   4,
		Length: buf,
		Body:   roothash,
	}
}

/*
func buildRootReplyNoData() *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(32))
	return &P2PRequest{
		Type:   131,
		Length: buf,
		Body:   emptyStringHash,
	}
} */

func buildRootReply(roothash []byte) *P2PRequest { // hash is 32 bytes long
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(32))
	return &P2PRequest{
		Type:   131,
		Length: buf,
		Body:   roothash,
	}
}

func buildDatumRequest(datahash []byte) *P2PRequest { // 32 bytes long
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(32))
	return &P2PRequest{
		Type:   5,
		Length: buf,
		Body:   datahash,
	}
}

/* func buildDatumReply(value []byte) *Datum { // variable length, assumed storable on 2 bytes
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(len(value)+32)) // add the hash length to the total
	return &Datum{
		Type:   132,
		Length: buf,
		Hash:   hash(value), // 32 bytes
		Value:  value,
	}
} */
func main() {
	s := ""

	h := sha256.New()

	h.Write([]byte(s))

	bs := h.Sum(nil)
	h.Write(bs)
	ba := h.Sum(nil)

	fmt.Println(s)
	fmt.Printf("%x\n", bs)
	fmt.Printf("%x\n", ba)

}
