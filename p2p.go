package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

/*
	PEER-TO-PEER SECTION
*/

/*
	Peer-to-peer structs for communication
*/

type P2PMsg struct {
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
	Childs    []Node
	Hash      []byte //the hash of the node
	Data      []byte
	name      string //for dir and the root of big file
}

/*
	UDP readers
*/

func readMsgNoSignature(conn net.Conn) []byte {
	// first read until the length
	header := make([]byte, 7)
	_, err := conn.Read(header)
	if err != nil || force_err {
		logProgress("Error reading from UDP socket")
		e := err.(net.Error)
		if e.Timeout() || force_err {
			logProgress("Connection timeout : returning an empty message.")
			return make([]byte, 0)
		}
	}
	msgtype := header[4]
	length := binary.BigEndian.Uint16(header[5:7])
	content := make([]byte, length)
	conn.Read(content)
	res := append(header, content...)
	displayError(res)
	if msgtype == 0 {
		// NoOp
		logProgress("Read NoOp message : skipping.")
		return readMsgNoSignature(conn)
	}
	return res
}

func readMsgWithSignature(conn net.Conn) []byte {
	// first read until the length
	header := make([]byte, 7)
	conn.Read(header)
	msgtype := header[4]
	length := binary.BigEndian.Uint16(header[5:7])
	content := make([]byte, length)
	conn.Read(content)
	signature := make([]byte, 64)
	conn.Read(signature)
	res := append(append(header, content...), signature...)
	displayError(res)
	if msgtype == 0 {
		// NoOp
		logProgress("Read NoOp message : skipping.")
		return readMsgNoSignature(conn)
	}
	return res
}

func verifChunk(content []byte, Hash []byte) bool {
	h := sha256.New()
	h.Write(content)
	tmp := h.Sum(nil)
	for i := 0; i < 32; i++ {
		if tmp[i] != Hash[i] {
			return false
		}
	}

	return true
}

func compareHash(h1 []byte, h2 []byte) bool {
	if len(h1) != len(h2) {
		for i := 0; i < len(h1); i++ {
			if h1[i] != h2[i] {
				return false
			}
		}
		return true
	} else {
		return false
	}
}

func findNode(Hash []byte, n Node) *Node {
	if compareHash(n.Hash, Hash) {
		return &n
	} else {
		for i := 0; i < n.nbchild; i++ {
			tmp := findNode(Hash, n.Childs[i])
			if tmp != nil {
				return tmp
			}
		}
		return nil
	}
}

func sendDatum(n Node, con net.Conn) {
	var data []byte

	if n.Directory {
		data[0] = byte(1)
		for i := 1; i < n.nbchild; i++ {
			data = append(data, ([]byte(n.Childs[i].name))...)
			data = append(data, n.Childs[i].Hash...)
		}
	}
	if n.Big {
		data[0] = byte(1)
		for i := 1; i < n.nbchild; i++ {
			data = append(data, n.Childs[i].Hash...)

		}
	} else {
		data[0] = byte(0)
		data = append(data, n.Data...)

	}
	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, uint16(len(data)+32))
	datum := &Datum{
		Length: tmp,
		Hash:   n.Hash,
		Value:  data,
	}

	con.Write(datumToByteSlice(datum))

}

func downloadNode(Hash []byte, conn net.Conn) Node {
	currentP2PConn.SetReadDeadline(time.Time{})
	logProgress("Asking for hash : " + string(hex.EncodeToString(Hash)))
	tmp := buildDatumRequest(Hash, 89)
	conn.Write(requestToByteSlice(tmp))
	answer := make([]byte, 40)
	for {
		answer = make([]byte, 40) // fully reset buffer
		conn.Read(answer)
		msgtype := answer[4]
		if debugmode {
			fmt.Printf("Download Node : found message type of %d\n", msgtype)
		}
		if msgtype == 132 { // Datum
			break
		}
		displayError(answer)
	}
	logProgress("test")
	length := binary.BigEndian.Uint16(answer[5:7])
	if debugmode {
		fmt.Printf("Download Node : found length of %d\n", length)
	}
	datatype := answer[39]
	if debugmode {
		fmt.Printf("Download Node : found datatype of %d\n", datatype)
	}
	if datatype == 0 {
		//chunk
		data := make([]byte, length-33)
		conn.Read(data)
		logProgress("un chunk de load")

		return createChunk(data, 1024) //TODO faire un truc qui detecte la vraie longueur des donné

	}
	if datatype == 1 {
		//big
		h := make([]byte, length-33)
		conn.Read(h)
		var bf []Node
		for i := 0; i < 32; i++ {
			bf = append(bf, downloadNode(h[i*32:i+1*32], conn))
			if int(h[0]) == 0 {
				break
			}
		}
		return createBigFile(bf, len(bf))
	}
	if datatype == 2 {
		//directory
		n := createDirectory("")

		tmp := make([]byte, length-33)
		conn.Read(tmp)
		name := make([]byte, 32)
		h := make([]byte, 32)

		for i := 0; i < 16; i++ {
			name = tmp[i*32*2 : (i+1)*32*2]
			h = tmp[(i+1)*32*2 : (i+2)*32*2]
			if int(h[0]) == 0 {
				break
			}
			AddChild(n, downloadNode(h, conn))
			n.Childs[i].name = string(name)
		}
		return n
	}
	logProgress("ya un blem")
	return createDirectory("")

}

/*
	REST macro to check if someone has a declared pubkey.
	If someone writes to us and we do implement signatures,
	we HAVE to check if they have a declared pubkey.
	If they do, we have to reject any unsigned or badly signed message of types :
	Hello / HelloReply / PublicKey / PublicKeyReply / Root / RootReply
*/

func fetchPubKey(name string) ([]byte, bool) {
	res := make([]byte, 64)
	req := buildGetPeerPubkeyRequest(name)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Error fetching server for pubkey")
		return res, false
	}
	if resp.StatusCode == http.StatusNotFound { // 404
		return res, false
	}
	if resp.StatusCode == http.StatusNoContent { // 204
		return res, false
	}
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed parsing the pubkey")
		return res, false
	}
	resp.Body.Close()
	res = append(res, text...)
	return res, true
}

func salute(name string) {
	for {
		req := buildHelloRequest(name, 153, 0)
		currentP2PConn.Write(helloToByteSlice(req))
		rep := readMsgNoSignature(currentP2PConn) // TODO signature mode. We read the HelloReply.
		repid := binary.BigEndian.Uint32(rep[0:4])
		if repid == 153 { // handshake ok
			break
		}
	}
	currentP2PConn.SetReadDeadline(time.Now().Add(time.Second * 5)) // accept a one-minute delay for pubkey or roothash
	for {
		req := readMsgNoSignature(currentP2PConn) // read for a PublicKey or a Root
		if len(req) == 0 {
			// empty message
			return
		}
		reqtype := req[4]
		reqid := binary.BigEndian.Uint32(req[0:4])
		if reqtype == 3 { // PublicKey
			rep := buildPubkeyReplyNoPubkey(reqid) // TODO dignature
			currentP2PConn.Write(requestToByteSlice(rep))
			break
		}
		if reqtype == 4 { // Root
			rep := buildRootReply(emptyStringHash, reqid)
			currentP2PConn.Write(requestToByteSlice(rep))
			break
		}
	}
	for {
		req := readMsgNoSignature(currentP2PConn) // read for a PublicKey or a Root
		if len(req) == 0 {
			// empty message
			return
		}
		reqtype := req[4]
		reqid := binary.BigEndian.Uint32(req[0:4])
		if reqtype == 3 { // PublicKey
			rep := buildPubkeyReplyNoPubkey(reqid) // TODO dignature
			currentP2PConn.Write(requestToByteSlice(rep))
			break
		}
		if reqtype == 4 { // Root
			rep := buildRootReply(emptyStringHash, reqid)
			currentP2PConn.Write(requestToByteSlice(rep))
			break
		}
	}
	for {
		req := readMsgNoSignature(currentP2PConn) // read for a PublicKey or a Root
		if len(req) == 0 {
			// empty message
			return
		}
		reqtype := req[4]
		reqid := binary.BigEndian.Uint32(req[0:4])
		if reqtype == 3 { // PublicKey
			rep := buildPubkeyReplyNoPubkey(reqid) // TODO dignature
			currentP2PConn.Write(requestToByteSlice(rep))
			break
		}
		if reqtype == 4 { // Root
			rep := buildRootReply(emptyStringHash, reqid)
			currentP2PConn.Write(requestToByteSlice(rep))
			break
		}
	}
	// We put the block three times to process a pubkey, a NoOp, and a root at most. That's not optimal.
}
