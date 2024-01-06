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
	"strings"
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

func readMsg(conn net.Conn) []byte {
	if signaturemode && hasPubKey && peerHasKey {
		return readMsgWithSignature(conn)
	} else {
		return readMsgNoSignature(conn)
	}
}

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
	
	msgid := binary.BigEndian.Uint32(header[0:4])
	msgtype := header[4]
	length := binary.BigEndian.Uint16(header[5:7])
	content := make([]byte, length)
	conn.Read(content)
	res := append(header, content...)
	if(debugmode){
		fmt.Println("recus:")
		fmt.Println("Id: ", res[0:4])
		fmt.Println("type: ", res[4])
		fmt.Println("length: ", res[5:7])
		fmt.Println("body:",res[7:length])
	}
	displayError(res)
	fmt.Println(hex.EncodeToString(res))
	switch msgtype {
	case 0:
		// NoOp
		logProgress("Read NoOp message : skipping.")
		return readMsgNoSignature(conn)
	case 1:
		// Error
		logProgress("Read an Error : reading again.")
		return readMsgNoSignature(conn)
	case 2:
		// Hello
		rep := buildHelloReply(msgid)
		fmt.Println(hex.EncodeToString(helloToByteSlice(rep)))
		conn.Write(helloToByteSlice(rep))
		return readMsgNoSignature(conn)
	case 3:
		// PublicKey
		logProgress("Pubkey request received")
		rep := buildPubkeyReplyNoPubkey(msgid)
		if hasPubKey {
			rep = buildPubkeyReplyWithPubkey(pubkey, msgid)
		}
		conn.Write(requestToByteSlice(rep))
		fmt.Println(hex.EncodeToString(requestToByteSlice(rep)))
		logProgress("Provided pubkey")
		return readMsgNoSignature(conn)
	case 4:
		// Root
		logProgress("Root hash request received")
		rep := buildRootReply(emptyStringHash, msgid)
		if hasFiles {
			rep = buildRootReply(roothash, msgid)
		}
		conn.Write(requestToByteSlice(rep))
		fmt.Println(hex.EncodeToString(requestToByteSlice(rep)))
		logProgress("Provided roothash")
		return readMsgNoSignature(conn)
	case 5:
		// GetDatum
		// TODO
		break
	case 6:
		// NAT Traversal Request
		// TODO
		break
	default:
		break
	}
	return res
}

func readMsgWithSignature(conn net.Conn) []byte {
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
	msgid := binary.BigEndian.Uint32(header[0:4])
	msgtype := header[4]
	length := binary.BigEndian.Uint16(header[5:7])
	content := make([]byte, length)
	conn.Read(content)
	res := append(header, content...)
	displayError(res)
	signature := make([]byte, 64)
	conn.Read(signature)
	if !verify(res, signature, byteSliceToPubkey(peerpubkey)) {
		logProgress("Invalid signature : skipping")
		return readMsgWithSignature(conn)
	}
	if(debugmode){
		fmt.Println("recus:")
		fmt.Println("Id: ", res[0:4])
		fmt.Println("type: ", res[4])
		fmt.Println("length: ", res[5:7])
		fmt.Println("body:",res[7:length])
	}
	switch msgtype {
	case 0:
		// NoOp
		logProgress("Read NoOp message : skipping.")
		return readMsgWithSignature(conn)
	case 1:
		// Error
		logProgress("Read an Error : reading again.")
		return readMsgWithSignature(conn)
	case 2:
		// Hello
		rep := buildHelloReply(msgid)
		conn.Write(signByteSlice(helloToByteSlice(rep), privkey))
		return readMsgWithSignature(conn)
	case 3:
		// PublicKey
		logProgress("Pubkey request received")
		rep := buildPubkeyReplyNoPubkey(msgid)
		if hasPubKey {
			rep = buildPubkeyReplyWithPubkey(pubkey, msgid)
		}
		conn.Write(signByteSlice(requestToByteSlice(rep), privkey))
		return readMsgWithSignature(conn)
	case 4:
		// Root
		logProgress("Root hash request received")
		rep := buildRootReply(emptyStringHash, msgid)
		if hasFiles {
			rep = buildRootReply(roothash, msgid)
		}
		conn.Write(signByteSlice(requestToByteSlice(rep), privkey))
		fmt.Println(hex.EncodeToString(requestToByteSlice(rep)))
		logProgress("Provided roothash")
		return readMsgWithSignature(conn)
	case 5:
		// Datum
		// TODO
		break
	case 6:
		// NAT Traversal Request
		// TODO
		break
	default:
		break
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
	logProgress("Asking for hash : " + string(hex.EncodeToString(Hash))+"/n envoie de :")
	tmp := buildDatumRequest(Hash, 89)
	conn.Write(requestToByteSlice(tmp))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // we need the last read to timeout to tell we're actually done with the server
	//conn.Write(requestToByteSlice(tmp))                   // re-ask, after the empty read
	answer := readMsg(conn)
	displayError(answer)
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
		logProgress("un chunk de load")
		return createChunk(answer[40:], int(length-32)) //TODO faire un truc qui detecte la vraie longueur des données

	}
	if datatype == 1 {
		//big
		var bf []Node
		for i := 0; i < 32; i++ {
			bf = append(bf, downloadNode(answer[40+(i*32):40+((i+1)*32)], conn))
			if int(answer[41+((i+1)*32)]) == 0 {
				break
			}
		}
		return createBigFile(bf, len(bf))
	}
	if datatype == 2 {
		//directory
		n := createDirectory("")
		name := make([]byte, 32)
		h := make([]byte, 32)

		for i := 0; i < 16; i++ {
			name = answer[40+(i*32*2) : 40+((i+1)*32*2)]
			h = answer[40+((i+1)*32*2) : 40+((i+2)*32*2)]
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

func splitaddr(address string) ([]byte, uint16) {
	addr, portnb, _ := strings.Cut(address, ":")
	return []byte(addr), binary.BigEndian.Uint16([]byte(portnb))
}

func salute(name string) {
	req := buildHelloRequest(name, 153, 0)
	for i := 0; i < 5; i++ {
		if hasPubKey && signaturemode {
			currentP2PConn.Write(signByteSlice(helloToByteSlice(req), privkey))
		} else {
			currentP2PConn.Write(helloToByteSlice(req))
		}
		currentP2PConn.SetReadDeadline(time.Now().Add(time.Second * 5)) // accept a delay for pubkey or roothash
		rep := readMsg(currentP2PConn)                                  // TODO signature mode. We read all the replys and process them, until an empty message tells us we're done.
		if len(rep) != 0 {
			if hasPubKey && signaturemode {
				go keepaliveSignature(currentP2PConn)
			} else {
				go keepaliveSignature(currentP2PConn)
			}
			return
		}
	}
	// 5 unsuccessful tries
	logProgress("Failed to contact the peer after 5 tries. Issuing a NAT traversal request.")
	remote_addr := currentP2PConn.RemoteAddr().String()
	isIPV4 := strings.Count(remote_addr, ".") == 3
	addr, portnb := splitaddr(remote_addr)
	var natreq *P2PMsg
	if isIPV4 {
		natreq = buildNatTraversalRequestIPv4(addr, portnb)
	} else {
		natreq = buildNatTraversalReplyIPv6(addr, portnb)
	}
	if hasPubKey && signaturemode {
		conn.Write(signByteSlice(helloToByteSlice(req), privkey))
	} else {
		conn.Write(helloToByteSlice(req))
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 5)) // accept a delay for pubkey or roothash
	readMsg(conn)
	conn.Write(requestToByteSlice(natreq)) // server handles the traversal
	// now we just listen through our listener
	// in case of a Hello reception, we have to tell Hello AGAIN : TODO create a table to store this
	conn.SetReadDeadline(time.Time{}) // reset deadline
}
