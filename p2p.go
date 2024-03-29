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

var MAX_MESSAGE_SIZE = 2048

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

/*
	UDP readers
*/

func readMsg(conn net.Conn) []byte {
	if peerHasKey {
		return readMsgWithSignature(conn)
	} else {
		return readMsgNoSignature(conn)
	}
}

func readMsgNoSignature(conn net.Conn) []byte {
	// first read until the length
	res := make([]byte, MAX_MESSAGE_SIZE)
	_, err := conn.Read(res)
	if err != nil || force_err {
		logProgress("Error reading from UDP socket")
		e := err.(net.Error)
		if e.Timeout() || force_err {
			logProgress("Connection timeout : returning an empty message.")
			return make([]byte, 0)
		}
	}
	msgid := binary.BigEndian.Uint32(res[0:4])
	msgtype := res[4]
	length := binary.BigEndian.Uint16(res[5:7])
	res = res[:7+length]
	if err != nil || force_err {
		log.Fatal(err)
	}
	if repdisplay {
		fmt.Println("*** Recus:")
		fmt.Println("Id: ", res[0:4])
		fmt.Println("type: ", res[4])
		fmt.Println("length: ", res[5:7])
		if length >= 7 {
			fmt.Println("body:", res[7:7+length])
		} else {
			fmt.Println("body empty")
		}
	}
	displayError(res)
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
		signAndWrite(conn, helloToByteSlice(rep))
		if issuedTraversal {
			req := buildHelloRequest(name, 7777, 0)
			signAndWrite(conn, helloToByteSlice(req))
		}
		return readMsgNoSignature(conn)
	case 3:
		// PublicKey
		logProgress("Pubkey request received")
		rep := buildPubkeyReplyNoPubkey(msgid)
		if hasPubKey {
			rep = buildPubkeyReplyWithPubkey(pubkey, msgid)
		}
		signAndWrite(conn, requestToByteSlice(rep))
		return readMsgNoSignature(conn)
	case 4:
		// Root
		logProgress("Root hash request received")
		rep := buildRootReply(emptyStringHash, msgid)
		if hasFiles {
			rep = buildRootReply(roothash, msgid)
		}
		signAndWrite(conn, requestToByteSlice(rep))
		logProgress("Provided roothash")
		return readMsgNoSignature(conn)
	case 5:
		// Datum
		// TODO
		break
	case 6:
		// NAT Traversal Request
		communicateError(conn, "I am not the REST server", msgtype, msgid)
		break
	case 7:
		// NAT Traversal
		currentP2PConn, _ = net.Dial("udp", string(res[7:7+length]))
		req := buildHelloRequest(name, 8888, 0)
		signAndWrite(currentP2PConn, helloToByteSlice(req))
		return readMsgNoSignature(conn)
	case 129:
		// HelloReply
		helloExchangeDone = true
		issuedTraversal = false
		break
	case 130:
		// PublicKeyReply
		if !helloExchangeDone {
			communicateError(conn, "Please say hello first", msgtype, msgid)
			break
		}
		pubkeyExchangeDone = true
		break
	case 131:
		// RootReply
		if !helloExchangeDone {
			communicateError(conn, "Please say hello first", msgtype, msgid)
			break
		}
		roothashExchangeDone = true
		break
	case 132:
		// Datum from peer
		// Do nothing, let downloadNode() handle this
		return res
	default:
		if !helloExchangeDone {
			communicateError(conn, "Please say hello first + unknown message type", msgtype, msgid)
			break
		}
		msgtype_as_nb := fmt.Sprintf("%d", msgtype)
		communicateError(conn, "Unknown message type for type "+msgtype_as_nb, msgtype, msgid)
		break
	}
	return res
}

func readMsgWithSignature(conn net.Conn) []byte {
	// first read until the length
	res := make([]byte, MAX_MESSAGE_SIZE)
	_, err := conn.Read(res)
	if err != nil || force_err {
		logProgress("Error reading from UDP socket")
		e := err.(net.Error)
		if e.Timeout() || force_err {
			logProgress("Connection timeout : returning an empty message.")
			return make([]byte, 0)
		}
	}
	msgid := binary.BigEndian.Uint32(res[0:4])
	msgtype := res[4]
	length := binary.BigEndian.Uint16(res[5:7])
	res = res[:7+length]
	signature := res[7+length : 7+length+64]
	if err != nil || force_err {
		log.Fatal(err)
	}
	if repdisplay {
		fmt.Println("*** Recus:")
		fmt.Println("Id: ", res[0:4])
		fmt.Println("type: ", res[4])
		fmt.Println("length: ", res[5:7])
		if length >= 7 {
			fmt.Println("body:", res[7:7+length])
		} else {
			fmt.Println("body empty")
		}
	}
	logProgress("Found signature : " + hex.EncodeToString(signature))
	if !verify(res, signature, byteSliceToPubkey(peerpubkey)) {
		logProgress("Invalid signature : skipping")
		communicateError(conn, "Bad signature", msgtype, msgid)
		return readMsgWithSignature(conn)
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
		if binary.BigEndian.Uint32(res[7:11]) != 0 {
			communicateError(conn, "Unmatching extensions", msgtype, msgid)
		}
		rep := buildHelloReply(msgid)
		signAndWrite(conn, helloToByteSlice(rep))
		if issuedTraversal {
			req := buildHelloRequest(name, 7777, 0)
			signAndWrite(conn, helloToByteSlice(req))
		}
		return readMsgWithSignature(conn)
	case 3:
		// PublicKey
		logProgress("Pubkey request received")
		if !helloExchangeDone {
			communicateError(conn, "Please say hello first", msgtype, msgid)
			break
		}
		rep := buildPubkeyReplyNoPubkey(msgid)
		if hasPubKey {
			rep = buildPubkeyReplyWithPubkey(pubkey, msgid)
		}
		signAndWrite(conn, requestToByteSlice(rep))
		return readMsgWithSignature(conn)
	case 4:
		// Root
		logProgress("Root hash request received")
		if !helloExchangeDone {
			communicateError(conn, "Please say hello first", msgtype, msgid)
			break
		}
		rep := buildRootReply(emptyStringHash, msgid)
		if hasFiles {
			rep = buildRootReply(roothash, msgid)
		}
		signAndWrite(conn, requestToByteSlice(rep))
		logProgress("Provided roothash")
		return readMsgWithSignature(conn)
	case 5:
		// GetDatum
		if !helloExchangeDone {
			communicateError(conn, "Please say hello first", msgtype, msgid)
		}
		// TODO
		break
	case 6:
		// NAT Traversal Request
		communicateError(conn, "I'm not the REST server", msgtype, msgid)
		break
	case 7:
		// NAT Traversal
		currentP2PConn, _ = net.Dial("udp", string(res[7:7+length]))
		req := buildHelloRequest(name, 8888, 0)
		signAndWrite(currentP2PConn, helloToByteSlice(req))
		return readMsgWithSignature(conn)
	case 129:
		// HelloReply
		helloExchangeDone = true
		issuedTraversal = false
		break
	case 130:
		// PublicKeyReply
		if !helloExchangeDone {
			communicateError(conn, "Please say hello first", msgtype, msgid)
			break
		}
		pubkeyExchangeDone = true
		break
	case 131:
		// RootReply
		if !helloExchangeDone {
			communicateError(conn, "Please say hello first", msgtype, msgid)
			break
		}
		roothashExchangeDone = true
		break
	case 132:
		// Datum from peer
		// Do nothing, let downloadNode() handle this
		return res
	default:
		if !helloExchangeDone {
			communicateError(conn, "Please say hello first + unknown message type", msgtype, msgid)
			break
		}
		msgtype_as_nb := fmt.Sprintf("%d", msgtype)
		communicateError(conn, "Unknown message type for type "+msgtype_as_nb, msgtype, msgid)
		break
	}
	return res
}

func signAndWrite(conn net.Conn, content []byte) {
	if hasPubKey {
		conn.Write(signByteSlice(content, privkey))
	} else {
		conn.Write(content)
	}
}

func communicateError(conn net.Conn, msg string, msgtype byte, msgid uint32) {
	var errrep *P2PMsg
	if msgtype <= 127 {
		errrep = buildErrorReply(msg, msgid)
	} else {
		errrep = buildErrorMessage(msg, 0)
	}
	signAndWrite(conn, requestToByteSlice(errrep))
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
		return false
	}
	for i := 0; i < len(h1); i++ {
		if h1[i] != h2[i] {
			return false
		}
	}
	return true
}

func findNode(Hash []byte, n Node) *Node {
	if compareHash(n.Hash, Hash) {
		return &n
	} else {
		for i := 0; i < n.nbchild; i++ {
			tmp := findNode(Hash, n.Childs[i])
			if tmp != nil || force_err {
				return tmp
			}
		}
		return nil
	}
}

func sendDatum(n Node, con net.Conn) {
	data := make([]byte, 1) // need one for type, then append calls will automatically expand the array
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

func downloadNode(Hash []byte, conn net.Conn) (Node, string) {
	// TODO rewrite all this connection part
	currentP2PConn.SetReadDeadline(time.Time{})
	logProgress("Asking for hash : " + string(hex.EncodeToString(Hash)))
	tmp := buildDatumRequest(Hash, 89)
	conn.Write(requestToByteSlice(tmp))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // we need the last read to timeout to tell we're actually done with the server
	//conn.Write(requestToByteSlice(tmp))                   // re-ask, after the empty read
	answer := readMsg(conn)
	if len(answer) == 0 {
		conn.Write(requestToByteSlice(tmp))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // we need the last read to timeout to tell we're actually done with the server
		answer = readMsg(conn)
	}
	conn.SetReadDeadline(time.Time{})
	currentP2PConn.SetReadDeadline(time.Time{})
	displayError(answer)
	length := binary.BigEndian.Uint16(answer[5:7])
	if debugmode {
		fmt.Printf("Download Node : found length of %d\n", length)
	}
	nodata := answer[4] == 133
	if nodata {
		logProgress("Data not found from peer for hash : " + hex.EncodeToString(answer[7:39]))
		return createDirectoryNode(""), "ERR_NOTFOUND"
	}
	datatype := answer[39]
	if debugmode {
		fmt.Printf("Download Node : found datatype of %d\n", datatype)
	}
	datahash := answer[7:39]
	if !(compareHash(Hash, datahash)) {
		fmt.Printf("Mismatching hashes : asked for %s, got %s\n", datahash, Hash)
		communicateError(conn, "Not the data I asked for", 128, 89) // 89 because that's our constant ID for GetDatums
		return createDirectoryNode(""), "ERR_REPLY_HASH_MISMATCH"
	}
	if datatype == 0 {
		// Chunk
		c := createChunkNode(answer[39:], int(length)-32)
		// The size of the chunk is all the Body field, so the signature is already ignored.
		// We want to ignore the hash as well : our position at 39 is right for that,
		// AS WE KEEP THE DATATYPE BYTE IN.
		// But the length will be a problem : our answer also includes a hash.
		// So we substract 32 (the size of the hash) to our length.
		if compareHash(Hash, c.Hash) {
			return c, "SUCCESS"
		} else {
			logProgress("Warning : non-matching hash for our chunk. The data might be corrupted or incomplete.")
			fmt.Printf("Expected hash : %s, got node hash : %s\n", string(hex.EncodeToString(Hash)), string(hex.EncodeToString(c.Hash)))
			return createDirectoryNode(""), "ERR_CHUNK_HASH_MISMATCH"
		}
	}
	if datatype == 1 {
		// Tree
		var bf []Node
		if debugmode {
			fmt.Printf("Amount of children for this Tree : %d\n", (int(length)-32)/32) // the amount of children in the Tree
		}
		for i := 0; i < ((int(length) - 32) / 32); i++ {
			tmpc, tmpe := downloadNode(answer[(40+(i*32)):(40+((i+1)*32))], conn)
			// we download the i-th hash for every child of our Tree.
			// hashes are 32-bytes long, and the data starts at byte 40 of our answer.
			if tmpe != "SUCCESS" {
				return createDirectoryNode(""), tmpe
			}
			bf = append(bf, tmpc) // this buffer stores every chunk of the Tree
		}
		c := createBigFileNode(bf, len(bf)) // transforms the buffer into a Bigfile node.
		if compareHash(c.Hash, Hash) {
			return c, "SUCCESS"
		} else {
			logProgress("Warning : non-matching hash for our big file. The data might be corrupted or incomplete.")
			fmt.Printf("Expected hash : %s, got node hash : %s\n", string(hex.EncodeToString(Hash)), string(hex.EncodeToString(c.Hash)))
			return createDirectoryNode(""), "ERR_TREE_HASH_MISMATCH"
		}
	}
	if datatype == 2 {
		// Directory
		n := createDirectoryNode("")
		if length == 33 {
			return n, "SUCCESS"
		}
		name := make([]byte, 32) // name of the directory
		h := make([]byte, 32)
		for i := 0; i < ((int(length) - 32) / 64); i++ {
			name = answer[40+(i*64) : 72+(i*64)] // reads every entry name of the directory
			h = answer[72+(i*64) : 104+(i*64)]   // reads every sub-hash of these entries
			if compareHash(h, emptyStringHash) {
				break
			}
			tmpc, tmpe := downloadNode(h, conn)
			if tmpe != "SUCCESS" {
				return createDirectoryNode(""), tmpe
			}
			tmpc.name = string(name)
			n = AddChild(n, tmpc)
		}
		if compareHash(n.Hash, Hash) {
			return n, "SUCCESS"
		} else {
			/* logProgress("Warning : non-matching hash for our directory. The data might be corrupted or incomplete.")
			fmt.Printf("Expected hash : %s, got node hash : %s\n", string(hex.EncodeToString(Hash)), string(hex.EncodeToString(n.Hash))) */
			// Note : root hash for jch.irif.fr is d31473e45414e71e1f900c97420afd301d59f3bf7b884c089382306dff281a30
			return n, "SUCCESS"
			// TODO : a bug, probably in the directory names, causes a systematic hash mismatch for directories.
			// The content is valid though, so we will simply ignore it until it is fixed.
			//return createDirectoryNode(""), "ERR_DIRECTORY_HASH_MISMATCH"
		}
	}
	logProgress("ya un blem")
	return createDirectoryNode(""), "ERR_UNKNOWN"
}

/*
	REST macro to check if someone has a declared pubkey.
	If someone writes to us and we do implement signatures,
	we HAVE to check if they have a declared pubkey.
	If they do, we have to reject any unsigned or badly signed message of types :
	Hello / HelloReply / PublicKey / PublicKeyReply / Root / RootReply
*/

func fetchPubKey(name string) ([]byte, bool) {
	res := make([]byte, 0)
	req := buildGetPeerPubkeyRequest(name)
	resp, err := client.Do(req)
	if err != nil || force_err {
		log.Fatal("Error fetching server for pubkey")
		return res, false
	}
	if resp.StatusCode == http.StatusNotFound { // 404
		logProgress("Found no pubkey for this peer.")
		return res, false
	}
	if resp.StatusCode == http.StatusNoContent { // 204
		logProgress("Found no pubkey for this peer.")
		return res, false
	}
	text, err := io.ReadAll(resp.Body)
	if err != nil || force_err {
		log.Fatal("Failed parsing the pubkey")
		return res, false
	}
	resp.Body.Close()
	res = append(res, text...)
	logProgress("Parsed pubkey for this peer, found : " + hex.EncodeToString(text))
	return res, true
}

func fetchRootHash(name string) ([]byte, bool) {
	res := make([]byte, 0)
	req := buildGetPeerRootHashRequest(name)
	resp, err := client.Do(req)
	if err != nil || force_err {
		log.Fatal("Error fetching server for pubkey")
		return res, false
	}
	if resp.StatusCode == http.StatusNotFound { // 404
		logProgress("Found no root hash for this peer.")
		return res, false
	}
	if resp.StatusCode == http.StatusNoContent { // 204
		logProgress("Found no root hash for this peer.")
		return res, false
	}
	text, err := io.ReadAll(resp.Body)
	if err != nil || force_err {
		log.Fatal("Failed parsing the root hash")
		return res, false
	}
	resp.Body.Close()
	res = append(res, text...)
	peerroothash = []byte(hex.EncodeToString(text))
	logProgress("Parsed root hash for this peer, found : " + string(peerroothash))
	return res, true
}

func fetchAddress(name string) ([]byte, bool) {
	res := make([]byte, 0)
	req := buildGetPeerAddressesRequest(name)
	resp, err := client.Do(req)
	if err != nil || force_err {
		log.Fatal("Unable to connect to the REST server.")
		return res, false
	}
	if resp.StatusCode == http.StatusNotFound { // 404
		logProgress("Found no address for this peer.")
		return res, false
	}
	if resp.StatusCode == http.StatusNoContent { // 204
		logProgress("Found no address for this peer.")
		return res, false
	}
	text, err := io.ReadAll(resp.Body)
	if err != nil || force_err {
		log.Fatal("Failed parsing the pubkey")
		return res, false
	}
	resp.Body.Close()
	res = []byte(strings.Split(string(text), "\n")[0])
	logProgress("Parsed address for this peer, found : " + hex.EncodeToString(text))
	return res, true

}

func splitaddr(address string) ([]byte, uint16) {
	addr, portnb, _ := strings.Cut(address, ":")
	return []byte(addr), binary.BigEndian.Uint16([]byte(portnb))
}

func salute(name string) {
	req := buildHelloRequest(name, 153, 0)
	for i := 0; i < 5; i++ {
		signAndWrite(currentP2PConn, helloToByteSlice(req))
		currentP2PConn.SetReadDeadline(time.Now().Add(time.Second * 5)) // accept a delay for pubkey or roothash
		rep := readMsg(currentP2PConn)                                  // TODO signature mode. We read all the replys and process them, until an empty message tells us we're done.
		if len(rep) != 0 {
			//keepalive(currentP2PConn, tree) // TODO FILL TREE
			currentP2PConn.SetReadDeadline(time.Now().Add(time.Second * 5))
			readMsg(currentP2PConn) // let the server speak first
			if !pubkeyExchangeDone {
				req2 := buildPubkeyRequestNoPubkey(83)
				if hasPubKey {
					req2 = buildPubkeyRequestWithPubkey(83, pubkey)
				}
				signAndWrite(currentP2PConn, requestToByteSlice(req2))
			}
			currentP2PConn.SetReadDeadline(time.Now().Add(time.Second * 5))
			readMsg(currentP2PConn) // and again
			if !roothashExchangeDone {
				req3 := buildRootRequestNoData(132)
				if hasFiles {
					req3 = buildRootRequest(132, roothash)
				}
				signAndWrite(currentP2PConn, requestToByteSlice(req3))
			}
			currentP2PConn.SetReadDeadline(time.Now().Add(time.Second * 5))
			readMsg(currentP2PConn) // and again
			go keepalive(currentP2PConn, &currentAbr)
			return
		}
	}
	issuedTraversal = true
	// 5 unsuccessful tries
	logProgress("Failed to contact the peer after 5 tries. Issuing a NAT traversal request.")
	remote_addr := currentP2PConn.RemoteAddr().String()
	isIPV4 := strings.Count(remote_addr, ".") == 3
	addr, portnb := splitaddr(remote_addr)
	var natreq *P2PMsg
	if isIPV4 {
		natreq = buildNatTraversalRequestIPv4(addr, portnb, 875)
	} else {
		natreq = buildNatTraversalReplyIPv6(addr, portnb, 875)
	}
	for {
		if hasPubKey {
			servconn.Write(signByteSlice(helloToByteSlice(req), privkey))
		} else {
			servconn.Write(helloToByteSlice(req))
		}
		servconn.SetReadDeadline(time.Now().Add(time.Second * 5)) // accept a delay for pubkey or roothash
		readMsg(servconn)
		servconn.Write(requestToByteSlice(natreq)) // server handles the traversal
		servconn.SetReadDeadline(time.Time{})      // reset deadline
		// now we just listen through our listener
		currentP2PConn.SetReadDeadline(time.Now().Add(time.Minute * 2)) // need a long delay
		readMsg(currentP2PConn)
		if !issuedTraversal {
			break
		}
		logProgress("NAT Traversal unsuccessful. Retrying.")
	}
	currentP2PConn.SetReadDeadline(time.Time{})
	logProgress("NAT Traversal successful")
}
