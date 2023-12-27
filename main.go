package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

/*
	GLOBAL VARS
*/

var hasPubKey = false
var hasFiles = false

var pubkey = make([]byte, 64)
var roothash = make([]byte, 32)

var emptyStringHash = make([]byte, 32) // TODO

var serv_addr = "jch.irif.fr:8443"
var serv_url = "https://jch.irif.fr:8443"

var debugmode = true  // TODO
var force_err = false // this forces error-handling routines to happen, even if nothing failed

func displayError(packet []byte) {
	if debugmode && len(packet) >= 5 && packet[4] == 128 {
		fmt.Println("ErrorReply from server : " + string(packet[7:]))
	}
}

func logProgress(msg string) {
	if debugmode {
		fmt.Println(msg)
	}
}

/*
	REST SECTION
*/

/*
	REST request builder
*/

func buildGetPeersRequest() *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func buildGetPeerAddressesRequest(peer_name string) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers/"+peer_name+"/addresses", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func buildGetPeerPubkeyRequest(peer_name string) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers/"+peer_name+"/key", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func buildGetPeerRootHashRequest(peer_name string) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers/"+peer_name+"/root", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

/*
	REST request processors
*/

func aux_list_printer(body io.ReadCloser) {
	text, err := io.ReadAll(body)
	if (err != nil && debugmode) || force_err {
		log.Fatal("readResponseBody: ", err)
		return
	}
	for _, line := range strings.Split(string(text[:]), "\n") {
		if line != "" { // remove ending newline
			fmt.Println("[REQBODY] " + line)
		}
	}
}

func aux_hash_printer(body io.ReadCloser) {
	text, err := io.ReadAll(body)
	if (err != nil && debugmode) || force_err {
		log.Fatal("readResponseBody: ", err)
		return
	}
	hexHash := hex.EncodeToString(text)
	fmt.Println(hexHash)
}

func processGetPeersResponse(resp *http.Response) {
	aux_list_printer(resp.Body)
	resp.Body.Close()
}

func processGetPeerAddressesResponse(resp *http.Response) {
	if resp.StatusCode == http.StatusNotFound { // 404
		fmt.Println(resp.Status)
	}
	aux_list_printer(resp.Body)
	resp.Body.Close()
}

func processGetPeerKeyResponse(resp *http.Response) {
	if resp.StatusCode == http.StatusNotFound { // 404
		fmt.Println(resp.Status)
	}
	if resp.StatusCode == http.StatusNoContent { // 204
		fmt.Println(resp.Status)
	}
	aux_hash_printer(resp.Body)
	resp.Body.Close()
}

func processGetPeerRootHashResponse(resp *http.Response) {
	if resp.StatusCode == http.StatusNotFound { // 404
		fmt.Println(resp.Status)
	}
	if resp.StatusCode == http.StatusNoContent { // 204
		fmt.Println(resp.Status)
	}
	aux_hash_printer(resp.Body)
	resp.Body.Close()
}

/*
	REST register module
*/

func registerPeer(conn net.Conn, name string, hasPubkey bool, hasFiles bool, pubkey []byte, roothash []byte) {
	// dial server
	req := buildHelloRequest(name, 23, 0)
	if hasPubkey {
		// sign the Hello
	}
	s := helloToByteSlice(req)
	conn.Write(s)
	logProgress("Handshake initiated")
	rep := readMsgNoSignature(conn)
	logProgress("Handshake response received")
	id := binary.BigEndian.Uint32(rep[0:4])
	if id != 23 {
		fmt.Printf("Warning : unmatching ID in handshake response, expected 23 and got %d\n", id)
	}
	pubkeyreq := readMsgNoSignature(conn)
	pubkeyid := binary.BigEndian.Uint32(pubkeyreq[0:4])
	logProgress("Pubkey request received")
	req2 := buildPubkeyReplyNoPubkey()
	if hasPubkey {
		req2 = buildPubkeyReplyWithPubkey(pubkey)
	}
	setMsgId(req2, pubkeyid)
	conn.Write(requestToByteSlice(req2))
	logProgress("Provided server with pubkey")
	_ = readMsgNoSignature(conn)
	logProgress("Root hash request received")
	req3 := buildRootReply(emptyStringHash)
	if hasFiles {
		req3 = buildRootReply(roothash)
	}
	setMsgId(req3, 0)
	conn.Write(requestToByteSlice(req3))
	logProgress("Provided server with roothash")
	// maintain connection through goroutine until interruption
}

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
	File manipulation primitives
*/

func filename(filepath string) string {

	i := strings.LastIndex(filepath, "/")
	if i == -1 {
		return filepath
	} else {
		return filepath[i:]
	}
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
	if len(bf) == 0 {
		if i > 1 {
			ret := createBigFile(c, i)
			ret.name = filename(filepath)
			return ret
		} else {
			c[0].name = filename(filepath)
			return c[0]
		}

	}
	bf[j-1] = createBigFile(c, i)
	var bbf []Node
	for len(bf) > 32 {
		for a := 0; a < len(bf); a = a + 32 {
			bbf = append(bbf, createBigFile(c[a:32], 32))
		}
		bf = nil
		copy(bf, bbf) //copie dans bf bbf
	}
	if len(bf) >= 2 {
		ret := createBigFile(bf, len(bf))
		ret.name = filename(filepath)
		return ret
	} else {
		bf[0].name = filename(filepath)
		return bf[0]
	}

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
		Childs:    make([]Node, 32),
	}
	for i := 1; i < nb; i++ {
		s = append(s, ch[i].Hash...)
		n.Childs[i] = ch[i]
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

/**
ne sert qu'a ajouter des node a un directory, si ce n'est pas un directory ne fait rien
*/
func AddChild(p Node, c Node) {
	if p.Directory && p.nbchild < 16 {
		c.Parent = &p
		p.Childs[p.nbchild] = c
		h := sha256.New()
		s := []byte{}
		for i := 0; i < p.nbchild; i++ {
			s = append(s, p.Childs[i].Hash...)

		}
		h.Write(s)
		p.Hash = h.Sum(nil)
	}
}
func createDirectory(n string) Node {
	return Node{
		Directory: true,
		Big:       false,
		nbchild:   0,
		Parent:    nil,
		name:      n,
	}
}
func PrintTree(r Node, pre string) {
	if r.Directory {
		for i := 0; i < r.nbchild; i++ {
			PrintTree(r.Childs[i], pre+"  ")
		}
	}
	if r.Big {
		fmt.Println(pre + r.name)
		for i := 0; i < r.nbchild; i++ {
			PrintTree(r.Childs[i], pre+"  ")
		}
	} else {
		fmt.Println(pre + "chunk")
	}
}
func WriteFile(current Node, index int, f os.File) int {
	if current.Big {
		tmp := index
		for i := 0; i < current.nbchild; i++ {
			tmp = tmp + WriteFile(current.Childs[i], tmp, f)
		}
		return index + (1024 * current.nbchild)
	} else {
		f.WriteAt(current.Data, int64(index))
		return index + 1024
	}
	// return -1 -> unreachable code
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

/*
	Request builders for peer-to-peer communication
*/

func buildNoOpRequestOfGivenSize(size uint16) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, size)
	return &P2PMsg{
		Length: buf,
		Body:   make([]byte, size),
	}
}

func buildNoOpRequest() *P2PMsg {
	return buildNoOpRequestOfGivenSize(0)
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

func buildErrorMessage(msg string) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	return &P2PMsg{
		Type:   1,
		Length: buf,
		Body:   []byte(msg),
	}
}

func buildErrorReply(msg string) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	return &P2PMsg{
		Type:   128,
		Length: buf,
		Body:   []byte(msg),
	}
}

func buildPubkeyReplyNoPubkey() *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(0))
	return &P2PMsg{
		Type:   130,
		Length: buf,
	}
}

func buildPubkeyReplyWithPubkey(pubkey []byte) *P2PMsg { // pubkey is 64 bytes long
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(64))
	return &P2PMsg{
		Type:   130,
		Length: buf,
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

func buildRootReply(roothash []byte) *P2PMsg { // hash is 32 bytes long
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(32))
	return &P2PMsg{
		Type:   131,
		Length: buf,
		Body:   roothash,
	}
}

func buildDatumRequest(datahash []byte) *P2PMsg { // 32 bytes long
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(32))
	return &P2PMsg{
		Type:   5,
		Length: buf,
		Body:   datahash,
	}
}

/*
	Setters for additional info throughout the requests
*/

func setHelloId(exchange *HelloExchange, id uint32) {
	exchange.Id = make([]byte, 4)
	binary.BigEndian.PutUint32(exchange.Id, id)
}

func setDatumId(datum *Datum, id uint32) {
	datum.Id = make([]byte, 4)
	binary.BigEndian.PutUint32(datum.Id, id)
}

func setMsgId(msg *P2PMsg, id uint32) {
	msg.Id = make([]byte, 4)
	binary.BigEndian.PutUint32(msg.Id, id)
}

func setHelloExtensions(exchange *HelloExchange, n uint32) {
	exchange.Extensions = make([]byte, 4)
	binary.BigEndian.PutUint32(exchange.Extensions, n)
}

/* func addHelloSignature(exchange *HelloExchange) {
	exchange.Signature = blablabla // TODO
} */

/* func addDatumSignature(datum *Datum) {
	datum.Signature = blablabla // TODO
} */

/* func addMsgSignature(msg *P2PMsg) {
	msg.Signature = blablabla // TODO
} */

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
	l, _ := strconv.Atoi(string(req.Length)) // TODO err handling
	res := make([]byte, 7+l+len(req.Signature))
	for i := 0; i < 4; i++ {
		res[i] = req.Id[i]
	}
	res[4] = req.Type
	for i := 0; i < 2; i++ {
		res[5+i] = req.Length[i]
	}
	for i := 0; i < l; i++ {
		res[7+i] = req.Body[i]
	}
	for i := 0; i < len(req.Signature); i++ {
		res[7+l+i] = req.Signature[i]
	}
	return res
}

/*
	Passive UDP listener
*/

func UDPListener() {
	// TODO
	// upon reception of a GetDatum, reply to the peer with arborescence
}

/*
	UDP readers
*/

func readMsgNoSignature(conn net.Conn) []byte {
	// first read until the length
	header := make([]byte, 7)
	conn.Read(header)
	length := binary.BigEndian.Uint16(header[5:7])
	content := make([]byte, length)
	conn.Read(content)
	res := append(header, content...)
	displayError(res)
	return res
}

func readMsgWithSignature(conn net.Conn) []byte {
	// first read until the length
	header := make([]byte, 7)
	conn.Read(header)
	length := binary.BigEndian.Uint16(header[5:7])
	content := make([]byte, length)
	conn.Read(content)
	signature := make([]byte, 64)
	conn.Read(signature)
	res := append(append(header, content...), signature...)
	displayError(res)
	return res
}

/*
	CLI SECTION
*/

func rest_main(client *http.Client, listPeersFlag bool, getPeerAddressesFlag string, getPeerKeyFlag string, getPeerRootHashFlag string, helpFlag bool, exitFlag bool) {
	// REST CLI
	if exitFlag {
		os.Exit(0)
	}
	if helpFlag {
		fmt.Println("Usage for REST mode :")
		fmt.Println("Several commands can be used, the help command is used by default if none is provided.")
		fmt.Println("Commands :")
		// create key command
		fmt.Println("debugon : enables error display (disabled by default)")
		fmt.Println("debugoff : disables error display (disabled by default)")
		fmt.Println("exit : quits the program")
		// fetchStorage command (updates our hash)
		fmt.Println("getAddresses [peer_name] : fetches and displays a list of known addresses for a given peer, from the server.")
		fmt.Println("getKey [peer_name] : fetches and displays the public key of a given peer, from the server.")
		fmt.Println("getRootHash [peer_name] : fetches and displays the hash of the root of a given peer, from the server.")
		fmt.Println("help : displays this help and exits. Default behavior.")
		fmt.Println("list : fetches and displays a list of known peers from the server.")
		fmt.Println("register : registers ourself to the REST server.")
		fmt.Println("switchmode : switches into peer-to-peer mode")
		return
	}
	if listPeersFlag {
		req := buildGetPeersRequest()
		if req != nil {
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal("http.NewRequest: ", err)
			}
			processGetPeersResponse(resp)
		}
	}
	if getPeerAddressesFlag != "" {
		req := buildGetPeerAddressesRequest(getPeerAddressesFlag)
		if req != nil {
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal("http.NewRequest: ", err)
			}
			processGetPeerAddressesResponse(resp)
		}
	}
	if getPeerKeyFlag != "" {
		req := buildGetPeerPubkeyRequest(getPeerKeyFlag)
		if req != nil {
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal("http.NewRequest: ", err)
			}
			processGetPeerKeyResponse(resp)
		}
	}
	if getPeerRootHashFlag != "" {
		req := buildGetPeerRootHashRequest(getPeerRootHashFlag)
		if req != nil {
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal("http.NewRequest: ", err)
			}
			processGetPeerRootHashResponse(resp)
		}
	}
	if exitFlag {
		// todo disconnect client
		return
	}
}

func udp_main(helpFlag bool, exitFlag bool, name string) {
	// P2P CLI (TODO)

	// s := ""

	// h := sha256.New()

	// h.Write([]byte(s))

	// bs := h.Sum(nil)
	// h.Write(bs)
	// ba := h.Sum(nil)

	// fmt.Println(s)
	// fmt.Printf("%x\n", bs)
	// fmt.Printf("%x\n", ba)
	if exitFlag {
		os.Exit(0)
	}
	if helpFlag {
		fmt.Println("Usage for P2P (UDP) mode :")
		fmt.Println("Several commands can be used, the help command is used by default if none is provided.")
		fmt.Println("Commands :")
		fmt.Println("exit : quits the program")
		fmt.Println("help : displays this help and exits. Default behavior.")
		fmt.Println("switchmode : switches into REST mode")
		return
	} else {
		a := createFile("projet.pdf")
		PrintTree(a, "")
	}
}

func main() { // CLI Merge from REST and P2P (UDP)
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}
	conn, err := net.Dial("udp", serv_addr)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	name := "NoName"
	RESTMode := true
	listPeersFlag := false
	getPeerAddressesFlag := ""
	getPeerKeyFlag := ""
	getPeerRootHashFlag := ""
	helpFlag := false
	exitFlag := false
	//name := "" // client name for registration (TODO)
	reader := bufio.NewReader(os.Stdin)
	for {
		commandWord := ""
		secondWord := ""
		thirdWord := ""
		fourthWord := ""
		fifthWord := ""
		fmt.Print(">")
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		line = strings.ReplaceAll(line, "\n", "") // remove trailing newline
		parts := strings.Split(line, " ")
		commandWord = parts[0]
		if len(parts) > 1 {
			secondWord = parts[1]
			if len(parts) > 2 {
				thirdWord = parts[2]
				if len(parts) > 3 {
					fourthWord = parts[3]
					if len(parts) > 4 {
						fifthWord = parts[4]
					}
				}

			}
		}
		fmt.Println()
		if RESTMode {
			// client REST mode
			listPeersFlag = false
			getPeerAddressesFlag = ""
			getPeerKeyFlag = ""
			getPeerRootHashFlag = ""
			exitFlag = false
			helpFlag = false
			// read user input
			switch commandWord {
			case "debugon":
				debugmode = true
				break
			case "debugoff":
				debugmode = false
				break
			case "list":
				listPeersFlag = true
				break
			case "getAddresses":
				getPeerAddressesFlag = secondWord
				break
			case "getKey":
				getPeerKeyFlag = secondWord
				break
			case "getRootHash":
				getPeerRootHashFlag = secondWord
				break
			case "register":
				registerPeer(conn, name, hasPubKey, hasFiles, pubkey, roothash)
				break
			case "setName":
				name = secondWord
				break
			case "switchmode":
				RESTMode = false
				break
			case "exit":
				exitFlag = true
				break
			default:
				helpFlag = true
				break
			}
			// TODO : allow a list of peers instead of a single one here
			rest_main(client, listPeersFlag, getPeerAddressesFlag, getPeerKeyFlag, getPeerRootHashFlag, helpFlag, exitFlag)
		} else {
			//latest_req_time := 0 // current time here, used for keepalives
			// client P2P mode
			// read user input
			switch commandWord {
			case "connect":
				break
			case "debugon":
				debugmode = true
				break
			case "debugoff":
				debugmode = false
				break
			case "disconnect":
				RESTMode = true
				break
			case "exit":
				exitFlag = true
				break
			case "op":
				// need precise parsing of the actual operation here through the secondword, or add additional prompts
				// in case of connection : maintain the connection with a goroutine
			default:
				helpFlag = true
				break
			}
			udp_main(helpFlag, exitFlag, "no_name")
		}
		if debugmode {
			fmt.Println("Operation {" + commandWord + " " + secondWord + " " + thirdWord + " " + fourthWord + " " + fifthWord + "} done.")
		}
		fmt.Println()
	}
}

/*
	UNUSED FUNCTIONS FOR NOW
	(We do not currently store data and don't expect peers to contact us)
	(We cannot properly contact other peers for now)
	(We do not support NAT traversal for now)
*/

func buildHelloReply(name string) *HelloExchange {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(name)+4)) // +4 for extensions
	return &HelloExchange{
		Type:   129,
		Length: buf,
		Name:   []byte(name),
	}
}

func buildRootRequest(roothash []byte) *P2PMsg { // hash is 32 bytes long
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(32))
	return &P2PMsg{
		Type:   4,
		Length: buf,
		Body:   roothash,
	}
}

func buildPubkeyRequestNoPubkey() *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(0))
	return &P2PMsg{
		Type:   3,
		Length: buf,
	}
}

func buildPubkeyRequestWithPubkey(pubkey []byte) *P2PMsg { // pubkey is 64 bytes long
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(64))
	return &P2PMsg{
		Type:   3,
		Length: buf,
		Body:   pubkey,
	}
}

func buildRootRequestNoData() *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(32))
	return &P2PMsg{
		Type:   4,
		Length: buf,
		Body:   emptyStringHash,
	}
}

/* func buildDatumReply(value []byte) *Datum { // variable length, assumed storable on 2 bytes
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(value)+32)) // add the hash length to the total
	return &Datum{
		Type:   132,
		Length: buf,
		Hash:   hash(value), // 32 bytes
		Value:  value,
	}
} */

/* func buildNatTraversalRequestIPv4(ipv4addr []byte, port uint16) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(6)) // ipv4 addr are on 4 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return &P2PMsg{
		Type:   6,
		Length: buf,
		Body:   ipv4addr + buf2,
	}
} */

/* func buildNatTraversalRequestIPv6(ipv6addr []byte, port uint16) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(18)) // ipv6 addr are on 16 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return &P2PMsg{
		Type:   6,
		Length: buf,
		Body:   ipv6addr + buf2,
	}
} */

/* func buildNatTraversalReplyIPv4(ipv4addr []byte, port uint16) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(6)) // ipv4 addr are on 4 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return &P2PMsg{
		Type:   7,
		Length: buf,
		Body:   ipv4addr + buf2,
	}
} */

/* func buildNatTraversalReplyIPv6(ipv6addr []byte, port uint16) *P2PMsg {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(18)) // ipv6 addr are on 16 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return &P2PMsg{
		Type:   7,
		Length: buf,
		Body:   ipv6addr + buf2,
	}
} */
