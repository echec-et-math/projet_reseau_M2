package src

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
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
	Childs    []Node
	Hash      []byte //the hash of the node
	Data      []byte
	name		string//for dir and the root of big file
}
func filename(filepath string) string{

	i:=strings.LastIndex(filepath,"/")
	if(i==-1){
		return filepath
	}else{
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
	if(len(bf)==0){
		if(i>1){
			ret:=createBigFile(c, i)
			ret.name=filename(filepath)
			return ret
		}else{
			c[0].name=filename(filepath);
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
	if len(bf)>=2{
		ret:=createBigFile(bf, len(bf))
		ret.name=filename(filepath)
		return ret
	}else{
		bf[0].name=filename(filepath);
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
		Childs: make([]Node,32),
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
	if(p.Directory && p.nbchild<16){
		c.Parent=&p;
		p.Childs[p.nbchild]=c;
		h := sha256.New()
		s := []byte{}
		for i:=0;i<p.nbchild;i++{
			s = append(s, p.Childs[i].Hash...)

		}
		h.Write(s);
		p.Hash=h.Sum(nil);
	}
}
func createDirectory(n string)Node{
	return Node{
		Directory:true,
		Big:false,
		nbchild: 0,
		Parent : nil,
		name: n,
	}
}
func PrintTree(r Node, pre string){
	if(r.Directory){
		for i:=0; i< r.nbchild;i++{
			PrintTree(r.Childs[i],pre+"  ");
		}
	}
	if(r.Big){
		fmt.Println(pre+r.name);
		for i:=0; i< r.nbchild;i++{
			PrintTree(r.Childs[i],pre+"  ");
		}
	}else{
		fmt.Println(pre+"chunk");
	}
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

/* func buildNatTraversalRequestIPv4(ipv4addr []byte, port uint16) *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(6)) // ipv4 addr are on 4 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, port)
	return &P2PRequest{
		Type:   6,
		Length: buf,
		Body:   ipv4addr + buf2,
	}
} */

/* func buildNatTraversalRequestIPv6(ipv6addr []byte, port uint16) *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(18)) // ipv6 addr are on 16 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, port)
	return &P2PRequest{
		Type:   6,
		Length: buf,
		Body:   ipv6addr + buf2,
	}
} */

/* func buildNatTraversalReplyIPv4(ipv4addr []byte, port uint16) *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(6)) // ipv4 addr are on 4 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, port)
	return &P2PRequest{
		Type:   7,
		Length: buf,
		Body:   ipv4addr + buf2,
	}
} */

/* func buildNatTraversalReplyIPv6(ipv6addr []byte, port uint16) *P2PRequest {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(18)) // ipv6 addr are on 16 bytes, +2 for port
	buf2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, port)
	return &P2PRequest{
		Type:   7,
		Length: buf,
		Body:   ipv6addr + buf2,
	}
} */

func setHelloId(exchange *HelloExchange, id uint32) {
	binary.LittleEndian.PutUint32(exchange.Id, id)
}

func setDatumId(datum *Datum, id uint32) {
	binary.LittleEndian.PutUint32(datum.Id, id)
}

func setMsgId(msg *P2PRequest, id uint32) {
	binary.LittleEndian.PutUint32(msg.Id, id)
}

/* func addHelloSignature(exchange *HelloExchange) {
	exchange.Signature = blablabla // TODO
} */

/* func addDatumSignature(datum *Datum) {
	datum.Signature = blablabla // TODO
} */

/* func addMsgSignature(msg *P2PRequest) {
	msg.Signature = blablabla // TODO
} */

/* TODO

func helloToPacket(exchange *HelloExchange) *UDPPacket { // not the right type but you get the idea

}

func datumToPacket(datum *Datum) *UDPPacket {

}

func requestToPacket(req *P2PRequest) *UDPPacket {

}

*/

func udp_main(helpFlag bool, name string) {
	if helpFlag {
		// display help here
	}
	else  {
		// sort the reqtypes
		// case helloexchange here
		// init an HelloExchange
		// reqHello = buildHelloRequest(name)
	}
	// s := ""

	// h := sha256.New()

	// h.Write([]byte(s))

	// bs := h.Sum(nil)
	// h.Write(bs)
	// ba := h.Sum(nil)

	// fmt.Println(s)
	// fmt.Printf("%x\n", bs)
	// fmt.Printf("%x\n", ba)
	a :=createFile("projet.pdf");
	PrintTree(a,"");
}
  