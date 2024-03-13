package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
)

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
	FILE MANIPULATION PRIMITIVES
*/

func filename(filepath string) string {
	// macro removing the trailing slash in filepaths
	i := strings.LastIndex(filepath, "/")
	if i == -1 {
		// if no slash at all, then the file name is the full string
		return filepath
	} else {
		// otherwise, the file name is the last word of the slash-delimited string
		return filepath[i:]
	}
}

/*
	Returns a Merkle tree Node for a given filepath. Assumes that this path points to a file and NOT a directory.
*/
func createNode(filepath string) Node {
	// open a file on the disk
	f, err := os.Open(filepath)
	if err != nil || force_err {
		fmt.Println(err)
	}
	defer f.Close()
	reader := bufio.NewReader(f)    // a reader on our file
	buf := make([]byte, 1024)       // this buffer will serve to read our file
	chunkbuffer := make([]Node, 32) // an empty Node array (will store the children of our final Node)
	var chunkchildren, bigfilechildren int = 0, 0
	// i is a counter for the amount of reads done on the file. It tracks the current amount of chunks among the children
	// As every read creates a child, it is important to track this amount, to convert a large amount of data chunks into a big file
	// Similarly, j tracks the amount of big files among the children
	var bigfilebuffer []Node // bf stores the big files we created
	for {
		n, err := reader.Read(buf) // reads the file
		if err != nil || force_err {
			if err != io.EOF {
				fmt.Println(err)
				return Node{}
			}
			break // when EOF reached, skip to the next part
		}
		if chunkchildren == 32 { // when we have too many chunks, convert them into a single big file
			bigfilebuffer = append(bigfilebuffer, createBigFileNode(chunkbuffer, 32))
			chunkchildren = 0                     // resets the chunk children counter
			bigfilechildren = bigfilechildren + 1 // increments the big file children counter
		}
		chunkbuffer[chunkchildren] = createChunkNode(buf, n)
		chunkchildren = chunkchildren + 1
	}
	// Now that we created buffers and counters for both chunks and big files, we need to group the leftover chunks one last time
	if bigfilechildren == 0 { // if we have no big file
		if chunkchildren > 1 { // and several chunks
			ret := createBigFileNode(chunkbuffer, chunkchildren) // group them under one big file
			ret.name = filename(filepath)
			return ret // and directly return it
		} else {
			chunkbuffer[0].name = filename(filepath) // if we have no big file and only one chunk, keep it as is
			return chunkbuffer[0]                    // and return this single chunk
		}
	}
	// in this part, we already have at least one big file, and possibly some leftover chunks : we will need to group them adequately
	fmt.Printf("Amount of Big Files : %d\n", bigfilechildren)
	fmt.Printf("Amount of leftover Chunks : %d\n", chunkchildren)
	bigfilebuffer = append(bigfilebuffer, createBigFileNode(chunkbuffer, chunkchildren)) // merging leftover chunks into a final big file node
	/*
		In this part, we will use conjunctively two buffers to enforce the "32 max children" rule.
		One will be our bigfilebuffer, re-used.
		The second one will be our next_depth_buf.
		We will group the children of bigfilebuffer into a new, next-depth, Node when there are too many.
		We will then store these next-depth nodes into next_depth_buf.
		This next_depth_buf will then become our new bigfilebuffer, and so on.
		We are done when the 32-children cap is no longer broken.
	*/
	var next_depth_buf []Node
	for len(bigfilebuffer) > 32 {
		for a := 0; a < len(bigfilebuffer); a = a + 32 { // iterates by groups of 32 due to 32 being the children cap
			next_depth_buf = append(next_depth_buf, createBigFileNode(bigfilebuffer[a:32], 32)) // groups are placed into our next_depth buffer
		}
		bigfilebuffer = nil                 // resets the current array to nil
		copy(bigfilebuffer, next_depth_buf) // and sets former next-depth buffer as current depth
	}
	if len(bigfilebuffer) >= 2 { // big file merger : groups leftover big file nodes
		ret := createBigFileNode(bigfilebuffer, len(bigfilebuffer))
		ret.name = filename(filepath)
		return ret
	} else { // in case of a single big file remaining, returns it instead
		bigfilebuffer[0].name = filename(filepath)
		return bigfilebuffer[0]
	}
}

func createChunkNode(content []byte, length int) Node {
	h := sha256.New()
	tmpc := []byte{}
	t := make([]byte, 1)
	t[0] = 0
	data := content[0:l]
	tmpc = append(t, data...)
	h.Write(tmpc)
	return Node{
		Directory: false,
		Big:       false,
		Parent:    nil,
		Hash:      h.Sum(nil),
		Data:      data,
	}
}

func createBigFileNode(children []Node, nb int) Node {
	s := []byte{}
	h := sha256.New()
	t := make([]byte, 1)
	t[0] = 1
	s = append(s, t[0])
	n := Node{
		Directory: false,
		Big:       true,
		nbchild:   nb,
		Childs:    make([]Node, 32),
	}
	for i := 0; i < nb; i++ {
		s = append(s, children[i].Hash...)
		n.Childs[i] = children[i]
		n.Childs[i].Parent = &n
	}
	h.Write(s)
	n.Hash = h.Sum(nil)
	return n
}

func copyChunkNode(n *Node) *Node {
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
func AddChild(p Node, c Node) Node {
	if p.Directory && p.nbchild < 16 {
		c.Parent = &p
		p.Childs = append(p.Childs, c)
		p.nbchild = p.nbchild + 1
		if debugmode {
			fmt.Println(p.nbchild)
		}
		h := sha256.New()
		s := []byte{}
		t := make([]byte, 1)
		t[0] = 2
		s = append(s, t...)

		for i := 0; i < p.nbchild; i++ {
			s = append(s, []byte(p.Childs[i].name)...)
			s = append(s, p.Childs[i].Hash...)

		}
		h.Write(s)
		p.Hash = h.Sum(nil)

	}
	return p
}
func createDirectoryNode(n string) Node {
	return Node{
		Directory: true,
		Big:       false,
		nbchild:   0,
		Parent:    nil,
		name:      n,
		Childs:    make([]Node, 16),
	}
}

/* func PrintTree(r Node, pre string) {
	if r.Directory {
		for i := 0; i < r.nbchild; i++ {
			PrintTree(r.Childs[i], pre+"  ")
		}
	}
	if r.Big {
		if debugmode {
			fmt.Println(pre + r.name)
		}
		for i := 0; i < r.nbchild; i++ {
			PrintTree(r.Childs[i], pre+"  ")
		}
	} else {
		if debugmode {
			fmt.Println(pre + "chunk")
		}
	}
} */
func WriteFile(current Node) []byte {
	if current.Big {
		s := []byte{}
		for i := 0; i < current.nbchild; i++ {
			s = append(s, WriteFile(current.Childs[i])...)
		}
		return s
	} else {
		return current.Data
	}
	// return -1 -> unreachable code
}
func WriteArbo(r Node, path string) int {
	if r.Directory {
		err := os.MkdirAll(path, 0777)
		if err != nil {
			fmt.Println("on essaie de creer un dossier")
			panic(err)
		}
		for i := 0; i < r.nbchild; i++ {
			fullpath := fmt.Sprintf(path+"/"+"%d", i)
			WriteArbo(r.Childs[i], fullpath)
		}
		return 0
	} else {
		s := WriteFile(r)
		n := path + r.name
		n = supp0(n)
		err := os.WriteFile(n, s, 0666)
		if err != nil {
			fmt.Println("absolument illogique")
			panic(err)
		}
		return 0
	}
}
func supp0(a string) string {
	var j int
	for i := len(a) - 1; i > -1; i-- {
		if byte(a[i]) == 0 {
			j = i

		}
	}
	a = a[:j]
	return a
}
