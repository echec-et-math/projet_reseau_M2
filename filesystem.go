package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
)

/*
	FILE MANIPULATION PRIMITIVES
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
	if err != nil || force_err {
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
		if err != nil || force_err {
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
	tmpc := []byte{}
	t := make([]byte, 1)
	t[0] = 0
	tmpc = append(t, content...)
	h.Write(tmpc)
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
func AddChild(p Node, c Node) Node {
	if p.Directory && p.nbchild < 16 {
		c.Parent = &p
		p.Childs[p.nbchild] = c
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
func createDirectory(n string) Node {
	return Node{
		Directory: true,
		Big:       false,
		nbchild:   0,
		Parent:    nil,
		name:      n,
		Childs:    make([]Node, 16),
	}
}
func PrintTree(r Node, pre string) {
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
}
func WriteFile(current Node, index int, f *os.File) int {
	if current.Big {
		tmp := index
		for i := 0; i < current.nbchild; i++ {
			tmp = tmp + WriteFile(current.Childs[i], tmp, f)
		}
		return index + (1024 * current.nbchild)
	} else {
		f.Write(current.Data)
		return 0
	}
	// return -1 -> unreachable code
}
func WriteArbo(r Node, path string) int{
	fmt.Println(path+r.name+"/")
	if(r.Directory){
		os.MkdirAll(path+r.name,os.ModePerm)
		for i:=0;i<r.nbchild;i++{
			WriteArbo(r.Childs[i],path+r.name+"/")
		}
		return 0
	}else{
		f,_:=os.Create(path+r.name)
		defer f.Close()
		WriteFile(r,0,f)
		return 0
	}
	return -1
}
