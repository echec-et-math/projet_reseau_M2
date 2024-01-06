package main

import (
	"encoding/binary"
	"net"
	"time"
)

func keepalive(conn net.Conn, tree *Node) {
	// TODO COPY PEER DATA IN MEMORY (NOTABLY THE KEYS)
	for {
		time.Sleep(time.Minute)
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		tmp := readMsgNoSignature(conn)
		if len(tmp) != 0 {
			//on verifie uniquement les demande
			//les reponse c'est pas notre probleme et ca veut dire que le message a été envoyé au mauvais endroit
			if tmp[4] == byte(5) {
				//respond a datum
				n := findNode(tmp[7:39], *tree)
				if n != nil {
					if n.Directory {
						buf := make([]byte, n.nbchild*32)
						for i := 0; i < n.nbchild; i++ {
							tmpname := []byte(n.Childs[i].name)
							for j := 0; j < 32; j++ {
								if j < 16 {
									buf[i*32+j] = tmpname[j]
								} else {
									buf[i*32+j] = n.Childs[i].Hash[j]
								}
							}
						}
					} else if n.Big {
						buf := make([]byte, n.nbchild*32)
						for i := 0; i < n.nbchild; i++ {
							for j := 0; j < 32; j++ {
								buf[i*32+j] = n.Childs[i].Hash[j]
							}
						}
						buildDatumReply(tmp[0:4], buf, tmp[7:39])
					} else {
						buildDatumReply(tmp[0:4], (*n).Data, tmp[7:39])
					}
				} else {
					answer := make([]byte, 40)
					for i := 0; i < 40; i++ {
						answer[i] = tmp[i]
					}
					answer[5] = byte(133)
					conn.Write(answer) // faire un renvoi de no datum
				}
			}
			if tmp[4] == byte(2) {
				hellorep := buildHelloReply(binary.BigEndian.Uint32(tmp[0:4]))
				conn.Write(helloToByteSlice(hellorep))
			}
			if tmp[4] == byte(3) {
				rep := buildPubkeyReplyNoPubkey(binary.BigEndian.Uint32(tmp[0:4]))
				if hasPubKey {
					rep = buildPubkeyReplyWithPubkey(pubkey, binary.BigEndian.Uint32(tmp[0:4]))
				}
				conn.Write(requestToByteSlice(rep))
			}
		} else {
			buf := make([]byte, 7)
			for i := 0; i < 7; i++ {
				buf[i] = byte(0)
			}
			conn.Write(buf) // mettre un noop a un moment plus logique
		}
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		readMsg(conn)
	}
}
