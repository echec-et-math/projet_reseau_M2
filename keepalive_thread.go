package main

import (
	"net"
	"time"
)

func keepaliveNoSignature(conn net.Conn) {
	helloreq := buildHelloRequest(name, 0, 0)
	for {
		time.Sleep(time.Minute)
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		readMsgNoSignature(conn)
		conn.Write(helloToByteSlice(helloreq))
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		readMsgNoSignature(conn)
	}
}

func keepaliveSignature(conn net.Conn) {
	helloreq := buildHelloRequest(name, 0, 0)
	for {
		time.Sleep(time.Minute)
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		readMsgWithSignature(conn)
		conn.Write(helloToByteSlice(helloreq))
		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		readMsgWithSignature(conn)
	}
}
