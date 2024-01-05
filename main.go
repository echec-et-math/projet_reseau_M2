package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

/*
	GLOBAL VARS
*/

var hasPubKey = false
var hasFiles = false

var pubkey = make([]byte, 64)
var privkey *ecdsa.PrivateKey
var roothash = make([]byte, 32)

var emptyStringHash = make([]byte, 32) // TODO

var serv_addr = "jch.irif.fr:8443"
var serv_url = "https://jch.irif.fr:8443"

var currentAbr = createDirectory("root")

var currentP2PConn net.Conn
var connectedToPeer = false

var peerpubkey = make([]byte, 64)
var peerHasKey = false

var signaturemode = false

var debugmode = true  // TODO
var force_err = false // this forces error-handling routines to happen, even if nothing failed

var client *http.Client

var name = "NoName"

func displayError(packet []byte) {
	if (debugmode && len(packet) >= 5 && (packet[4] == 128 || packet[4] == 1)) || force_err {
		fmt.Println("Error / ErrorReply from server : " + string(packet[7:]))
	}
}

func logProgress(msg string) {
	if debugmode {
		fmt.Println(msg)
	}
}

/*
	REST register module
*/

func registerPeer(conn net.Conn, name string, hasPubkey bool, hasFiles bool, pubkey []byte, roothash []byte) {
	// dial server
	for {
		req := buildHelloRequest(name, 23, 0)
		if hasPubkey {
			// sign the Hello
		}
		s := helloToByteSlice(req)
		conn.Write(s)
		logProgress("Handshake initiated")
		rep := readMsg(conn)
		logProgress("Handshake response received")
		id := binary.BigEndian.Uint32(rep[0:4])
		if id != 23 || force_err {
			if debugmode {
				fmt.Printf("Warning : unmatching ID in handshake response, expected 23 and got %d\n", id)
				fmt.Println("Our request : " + string(helloToByteSlice(req)))
				fmt.Println("Full hex representation of our request : " + hex.EncodeToString(helloToByteSlice(req)))
				fmt.Println("Server reply : " + string(rep))
				fmt.Println("Full hex representation of the reply : " + hex.EncodeToString(rep))
			}
			fmt.Println("Handshake failed, retrying.")
		} else {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // we need the last read to timeout to tell we're actually done with the server
			readMsg(conn)                                         // our read will auto-sort the requests
			conn.SetReadDeadline(time.Time{})                     // reset deadline
			logProgress("Handshake successful.")
			return
		}
	}
	// maintain connection through goroutine until interruption
}

func main() { // CLI Merge from REST and P2P (UDP)
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client = &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}
	conn, err := net.Dial("udp", serv_addr)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	RESTMode := true
	listPeersFlag := false
	getPeerAddressesFlag := ""
	getPeerKeyFlag := ""
	getPeerRootHashFlag := ""
	helpFlag := false
	exitFlag := false
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
			case "forceerron":
				force_err = true
				break
			case "forceerroff":
				force_err = false
				break
			case "list":
				listPeersFlag = true
				break
			case "getAddresses":
				getPeerAddressesFlag = secondWord
				break
			case "generateKey":
				privkey = privKeyGen()
				pubkey = pubkeyToByteSlice(computePubKey(privkey))
				fmt.Println("Public key : " + string(hex.EncodeToString(pubkey)))
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
			case "signatureon":
				signaturemode = true
				break
			case "signatureoff":
				signaturemode = false
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
			rest_main(listPeersFlag, getPeerAddressesFlag, getPeerKeyFlag, getPeerRootHashFlag, helpFlag, exitFlag)
		} else {
			//latest_req_time := 0 // current time here, used for keepalives
			// client P2P mode
			// read user input
			switch commandWord {
			case "connect":
				if connectedToPeer {
					fmt.Println("Already connected to someone : please disconnect beforehand.")
					break
				}
				currentP2PConn, err = net.Dial("udp", secondWord)
				if err != nil {
					fmt.Println("Error connecting to the peer.")
					if debugmode {
						log.Fatal(err)
					}
				} else {
					salute(name)
					peerpubkey, peerHasKey = fetchPubKey(secondWord)
					connectedToPeer = true
					fmt.Println("Successfully connected to peer.")
				}
				// TODO maintain connection
				break
			case "debugon":
				debugmode = true
				break
			case "debugoff":
				debugmode = false
				break
			case "forceerron":
				force_err = true
				break
			case "forceerroff":
				force_err = false
				break
			case "disconnect":
				if connectedToPeer {
					conn.Close()
					connectedToPeer = false
				}
				RESTMode = true
				break
			case "download":
				if !connectedToPeer {
					fmt.Println("We're not currently connected to a peer !")
				} else {
					byteslice, _ := hex.DecodeString(secondWord)
					logProgress("on vas demander un download")
					tmp2,_:=os.Create("./test")
					tmp:=downloadNode(byteslice, currentP2PConn)
					WriteFile(tmp,0,*tmp2)
				}
			case "exit":
				exitFlag = true
				break
			case "op":
				if !connectedToPeer {
					fmt.Println("We're not currently connected to a peer !")
				} else {
					break // TODO
				}
				// need precise parsing of the actual operation here through the secondword, or add additional prompts
				// in case of connection : maintain the connection with a goroutine
			case "setName":
				name = secondWord
				break
			case "signatureon":
				signaturemode = true
				break
			case "signatureoff":
				signaturemode = false
				break
			default:
				helpFlag = true
				break
			}
			udp_main(helpFlag, exitFlag)
		}
		if debugmode {
			fmt.Println("Operation {" + commandWord + " " + secondWord + " " + thirdWord + " " + fourthWord + " " + fifthWord + "} done.")
		}
		fmt.Println()
	}
}
