package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/tls"
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

var helloExchangeDone = false
var pubkeyExchangeDone = false
var roothashExchangeDone = false

var hasPubKey = false
var hasFiles = true

var pubkey = make([]byte, 64)
var privkey *ecdsa.PrivateKey
var roothash = make([]byte, 32)

var emptyStringHash = make([]byte, 32) // TODO

var serv_addr = "jch.irif.fr:8443"
var serv_addr_noport = "jch.irif.fr"
var serv_url = "https://jch.irif.fr:8443"

var currentAbr = createFile("projet.pdf")

var currentP2PConn net.Conn
var connectedToPeer = false

var servconn net.Conn // REST server connection
var list net.Conn

var peerpubkey = make([]byte, 64)
var peerHasKey = false

var debugmode = false
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

func registerPeer(name string, pubkey []byte, roothash []byte) {
	// dial server
	req := buildHelloRequest(name, 23, 0)
	s := helloToByteSlice(req)
	signAndWrite(servconn, s)
	logProgress("Handshake initiated")
	readMsg(servconn)
	servconn.SetReadDeadline(time.Now().Add(time.Second * 5))
	readMsg(servconn) // let the server speak first
	if !pubkeyExchangeDone {
		req2 := buildPubkeyRequestNoPubkey(91)
		if hasPubKey {
			req2 = buildPubkeyRequestWithPubkey(91, pubkey)
		}
		signAndWrite(servconn, requestToByteSlice(req2))
	}
	servconn.SetReadDeadline(time.Now().Add(time.Second * 5))
	readMsg(servconn) // again
	if !roothashExchangeDone {
		req3 := buildRootRequestNoData(157)
		if hasFiles {
			req3 = buildRootRequest(157, roothash)
		}
		signAndWrite(servconn, requestToByteSlice(req3))
	}
	readMsg(servconn) // and again
	logProgress("Handshake successful.")
	return
}

func main() { // CLI Merge from REST and P2P (UDP)
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client = &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}
	// THIS BLOCK IS ONLY USEFUL FOR NAT TRAVERSAL REQUESTS
	/* conn, _ = net.Dial("udp", serv_addr)
	req := buildHelloRequest(name, 0, 0)
	conn.Write(helloToByteSlice(req))
	conn.SetReadDeadline(time.Now().Add(time.Second * 5)) // accept a delay for pubkey or roothash
	readMsg(conn)                                         // TODO signature mode. We read all the replys and process them, until an empty message tells us we're done.
	//go keepaliveNoSignature(conn) */
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
		if err != nil || force_err {
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
			case "exportKey":
				exportKey()
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
				hasPubKey = true
				logProgress("Public key : " + string(hex.EncodeToString(pubkey)))
				break
			case "getKey":
				getPeerKeyFlag = secondWord
				break
			case "getRootHash":
				getPeerRootHashFlag = secondWord
				break
			case "importKey":
				importKey()
				fmt.Println("Imported key : " + string(hex.EncodeToString(pubkey)))
				break
			case "register":
				helloExchangeDone = false
				pubkeyExchangeDone = false
				roothashExchangeDone = false
				servconn, _ = net.Dial("udp", serv_addr)
				//peerpubkey, peerHasKey = fetchPubKey(serv_addr_noport)
				//Uncomment above when the REST Server will sign its HelloReply properly
				registerPeer(name, pubkey, roothash)
				go keepalive(servconn, &currentAbr)
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
				helloExchangeDone = false
				pubkeyExchangeDone = false
				roothashExchangeDone = false
				currentP2PConn, err = net.Dial("udp", secondWord)
				if err != nil || force_err {
					fmt.Println("Error connecting to the peer.")
					if debugmode {
						log.Fatal(err)
					}
				} else {
					peerpubkey, peerHasKey = fetchPubKey(secondWord)
					// Uncomment above when we figure out signatures
					salute(name)
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
					currentP2PConn.Close()
					helloExchangeDone = false
					pubkeyExchangeDone = false
					roothashExchangeDone = false
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
					tmp, tmpe := downloadNode(byteslice, currentP2PConn)
					if tmpe != 0 {
						fmt.Printf("Erreur lors du download,  %d \n", tmpe)
					} else {
						WriteArbo(tmp, "./testdump")
					}
				}
			case "exit":
				exitFlag = true
				break
			case "setName":
				name = secondWord
				break
			case "switchmode":
				RESTMode = true
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
