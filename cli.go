package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	RESTMode := true
	listPeersFlag := false
	getPeerAddressesFlag := ""
	getPeerKeyFlag := ""
	getPeerRootHashFlag := ""
	helpFlag := false
	debugmode := false
	reader := bufio.NewReader(os.Stdin)
	commandWord := ""
	secondWord := ""
	while (true) {
		line, err := reader.ReadString('\n')
    	if err != nil {
        	log.Fatal(err)
    	}
		parts := string.Split(line, "\n")
		commandWord := parts[0]
		if len(parts) > 1 {
			secondWord := parts[1]
		}
		if (RESTMode) {
			// client REST mode
			listPeersFlag := false
			getPeerAddressesFlag := ""
			getPeerKeyFlag := ""
			getPeerRootHashFlag := ""
			helpFlag := false
			// read user input
			switch (commandWord) {
				case "debugon":
					debugmode = true
					break
				case "debugoff":
					debugmode := false
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
				case "connect":
					RESTMode = false
					break
				case "exit":
					return
				default:
					helpFlag = true
					break
			}
			// TODO : allow a list of peers instead of a single one here
			rest_main(listPeersFlag, getPeerAddressesFlag, getPeerKeyFlag, getPeerRootHashFlag, helpFlag, debugmode)
		}
		else {
			// client P2P mode
			helpFlag := false
			// read user input
			switch (commandWord) {
				case "debugon":
					debugmode = true
					break
				case "debugoff":
					debugmode := false
					break
				case "disconnect":
					RESTMode = true
					break
				case "exit":
					return
				default:
					helpFlag = true
					break
			}
			//udp_main(..., helpFlag, debugmode)
		}
	}
}