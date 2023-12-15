package main

import (
	"bufio"
	"log"
	"os"
	"strings"
)

func main() {
	RESTMode := true
	listPeersFlag := false
	getPeerAddressesFlag := ""
	getPeerKeyFlag := ""
	getPeerRootHashFlag := ""
	helpFlag := false
	exitFlag := false
	debugmode := false
	name := ""
	reader := bufio.NewReader(os.Stdin)
	commandWord := ""
	secondWord := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		parts := strings.Split(line, "\n")
		commandWord = parts[0]
		if len(parts) > 1 {
			secondWord = parts[1]
		}
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
			rest_main(listPeersFlag, getPeerAddressesFlag, getPeerKeyFlag, getPeerRootHashFlag, helpFlag, debugmode)
		} else {
			latest_req_time := 0 // current time here
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
				// need precise parsing of the actual operation here
			default:
				helpFlag = true
				break
			}
			//udp_main(..., helpFlag, debugmode)
		}
	}
}
