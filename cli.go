package main

import (
	"fmt"
	"log"
	"os"
)

/*
	CLI SECTION
*/

func rest_main(listPeersFlag bool, getPeerAddressesFlag string, getPeerKeyFlag string, getPeerRootHashFlag string, helpFlag bool, exitFlag bool) {
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
		fmt.Println("forceerron : simulates an error in every critical section (disabled by default)")
		fmt.Println("forceerroff : stops simulating an error in every critical section (disabled by default)")
		fmt.Println("exit : quits the program")
		// fetchStorage command (updates our hash)
		fmt.Println("getAddresses [peer_name] : fetches and displays a list of known addresses for a given peer, from the server.")
		fmt.Println("generateKey : generates a new key, displays it. DOES NOT AUTOMATICALLY TURN ON SIGNATURE MODE.")
		fmt.Println("getKey [peer_name] : fetches and displays the public key of a given peer, from the server.")
		fmt.Println("getRootHash [peer_name] : fetches and displays the hash of the root of a given peer, from the server.")
		fmt.Println("help : displays this help and exits. Default behavior.")
		fmt.Println("list : fetches and displays a list of known peers from the server.")
		fmt.Println("register : registers ourself to the REST server.")
		fmt.Println("setName [name] : changes your name as seen by the REST server.")
		fmt.Println("signatureon : enables signatures during exchanges. Disabled by default.")
		fmt.Println("signatureoff : disables signatures during exchanges. Disabled by default.")
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

func udp_main(helpFlag bool, exitFlag bool) {
	// P2P CLI (TODO)
	if exitFlag {
		os.Exit(0)
	}
	if helpFlag {
		fmt.Println("Usage for P2P (UDP) mode :")
		fmt.Println("Several commands can be used, the help command is used by default if none is provided.")
		fmt.Println("Commands :")
		fmt.Println("debugon : enables error display (disabled by default)")
		fmt.Println("debugoff : disables error display (disabled by default)")
		fmt.Println("forceerron : simulates an error in every critical section (disabled by default)")
		fmt.Println("forceerroff : stops simulating an error in every critical section (disabled by default)")
		fmt.Println("connect [addr]: connects to a peer given its address. It is recommended to check the root hash of this peer beforehand, and its public key if you plan to encrypt your data.")
		fmt.Println("disconnect : closes the connection to the current peer.")
		fmt.Println("exit : quits the program")
		fmt.Println("help : displays this help and exits. Default behavior.")
		fmt.Println("setName [name] : changes your name as seen by the peers.")
		fmt.Println("signatureon : enables signatures during exchanges. Disabled by default.")
		fmt.Println("signatureoff : disables signatures during exchanges. Disabled by default.")
		fmt.Println("switchmode : switches back into REST mode AND deconnects.")
		fmt.Println("download hash : download the node specified and all descendant and write it to a file")
		return
	}
}
