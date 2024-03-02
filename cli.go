package main

import (
	"fmt"
	"log"
	"os"
)

/*
	CLI SECTION
*/

func cli_main(listPeersFlag bool, helpFlag bool, exitFlag bool) {
	// CLI
	if exitFlag {
		os.Exit(0)
	}
	if helpFlag {
		fmt.Println("Several commands can be used, the help command is used by default if none is provided.")
		fmt.Println("Commands :")
		fmt.Println("connect [name]: connects to a peer given its name. Our client will automatically fetch the public key and the root hash of this peer from the REST server.")
		fmt.Println("debugon : enables error display (disabled by default)")
		fmt.Println("debugoff : disables error display (disabled by default)")
		fmt.Println("disconnect : closes the connection to the current peer.")
		fmt.Println("download : downloads all data from the peer we are currently connected to. Requires a connection to a peer.")
		fmt.Println("forceerron : simulates an error in every critical section (disabled by default)")
		fmt.Println("forceerroff : stops simulating an error in every critical section (disabled by default)")
		fmt.Println("exit : quits the program")
		fmt.Println("exportKey : exports our private key to a external file in the project root.")
		fmt.Println("generateKey : generates a new key, displays it. DOES NOT AUTOMATICALLY TURN ON SIGNATURE MODE.")
		fmt.Println("help : displays this help and exits. Default behavior.")
		fmt.Println("importKey : imports the private key from an external file, takes it as out private key, computes the associated public key, and assigns it as out public key.")
		fmt.Println("list : fetches and displays a list of known peers from the server.")
		fmt.Println("register : registers ourself to the REST server.")
		fmt.Println("setName [name] : changes your name as seen by the REST server.")
		return
	}
	if listPeersFlag {
		req := buildGetPeersRequest()
		if req != nil || force_err {
			resp, err := client.Do(req)
			if err != nil || force_err {
				log.Fatal("http.NewRequest: ", err)
			}
			processGetPeersResponse(resp)
		}
	}
	if exitFlag {
		// todo disconnect client
		return
	}
}
