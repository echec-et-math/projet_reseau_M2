package src

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

var serv_url = "https://jch.irif.fr:8443"

var debugmode = true  // TODO
var force_err = false // this forces error-handling routines to happen, even if nothing failed

func buildGetPeersRequest() *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func buildGetPeerAddressesRequest(peer_name string) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers/"+peer_name+"/addresses", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func buildGetPeerPubkeyRequest(peer_name string) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers/"+peer_name+"/key", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func buildGetPeerRootHashRequest(peer_name string) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers/"+peer_name+"/root", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func aux_list_printer(body io.ReadCloser) {
	text, err := io.ReadAll(body)
	if (err != nil && debugmode) || force_err {
		log.Fatal("readResponseBody: ", err)
		return
	}
	for _, line := range strings.Split(string(text[:]), "\n") {
		fmt.Println("[REQBODY] " + line)
	}
}

func aux_hash_printer(body io.ReadCloser) {
	text, err := io.ReadAll(body)
	if (err != nil && debugmode) || force_err {
		log.Fatal("readResponseBody: ", err)
		return
	}
	hexHash := hex.EncodeToString(text)
	fmt.Println(hexHash)
}

func processGetPeersResponse(resp *http.Response) {
	aux_list_printer(resp.Body)
	resp.Body.Close()
}

func processGetPeerAddressesResponse(resp *http.Response) {
	if resp.StatusCode == http.StatusNotFound { // 404
		fmt.Println(resp.Status)
	}
	aux_list_printer(resp.Body)
	resp.Body.Close()
}

func processGetPeerKeyResponse(resp *http.Response) {
	if resp.StatusCode == http.StatusNotFound { // 404
		fmt.Println(resp.Status)
	}
	if resp.StatusCode == http.StatusNoContent { // 204
		fmt.Println(resp.Status)
	}
	aux_list_printer(resp.Body)
	resp.Body.Close()
}

func processGetPeerRootHashResponse(resp *http.Response) {
	if resp.StatusCode == http.StatusNotFound { // 404
		fmt.Println(resp.Status)
	}
	if resp.StatusCode == http.StatusNoContent { // 204
		fmt.Println(resp.Status)
	}
	aux_hash_printer(resp.Body)
	resp.Body.Close()
}

func rest_main(listPeersFlag bool, getPeerAddressesFlag string, getPeerKeyFlag string, getPeerRootHashFlag string, helpFlag bool, exitFlag bool, debugmode bool) {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}
	if helpFlag {
		fmt.Println("Usage for REST mode :")
		fmt.Println("Several commands can be used, the help command is used by default if none is provided.")
		fmt.Println("Commands :")
		fmt.Println("debugon : enables error display (disabled by default)")
		fmt.Println("debugoff : disables error display (disabled by default)")
		fmt.Println("exit : quits the program")
		fmt.Println("getAddresses [peer_name] : fetches and displays a list of known addresses for a given peer, from the server.")
		fmt.Println("getKey [peer_name] : fetches and displays the public key of a given peer, from the server.")
		fmt.Println("getRootHash [peer_name] : fetches and displays the hash of the root of a given peer, from the server.")
		fmt.Println("help : displays this help and exits. Default behavior.")
		fmt.Println("list : fetches and displays a list of known peers from the server.")
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
