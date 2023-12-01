package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

var debugmode = true  // this allows the processing of errors
var force_err = false // this forces error-handling routines to happen, even if nothing failed

func buildGetPeersRequest(serv_url string) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func buildGetPeerAddressesRequest(serv_url string, peer_id int) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers/"+strconv.Itoa(peer_id)+"/addresses", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func buildGetPeerPubkeyRequest(serv_url string, peer_id int) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers/"+strconv.Itoa(peer_id)+"/key", nil)
	if (err != nil && debugmode) || force_err {
		log.Fatal("http.NewRequest: ", err)
	}
	return req
}

func buildGetPeerRootHashRequest(serv_url string, peer_id int) *http.Request {
	req, err := http.NewRequest("GET", serv_url+"/peers/"+strconv.Itoa(peer_id)+"/root", nil)
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
	for _, lines := range strings.Split(string(text[:]), "\n") {
		log.Printf("metric: %s", lines)
	}
}

func processGetPeersResponse(resp *http.Response) {
	aux_list_printer(resp.Body)
	resp.Body.Close()
}

func processGetPeerAddressesResponse(resp *http.Response) {
	if resp.StatusCode == http.StatusNotFound {
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
	aux_list_printer(resp.Body)
	resp.Body.Close()
}

func main() {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}
	servAddressFlag := flag.String("server", "localhost", "the IP address of the central REST server")
	listPeersFlag := flag.Bool("list", true, "use to ask for the peer list")
	getPeerAddressesFlag := flag.Int("getAddresses", -1, "specify a peer ID to get the addresses from")
	getPeerKeyFlag := flag.Int("getKey", -1, "specify a peer ID to get the pubkey from")
	getPeerRootHashFlag := flag.Int("getRootHash", -1, "specify a peer ID to get the root hash from")
	flag.Parse()
	if *listPeersFlag {
		req := buildGetPeersRequest(*servAddressFlag)
		if req != nil {
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal("http.NewRequest: ", err)
			}
			processGetPeersResponse(resp)
		}
	}
	if *getPeerAddressesFlag != -1 {
		req := buildGetPeerAddressesRequest(*servAddressFlag, *getPeerAddressesFlag)
		if req != nil {
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal("http.NewRequest: ", err)
			}
			processGetPeerAddressesResponse(resp)
		}
	}
	if *getPeerKeyFlag != -1 {
		req := buildGetPeerPubkeyRequest(*servAddressFlag, *getPeerKeyFlag)
		if req != nil {
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal("http.NewRequest: ", err)
			}
			processGetPeerKeyResponse(resp)
		}
	}
	if *getPeerRootHashFlag != -1 {
		req := buildGetPeerAddressesRequest(*servAddressFlag, *getPeerRootHashFlag)
		if req != nil {
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal("http.NewRequest: ", err)
			}
			processGetPeerRootHashResponse(resp)
		}
	}
}
