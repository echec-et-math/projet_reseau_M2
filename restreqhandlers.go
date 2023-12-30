package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

/*
	REST request processors
*/

func aux_list_printer(body io.ReadCloser) {
	text, err := io.ReadAll(body)
	if (err != nil && debugmode) || force_err {
		log.Fatal("readResponseBody: ", err)
		return
	}
	for _, line := range strings.Split(string(text[:]), "\n") {
		if line != "" { // remove ending newline
			fmt.Println("[REQBODY] " + line)
		}
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
	aux_hash_printer(resp.Body)
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
