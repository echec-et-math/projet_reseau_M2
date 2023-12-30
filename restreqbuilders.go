package main

import (
	"log"
	"net/http"
)

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
