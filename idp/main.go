package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/apex/gateway"
)

var (
	// DefaultHTTPGetAddress Default Address
	DefaultHTTPGetAddress = "https://checkip.amazonaws.com"

	// ErrNoIP No IP found in response
	ErrNoIP = errors.New("No IP in HTTP response")

	// ErrNon200Response non 200 status code in response
	ErrNon200Response = errors.New("Non 200 Response found")
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	lreq, ok := gateway.RequestContext(r.Context())
	if ok {
		log.Printf("Processing request data for request %s.\n", lreq.RequestID)
	}
	log.Printf("Path: %s\n", r.URL.Path)
	// fmt.Printf("Body size = %d.\n", len(request.Body))

	log.Println("Headers:")
	for key, value := range r.Header {
		fmt.Printf("    %s: %s\n", key, value)
	}

	resp, err := http.Get(DefaultHTTPGetAddress)
	if err != nil {
		log.Printf("error in get: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != 200 {
		log.Printf("error in get: %v", ErrNon200Response)
		http.Error(w, ErrNon200Response.Error(), http.StatusInternalServerError)
		return
	}

	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error in get: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(ip) == 0 {
		log.Printf("error in get: %v", ErrNoIP)
		http.Error(w, ErrNoIP.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Hello, %v", string(ip))
}

func main() {
	m := http.NewServeMux()
	m.HandleFunc("/hello", helloHandler)
	gateway.ListenAndServe("", m)
}
