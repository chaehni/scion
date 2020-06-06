package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"github.com/scionproto/scion/go/sig/zoning/controller/handler"
)

func main() {

	// add client cert to trusted RootCAs
	pool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("certs/client_cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	pool.AppendCertsFromPEM(pem)

	server := http.Server{
		Addr: ":8080",
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		},
	}

	apiChain := handler.LogHandler

	/*** API used by Zone Translation Points ***/
	http.HandleFunc("/api/get-key", apiChain(handler.GetKeyHandler))
	http.HandleFunc("/api/get-subnets", apiChain(handler.GetSubnetsHandler))
	http.HandleFunc("/api/get-transfers", apiChain(handler.GetTransfersHandler))

	/*** API used by admin frontend ***/
	//TODO: iplement frontend

	log.Fatal(server.ListenAndServeTLS("certs/server_cert.pem", "certs/server_key.pem"))
}
