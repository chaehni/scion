package main

import (
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	//	"github.com/netsec-ethz/scion-apps/pkg/shttp"
	"github.com/scionproto/scion/go/pkg/gateway/zoning/controller/handler"
)

func main() {

	/* // add client cert to trusted RootCAs
	pool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("certs/client_cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	pool.AppendCertsFromPEM(pem) */

	/* server := shttp.Server{
		Addr: ":8080",
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		},
	} */

	apiChain := handler.LogHandler

	/*** API used by Zone Translation Points ***/
	http.HandleFunc("/api/get-subnets", apiChain(handler.GetSubnetsHandler))
	http.HandleFunc("/api/get-transitions", apiChain(handler.GetTransitionsHandler))

	/*** API used by admin frontend ***/
	//TODO: iplement frontend
	http.HandleFunc("/", handler.IndexHandler)
	http.HandleFunc("/api/get-all-subnets", apiChain(handler.GetAllSubnetsHandler))
	http.HandleFunc("/api/get-all-transitions", apiChain(handler.GetAllTransitionsHandler))
	http.HandleFunc("/api/insert-transitions", apiChain(handler.InsertTransitionsHandler))

	// go func() {
	log.Fatal(http.ListenAndServeTLS("0.0.0.0:4433", "cert.pem", "key.pem", nil))
	//}()

	//log.Fatal(shttp.ListenAndServe(":8080", nil))
}
