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

	/*** READ ***/
	http.HandleFunc("/", handler.IndexHandler)
	http.HandleFunc("/api/get-all-sites", apiChain(handler.GetAllSitesHandler))
	http.HandleFunc("/api/get-all-zones", apiChain(handler.GetAllZonesHandler))
	http.HandleFunc("/api/get-all-subnets", apiChain(handler.GetAllSubnetsHandler))
	http.HandleFunc("/api/get-all-transitions", apiChain(handler.GetAllTransitionsHandler))

	/*** Insert ***/
	http.HandleFunc("/api/insert-sites", apiChain(handler.InsertSitesHandler))
	http.HandleFunc("/api/insert-zones", apiChain(handler.InsertZonesHandler))
	http.HandleFunc("/api/insert-subnets", apiChain(handler.InsertSubnetsHandler))
	http.HandleFunc("/api/insert-transitions", apiChain(handler.InsertTransitionsHandler))

	/*** Delete ***/
	http.HandleFunc("/api/delete-sites", apiChain(handler.GetAllSubnetsHandler))           // todo
	http.HandleFunc("/api/delete-zones", apiChain(handler.GetAllSubnetsHandler))           // todo
	http.HandleFunc("/api/delete-subnets", apiChain(handler.GetAllSubnetsHandler))         // todo
	http.HandleFunc("/api/delete-all-transitions", apiChain(handler.GetAllSubnetsHandler)) // todo
	http.HandleFunc("/api/delete-transition", apiChain(handler.GetAllSubnetsHandler))      // todo

	// go func() {
	log.Fatal(http.ListenAndServeTLS("192.168.1.11:4433", "cert.pem", "key.pem", nil))
	//}()

	//log.Fatal(shttp.ListenAndServe(":8080", nil))
}

//curl --insecure https://localhost:4433/api/insert-sites --request POST  --data
//'[{"TPAddr":"9-9999:9:9,1.1.1.1","Name":"Test site"}]'
