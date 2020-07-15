package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/scionproto/scion/go/sig/zoning/controller/sqlite"
)

var db *sqlite.Backend

func init() {
	// get a database handle
	db = setupDB()
}

// GetSubnetsHandler returns all subnet information to the client
func GetSubnetsHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: the shttp package is very basic and does not allow to set the local address
	// therefore the handler sees the default ISD-AS,127.0.0.1 address as remote. The public IP of the TP is therfore sent
	// in the body. This should be checked to match the certificate
	defer r.Body.Close()
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	nets, err := db.GetSubnets(string(buf))
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ") //TODO: remove after testing
	enc.Encode(nets)
}

// GetTransfersHandler returns all transfer information to the client
func GetTransfersHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: the shttp package is very basic and does not allow to set the local address
	// therefore the handler sees the default ISD-AS,127.0.0.1 address as remote. The public IP of the TP is therfore sent
	// in the body. This should be checked to match the certificate
	defer r.Body.Close()
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	transfers, err := db.GetTransfers(string(buf))
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ") //TODO: remove after testing
	enc.Encode(transfers)
}

// LogHandler logs incoming HTTP requests
// useful for debugging
func LogHandler(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		x, err := httputil.DumpRequest(r, true)
		if err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		log.Println(fmt.Sprintf("%q", x))
		fn(w, r)
	}
}

func setupDB() *sqlite.Backend {
	db, err := sqlite.New(":memory:")
	if err != nil {
		log.Fatal(err)
	}

	// add some test data
	err = db.InsertZone(1, "test")
	if err != nil {
		panic(err)
	}

	err = db.InsertZone(345, "other")
	if err != nil {
		panic(err)
	}
	err = db.InsertZone(456, "other")
	if err != nil {
		panic(err)
	}
	err = db.InsertZone(2, "other")
	if err != nil {
		panic(err)
	}
	err = db.InsertZone(3, "other")
	if err != nil {
		panic(err)
	}
	err = db.InsertZone(4, "other")
	if err != nil {
		panic(err)
	}
	err = db.InsertZone(5, "other")
	if err != nil {
		panic(err)
	}

	err = db.InsertSite("1-ff00:0:112,172.16.0.12", "Site A")
	if err != nil {
		panic(err)
	}
	err = db.InsertSite("1-ff00:0:113,172.16.0.13", "Site B")
	if err != nil {
		panic(err)
	}
	err = db.InsertSubnet(1, net.IPNet{IP: net.ParseIP("172.16.12.0"), Mask: net.IPv4Mask(255, 255, 255, 0)}, "1-ff00:0:112,172.16.0.12")
	if err != nil {
		panic(err)
	}
	err = db.InsertSubnet(1, net.IPNet{IP: net.ParseIP("172.16.13.0"), Mask: net.IPv4Mask(255, 255, 255, 0)}, "1-ff00:0:113,172.16.0.13")
	if err != nil {
		panic(err)
	}

	t := map[int][]int{
		1:   {1, 345},
		345: {345, 1},
		456: {2, 3, 4, 5},
	}

	err = db.InsertTransfers(t)
	if err != nil {
		panic(err)
	}
	return db
}
