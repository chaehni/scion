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

	"github.com/scionproto/scion/go/pkg/gateway/zoning/controller/sqlite"
	"github.com/scionproto/scion/go/pkg/gateway/zoning/types"
)

var db *sqlite.Backend

func init() {
	// get a database handle
	db = setupDB()
}

// IndexHandler handles the default route
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Hello from the Controller")
}

/*** GET Handlers (Read) ***/

// GetAllSitesHandler returns all sites information to the client
func GetAllSitesHandler(w http.ResponseWriter, r *http.Request) {
	sites, err := db.GetAllSites()
	encodeAndSend(sites, err, w)
}

// GetAllZonesHandler returns all sites information to the client
func GetAllZonesHandler(w http.ResponseWriter, r *http.Request) {
	zones, err := db.GetAllZones()
	encodeAndSend(zones, err, w)
}

// GetAllSubnetsHandler returns all subnet information to the client
func GetAllSubnetsHandler(w http.ResponseWriter, r *http.Request) {
	nets, err := db.GetAllSubnets()
	encodeAndSend(nets, err, w)
}

// GetAllTransitionsHandler returns all transition information to the client
func GetAllTransitionsHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: the shttp package is very basic and does not allow to set the local address
	// therefore the handler sees the default ISD-AS,127.0.0.1 address as remote. The public IP of the TP is therfore sent
	// in the body. This should be checked to match the certificate
	transitions, err := db.GetAllTransitions()
	encodeAndSend(transitions, err, w)
}

// GetSubnetsHandler returns the subnet information for a given TP to the client
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
	encodeAndSend(nets, err, w)
}

// GetTransitionsHandler returns all transition information to the client
func GetTransitionsHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: the shttp package is very basic and does not allow to set the local address
	// therefore the handler sees the default ISD-AS,127.0.0.1 address as remote. The public IP of the TP is therfore sent
	// in the body. This should be checked to match the certificate
	defer r.Body.Close()
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	transitions, err := db.GetTransitions(string(buf))
	encodeAndSend(transitions, err, w)
}

func encodeAndSend(data interface{}, err error, w http.ResponseWriter) {
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ") //TODO: remove after testing
	enc.Encode(data)
}

/*** POST Handlers (Insert) ***/

// InsertSitesHandler inserts the given sites into the backend
func InsertSitesHandler(w http.ResponseWriter, r *http.Request) {
	// decode body into site
	var sites []types.Site
	err := json.NewDecoder(r.Body).Decode(&sites)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	err = db.InsertSites(sites)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// InsertZonesHandler inserts the given zones into the backend
func InsertZonesHandler(w http.ResponseWriter, r *http.Request) {
	// decode body into site
	var zones []types.Zone
	err := json.NewDecoder(r.Body).Decode(&zones)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	err = db.InsertZones(zones)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// InsertSubnetsHandler inserts the given subnets into the backend
func InsertSubnetsHandler(w http.ResponseWriter, r *http.Request) {
	// decode body into site
	var subnets []types.Subnet
	err := json.NewDecoder(r.Body).Decode(&subnets)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	err = db.InsertSubnets(subnets)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// InsertTransitionsHandler inserts the given transitions into the backend
func InsertTransitionsHandler(w http.ResponseWriter, r *http.Request) {
	// decode body into transitions
	var transitions types.Transitions
	err := json.NewDecoder(r.Body).Decode(&transitions)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	err = db.InsertTransitions(transitions)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/*** Delete Handlers (Delete) ***/

// DeleteSitesHandler deletes the given sites from the backend
func DeleteSitesHandler(w http.ResponseWriter, r *http.Request) {
	// decode body into sites
	var sites []types.Site
	err := json.NewDecoder(r.Body).Decode(&sites)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	err = db.DeleteSites(sites)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DeleteZonesHandler deletes the given zones from the backend
func DeleteZonesHandler(w http.ResponseWriter, r *http.Request) {
	// decode body into zones
	var zones []types.Zone
	err := json.NewDecoder(r.Body).Decode(&zones)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	err = db.DeleteZones(zones)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DeleteSubnetsHandler deletes the given subnets from the backend
func DeleteSubnetsHandler(w http.ResponseWriter, r *http.Request) {
	// decode body into subnets
	var subnets []types.Subnet
	err := json.NewDecoder(r.Body).Decode(&subnets)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	err = db.DeleteSubnets(subnets)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DeleteTransitionsHandler deletes the given transitions from the backend
func DeleteTransitionsHandler(w http.ResponseWriter, r *http.Request) {
	// decode body into transitions
	var transitions types.Transitions
	err := json.NewDecoder(r.Body).Decode(&transitions)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	err = db.DeleteTransitions(transitions)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	err = db.InsertZones([]types.Zone{
		{ID: 1, Name: "gNB1"},
		{ID: 2, Name: "gNB2"},
		{ID: 3, Name: "MEC"},
	})
	if err != nil {
		panic(err)
	}

	/* err = db.InsertZone(3, "other")
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
	} */

	err = db.InsertSites([]types.Site{{TPAddr: "1-ff00:0:112,127.0.0.1", Name: "Site A"}})
	if err != nil {
		panic(err)
	}

	/* err = db.InsertSite("1-ff00:0:113,172.16.0.13", "Site B")
	if err != nil {
		panic(err)
	} */

	err = db.InsertSubnets([]types.Subnet{
		{IPNet: net.IPNet{IP: net.IPv4(192, 168, 17, 90).To4(), Mask: net.IPv4Mask(255, 255, 255, 255)}, ZoneID: 1, TPAddr: "1-ff00:0:112,127.0.0.1"}, // gNB1
		{net.IPNet{IP: net.IPv4(192, 168, 17, 91).To4(), Mask: net.IPv4Mask(255, 255, 255, 255)}, 2, "1-ff00:0:112,127.0.0.1"},                        // gNB 2
		{net.IPNet{IP: net.IPv4(192, 168, 14, 100).To4(), Mask: net.IPv4Mask(255, 255, 255, 255)}, 3, "1-ff00:0:112,127.0.0.1"},                       // MEC App Server
	})
	if err != nil {
		panic(err)
	}

	t := types.Transitions{
		1: {2, 3},
		2: {3},
		3: {1, 2},
	}

	err = db.InsertTransitions(t)
	if err != nil {
		panic(err)
	}
	return db
}
