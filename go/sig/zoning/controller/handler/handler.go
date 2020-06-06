package handler

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/scionproto/scion/go/sig/zoning/controller/sqlite"
)

var db *sqlite.Backend

var zeroKey []byte
var keySize = 128
var keyLock sync.RWMutex
var keyRefreshInterval = 5 * time.Second

func init() {
	// get a database handle
	db = setupDB()

	// start periodic key refresh task
	zeroKey = make([]byte, keySize)
	err := generateFreshKey()
	if err != nil {
		log.Fatal(err)
	}
	ticker := time.NewTicker(keyRefreshInterval)
	go func() {
		for range ticker.C {
			err := generateFreshKey()
			if err != nil {
				log.Fatal("key generation failed: " + err.Error())
			}
		}
	}()
}

// GetKeyHandler returns the latest 0-level key to the client
func GetKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyLock.RLock()
	defer keyLock.RUnlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(zeroKey)
}

// GetSubnetsHandler returns all subnet information to the client
func GetSubnetsHandler(w http.ResponseWriter, r *http.Request) {
	nets, err := db.GetAllSubnets()
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
	transfers, err := db.GetAllTransfers()
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

	err = db.InsertSite(net.ParseIP("8.8.9.8"), "Main DC")
	if err != nil {
		panic(err)
	}
	err = db.InsertSubnet(1, net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}, net.ParseIP("8.8.9.8"))
	if err != nil {
		panic(err)
	}
	err = db.InsertSubnet(345, net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.IPv4Mask(255, 0, 255, 0)}, net.ParseIP("8.8.9.8"))
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

func generateFreshKey() error {
	keyLock.Lock()
	defer keyLock.Unlock()
	_, err := rand.Read(zeroKey)
	if err != nil {
		return err
	}
	return nil
}
