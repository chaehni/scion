package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/sig/zoning/auth"
)

func main() {

	/* key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	//plaintext := []byte("exampleplaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	t := auth.NewTransformer(gcm)

	plain := []byte("This is super secret")
	ad := []byte("|234567|")

	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {

		wg.Add(1)

		go func() {
			for c := 0; c < 1000; c++ {
				cipher, err := t.ToIR(plain, ad)
				if err != nil {
					fmt.Println(err)
				}
				//fmt.Printf("%v\n", cipher)
				_, _, err = t.FromIR(cipher)
				if err != nil {
					fmt.Println(err)
				}

				//fmt.Printf("%s\n", plaintxt)

			}
			wg.Done()
		}()
	}
	wg.Wait() */

	// set up scion network context
	ds := reliable.NewDispatcher("")
	sciondConn, err := sciond.NewService(sciond.DefaultSCIONDAddress).Connect(context.Background())
	if err != nil {
		fmt.Println(err)
	}
	listenAddr, err := snet.ParseUDPAddr("17-ffaa:1:89,127.0.0.1")
	if err != nil {
		fmt.Println(err)
	}
	pathQuerier := &sciond.Querier{Connector: sciondConn, IA: listenAddr.IA, MaxPaths: 5}
	network := snet.NewNetworkWithPR(listenAddr.IA, ds, pathQuerier, sciond.RevHandler{Connector: sciondConn})
	if err != nil {
		fmt.Println(err)
	}
	err = squic.Init("key.pem", "cert.pem")
	if err != nil {
		panic(err)
	}

	keyman := auth.NewKeyMan([]byte("KEY"), network, pathQuerier, listenAddr.Host.IP)
	if err != nil {
		panic(err)
	}

	ch := make(chan error)
	keyman.ServeL1(ch)

	wg := sync.WaitGroup{}

	start := time.Now()
	for i := 0; i < 1000; i++ {
		go func() {
			wg.Add(1)
			for i := 0; i < 1000; i++ {
				_, _, err := keyman.FetchL1Key("17-ffaa:1:89,127.0.0.1")
				if err != nil {
					panic(err)
				}
				//fmt.Printf("%+v\n", k)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	log.Printf("Fetch took %s", elapsed)

	start = time.Now()
	for i := 0; i < 1000; i++ {
		go func() {
			wg.Add(1)
			for i := 0; i < 1000; i++ {
				_, err := keyman.DeriveL1Key("17-ffaa:1:89,127.0.0.1")
				if err != nil {
					panic(err)
				}
				//fmt.Printf("%+v\n", k)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	elapsed = time.Since(start)
	log.Printf("Derive took %s", elapsed)

	//time.Sleep(time.Minute)
	//wg.Wait()
}
