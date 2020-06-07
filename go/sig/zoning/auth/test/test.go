package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/scionproto/scion/go/sig/zoning/auth"
)

func main() {

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
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
	wg.Wait()
}