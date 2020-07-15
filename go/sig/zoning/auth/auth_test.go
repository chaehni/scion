package auth

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"hash"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
)

var master = []byte("my_very_secure_master_secret")

var remote = "1-ff00:0:0,127.0.0.1"
var byteRes []byte
var stringRes string
var hashRes hash.Hash
var aeadRes cipher.AEAD

func BenchmarkInitMac(b *testing.B) {
	var key [16]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hashRes, _ = initMac(key[:])
	}
}

func BenchmarkDeriveL1KeyFromMaster(b *testing.B) {
	keyman := &KeyMan{ms: master, keyLength: 16, keyTTL: 24 * time.Hour}
	keyman.refreshL0()
	//var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		byteRes, _ = keyman.DeriveL1Key(remote)
		/* if err != nil {
			b.Fatal(err)
		} */
	}
}

func BenchmarkDeriveL2KeyFromMaster(b *testing.B) {
	keyman := &KeyMan{ms: master, keyLength: 16, keyTTL: 24 * time.Hour}
	keyman.refreshL0()
	//var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		byteRes, _ = keyman.DeriveL2Key(remote, 50)
		/* if err != nil {
			b.Fatal(err)
		} */
	}
}

func BenchmarkFetchL1FromCache(b *testing.B) {
	sizes := []int{10, 100, 1000, 10000, 100000, 1000000, 10000000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			keyman := &KeyMan{keyCache: cache.New(time.Hour, -1), keyLength: 16}
			fillKeyStore(keyman.keyCache, size)
			remotes := make([]string, size)
			for i := 0; i < size; i++ {
				remotes[i] = fmt.Sprintf("%d-%x:%x:%x,127.0.0.1", i%99, i%0xffff, i%0xf, i%0xf)
			}
			//var err error
			fillKeyStore(cache.New(cache.DefaultExpiration, -1), 100000)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				num := mrand.Intn(size)
				byteRes, _, _ = keyman.FetchL1Key(remotes[num])
				/* if err != nil {
					b.Fatal(err)
				} */
			}
		})
	}
}

func BenchmarkDeriveL2FromCachedL1(b *testing.B) {
	sizes := []int{10, 100, 1000, 10000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			keyman := &KeyMan{keyCache: cache.New(time.Hour, -1), keyLength: 16}
			fillKeyStore(keyman.keyCache, size)
			remotes := make([]string, size)
			for i := 0; i < size; i++ {
				remotes[i] = fmt.Sprintf("%d-%x:%x:%x,127.0.0.1", i%99, i%0xffff, i%0xf, i%0xf)
			}
			//var err error

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				num := mrand.Intn(size)
				byteRes, _, _ = keyman.FetchL2Key(remotes[num], 0)
				/* if err != nil {
					b.Fatal(err)
				} */
			}
		})
	}
}

/* func BenchmarkSprintf(b *testing.B) {
	sizes := []int{10, 100, 1000, 10000}
	for _, size := range sizes {

		b.ResetTimer()
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				num := mrand.Intn(size)
				stringRes = fmt.Sprintf("%d-%x:%x:%x,127.0.0.1", num%99, num, num, num)
			}
		})
	}
} */

func BenchmarkNewAEAD(b *testing.B) {
	var key [16]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aeadRes, _ = newAEAD(key[:])
	}
}
func BenchmarkToIR(b *testing.B) {
	sizes := []int{100, 500, 1000, 1500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			tr := NewTR()
			var key [16]byte
			packet := make([]byte, size)
			rand.Read(packet)

			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				byteRes, _ = tr.ToIR(remote, key[:], packet, 0)
			}
		})
	}
}

func BenchmarkFromIR(b *testing.B) {
	sizes := []int{100, 500, 1000, 1500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			tr := NewTR()
			var key [16]byte
			packet := make([]byte, size)
			rand.Read(packet)
			cipher, _ := tr.ToIR(remote, key[:], packet[:], 0)
			buf := make([]byte, size+tr.Overhead())

			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(buf, cipher)
				byteRes, _, _ = tr.FromIR(key[:], buf)
			}
		})
	}
}

func BenchmarkCopy(b *testing.B) {
	sizes := []int{100, 500, 1000, 1500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("copy size %d", size), func(b *testing.B) {
			srcBuf := make([]byte, size)
			rand.Read(srcBuf)
			dstBuf := make([]byte, size)
			for i := 0; i < b.N; i++ {
				copy(dstBuf, srcBuf)
			}
		})
	}
}

func fillKeyStore(cache *cache.Cache, n int) {
	for i := 0; i < n; i++ {
		buf := make([]byte, 16)
		rand.Read(buf)
		cache.Set(fmt.Sprintf("%d-%x:%x:%x,127.0.0.1", i%99, i%0xffff, i%0xf, i%0xf), buf, 0)
	}
}
