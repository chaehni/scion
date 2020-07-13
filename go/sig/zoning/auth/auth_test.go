package auth

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"net"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/scionproto/scion/go/sig/zoning/tpconfig"
)

var master = []byte("my_very_secure_master_secret")
var l2Key = []byte("0T3gLwLib7BsnhwV")
var dummyIP = net.IPv4(1, 1, 1, 1)
var remote = "1-ff00:0:0,127.0.0.1"
var result []byte

func BenchmarkDeriveL2KeyFromMaster(b *testing.B) {
	authConf := tpconfig.AuthConf{}
	authConf.InitDefaults()
	keyman := &KeyMan{}
	for i := 0; i < b.N; i++ {
		result, _ = keyman.DeriveL2Key(remote, 50)
	}
}

func BenchmarkDeriveL2FromCachedL1(b *testing.B) {
	sizes := []int{10, 100, 1000, 1000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			authConf := tpconfig.AuthConf{}
			authConf.InitDefaults()
			keyman := &KeyMan{keyCache: cache.New(time.Hour, -1)}
			fillKeyStore(keyman.keyCache, size)
			for i := 0; i < b.N; i++ {
				result, _, _ = keyman.FetchL2Key(remote, 0)
			}
		})
	}
}

func BenchmarkToIR(b *testing.B) {
	sizes := []int{100, 500, 1000, 1500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			tr := NewTR()
			packet := make([]byte, size)
			rand.Read(packet)
			for i := 0; i < b.N; i++ {
				result, _ = tr.ToIR(remote, l2Key, packet, 0)
			}
		})
	}
}

func BenchmarkFromIR(b *testing.B) {
	sizes := []int{100, 500, 1000, 1500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			tr := NewTR()
			packet := make([]byte, size)
			rand.Read(packet)
			cipher, _ := tr.ToIR(remote, l2Key, packet, 0)
			buf := make([]byte, size+tr.Overhead())
			for i := 0; i < b.N; i++ {
				copy(buf, cipher)
				result, _, _ = tr.FromIR(l2Key, buf)
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
		isd := mrand.Intn(98) + 1
		if i == 0 {
			cache.Set(remote, buf, 0)
		} else {
			cache.Set(fmt.Sprintf("%d-%x:0:0,127.0.0.1", isd, i), buf, 0)
		}
	}
}
