package auth

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"net"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/sig/zoning"
	"github.com/scionproto/scion/go/sig/zoning/tpconfig"
)

var master = []byte("my_very_secure_master_secret")

var remote = "0-0:0:0,127.0.0.1"
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
	sizes := []int{100, 1000, 10000, 100000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			keyman := &KeyMan{keyCache: cache.New(cache.NoExpiration, -1), keyLength: 16}
			fillKeyStore(keyman.keyCache, size)
			/* queries := make([]string, size)
			for i := 0; i < size; i++ {
				num := mrand.Intn(size)
				queries[i] = fmt.Sprintf("%d-%x:%x:%x,127.0.0.1", num%99, num%0xffff, num%0xf, num%0xf)
			}
			un := queries[0] */
			var err error

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				byteRes, _, _ = keyman.FetchL1Key(remote)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDeriveL2FromCachedL1(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			keyman := &KeyMan{keyCache: cache.New(cache.NoExpiration, -1), keyLength: 16}
			fillKeyStore(keyman.keyCache, size)
			/* queries := make([]string, size)
			for i := 0; i < size; i++ {
				num := mrand.Intn(size)
				queries[i] = fmt.Sprintf("%d-%x:%x:%x,127.0.0.1", num%99, num%0xffff, num%0xf, num%0xf)
			}
			un := queries[0] */
			var err error
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				byteRes, _, _ = keyman.FetchL2Key(remote, 0)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

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

func BenchmarkFromIRWrongMAC(b *testing.B) {
	sizes := []int{100, 500, 1000, 1500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			tr := NewTR()
			var key [16]byte
			packet := make([]byte, size)
			rand.Read(packet)

			b.SetBytes(int64(size))
			b.ResetTimer()
			var err error
			for i := 0; i < b.N; i++ {
				byteRes, _, err = tr.FromIR(key[:], packet)
				if err == nil {
					b.Fatal("expected auth error")
				}
			}
		})
	}
}

func BenchmarkRemoteIngressExpiredTimestamp(b *testing.B) {
	sizes := []int{64, 128, 256, 512, 1024, 1512}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			cfg := tpconfig.TPConf{}
			cfg.InitDefaults()
			cfg.AuthConf.MaxTimeDiff = util.DurWrap{Duration: 24 * time.Hour}

			km := NewKeyMan([]byte("master_secret"), net.IP{}, cfg.AuthConf, true)
			km.FillKeyStore(1000)
			tr := NewTR()
			am := NewModule(km, tr, cfg.AuthConf)

			pkt := zoning.Packet{
				RemoteTP:  "0-0:0:0,127.0.0.1",
				RawPacket: make([]byte, size+tr.Overhead()),
				Ingress:   true,
			}

			// set invalid timestamp
			binary.LittleEndian.PutUint32(pkt.RawPacket[timeOffset:timeOffset+timeLength], 0)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				am.Handle(pkt)
				/* if err == nil {
					b.Fatal("exptected timestamp error")
				} */
			}
		})
	}
}

func BenchmarkRemoteIngressInvalidMAC(b *testing.B) {
	sizes := []int{64, 128, 256, 512, 1024, 1512}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			cfg := tpconfig.TPConf{}
			cfg.InitDefaults()
			cfg.AuthConf.MaxTimeDiff = util.DurWrap{Duration: 24 * time.Hour}

			km := NewKeyMan([]byte("master_secret"), net.IP{}, cfg.AuthConf, true)
			km.FillKeyStore(100)
			tr := NewTR()
			am := NewModule(km, tr, cfg.AuthConf)

			pkt := zoning.Packet{
				RemoteTP:  "0-0:0:0,127.0.0.1",
				RawPacket: make([]byte, size+tr.Overhead()),
				Ingress:   true,
			}

			// set valid timestamp
			binary.LittleEndian.PutUint32(pkt.RawPacket[timeOffset:timeOffset+timeLength], uint32(time.Now().Unix()))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				//binary.LittleEndian.PutUint32(pkt.RawPacket[timeOffset:timeOffset+timeLength], uint32(time.Now().Unix()))
				_, err := am.Handle(pkt)
				if err == nil {
					b.Fatal("expected invalid MAC error")
				}
			}
		})
	}
}

func BenchmarkPutTimestamp(b *testing.B) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(time.Now().Unix()))
	cfg := tpconfig.TPConf{}
	cfg.InitDefaults()
	cfg.AuthConf.MaxTimeDiff = util.DurWrap{Duration: 24 * time.Hour}

	km := NewKeyMan([]byte("master_secret"), net.IP{}, cfg.AuthConf, true)
	tr := NewTR()
	am := NewModule(km, tr, cfg.AuthConf)
	for i := 0; i < b.N; i++ {
		ts := time.Unix(int64(binary.LittleEndian.Uint32(buf)), 0)
		err := am.checkTime(ts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenEnc(b *testing.B) {
	sizes := []int{64, 128, 256, 512, 1024, 1512}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			pkt := make([]byte, size)
			nonce := make([]byte, 12)
			ad := make([]byte, 36)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				aead, _ := newAEAD(make([]byte, 16))
				_, err := aead.Open(pkt, nonce, pkt, ad)
				if err == nil {
					b.Fatal(err)
				}
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
		cache.Set(fmt.Sprintf("%d-%x:%x:%x,127.0.0.1", i%99, i%0xffff, i%0xf, i%0xf), buf, time.Hour)
	}
}
