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
var remote = "0000000000000000"
var byteRes []byte
var stringRes string
var hashRes hash.Hash
var aeadRes cipher.AEAD

var km = &KeyMan{ms: master, keyCache: cache.New(cache.NoExpiration, -1), keyLength: 16}

func BenchmarkInitMac(b *testing.B) {
	var key [16]byte
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hashRes, err = initMac(key[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveL1KeyFromMaster(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			keyman := &KeyMan{ms: master, keyCache: cache.New(cache.NoExpiration, -1), keyLength: 16, keyTTL: 24 * time.Hour}
			keyman.refreshL0()
			var err error

			err = keyman.FillKeyStoreFakeKeys(size)
			if err != nil {
				b.Fatal(err)
			}
			if keyman.keyCache.ItemCount() != size {
				b.Fatal("wrong keystore size")
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				byteRes, err = keyman.DeriveL1Key(remote)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDeriveL2KeyFromMaster(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			keyman := &KeyMan{ms: master, keyCache: cache.New(cache.NoExpiration, -1), keyLength: 16, keyTTL: 24 * time.Hour}
			keyman.refreshL0()
			var err error

			err = keyman.FillKeyStoreFakeKeys(size)
			if err != nil {
				b.Fatal(err)
			}
			if keyman.keyCache.ItemCount() != size {
				b.Fatal("wrong keystore size")
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				byteRes, err = keyman.DeriveL2Key(remote, 50)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkFetchL1FromCache(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			var err error
			keyman := &KeyMan{ms: master, keyCache: cache.New(cache.NoExpiration, -1), keyLength: 16}
			err = keyman.FillKeyStoreFakeKeys(size)
			if err != nil {
				b.Fatal(err)
			}
			if keyman.keyCache.ItemCount() != size {
				b.Fatal("wrong keystore size")
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				byteRes, _, err = keyman.FetchL1Key(remote)
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
			keyman := &KeyMan{ms: master, keyCache: cache.New(cache.NoExpiration, -1), keyLength: 16}
			keyman.FillKeyStoreFakeKeys(size)
			if keyman.keyCache.ItemCount() != size {
				b.Fatal("wrong keystore size")
			}

			var err error
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				byteRes, _, err = keyman.FetchL2Key(remote, 0)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDeriveL2FromGivenL1(b *testing.B) {
	sizes := []int{100, 1000, 10000, 50000, 100000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d keys", size), func(b *testing.B) {
			keyman := &KeyMan{ms: master, keyCache: cache.New(cache.NoExpiration, -1), keyLength: 16}
			keyman.FillKeyStoreFakeKeys(size)
			if keyman.keyCache.ItemCount() != size {
				b.Fatal("wrong keystore size")
			}
			key := [16]byte{}
			keyman.keyCache = cache.New(cache.NoExpiration, -1)

			var err error
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				byteRes, err = keyman.DeriveL2ForGivenL1(key[:], remote, 0)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkNewAEAD(b *testing.B) {
	var key [16]byte
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aeadRes, err = newAEAD(key[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkToIR(b *testing.B) {
	sizes := []int{100, 500, 1000, 1500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			tr := NewTR()
			var key [16]byte
			var err error
			packet := make([]byte, size)
			rand.Read(packet)

			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				byteRes, err = tr.ToIR(remote, key[:], packet, 0)
				if err != nil {
					b.Fatal(err)
				}
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
			var err error
			packet := make([]byte, size)
			rand.Read(packet)
			cipher, _ := tr.ToIR(remote, key[:], packet[:], 0)
			buf := make([]byte, size+tr.Overhead())

			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(buf, cipher)
				byteRes, _, err = tr.FromIR(key[:], buf)
				if err != nil {
					b.Fatal(err)
				}
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
			var err error
			cfg := tpconfig.TPConf{}
			cfg.InitDefaults()
			cfg.AuthConf.MaxTimeDiff = util.DurWrap{Duration: 24 * time.Hour}

			km := NewKeyMan([]byte("master_secret"), net.IP{}, cfg.AuthConf, true)
			err = km.FillKeyStore(1000)
			if err != nil {
				b.Fatal(err)
			}
			if km.keyCache.ItemCount() != 1000 {
				b.Fatal("wrong keystore size")
			}
			tr := NewTR()
			am := NewModule(km, tr, cfg.AuthConf)

			pkt := zoning.Packet{
				RemoteTP:  remote,
				RawPacket: make([]byte, size+tr.Overhead()),
				Ingress:   true,
			}

			// set invalid timestamp
			binary.LittleEndian.PutUint32(pkt.RawPacket[timeOffset:timeOffset+timeLength], 0)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err = am.Handle(pkt)
				if err == nil {
					b.Fatal("exptected timestamp error")
				}
			}
		})
	}
}

func BenchmarkRemoteIngressInvalidMAC(b *testing.B) {
	sizes := []int{64, 128, 256, 512, 1024, 1512}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			var err error
			cfg := tpconfig.TPConf{}
			cfg.InitDefaults()
			cfg.AuthConf.MaxTimeDiff = util.DurWrap{Duration: 24 * time.Hour}

			km := NewKeyMan([]byte("master_secret"), net.IP{}, cfg.AuthConf, true)
			err = km.FillKeyStore(1000)
			if err != nil {
				b.Fatal(err)
			}
			if km.keyCache.ItemCount() != 1000 {
				b.Fatal("wrong keystore size")
			}
			tr := NewTR()
			am := NewModule(km, tr, cfg.AuthConf)

			pkt := zoning.Packet{
				RemoteTP:  remote,
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

/* func fillKeyStore(cache *cache.Cache, n int) {
	for i := 0; i < n; i++ {
		buf := make([]byte, 16)
		rand.Read(buf)
		cache.Set(fmt.Sprintf("%d-%x:%x:%x,127.0.0.1", i%99, i%0xffff, i%0xf, i%0xf), buf, time.Hour)
	}
} */
