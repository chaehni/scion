package zoning_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/sig/zoning"
	"github.com/scionproto/scion/go/sig/zoning/auth"
	"github.com/scionproto/scion/go/sig/zoning/tpconfig"
	"github.com/scionproto/scion/go/sig/zoning/transition"
	"github.com/scionproto/scion/go/sig/zoning/types"
)

var (
	ip4Ver      = 0x4
	ip6Ver      = 0x6
	ipVerOffset = 0
	ip4SrcOff   = 12
	ip4DstOff   = 16
	ip6SrcOff   = 8
	ip6DstOff   = 24
)

func BenchmarkLocal(b *testing.B) {
	sizes := []int{64, 128, 256, 512, 1024, 1512}

	for _, size := range sizes {
		cfg := tpconfig.TPConf{}
		cfg.InitDefaults()

		cm := zoning.NewCoreModule()
		subs, trans := setupRules(100000, 100000)
		fetcher := transition.NewMockFetcher(subs, trans)
		tm := transition.NewModule(fetcher, cfg.TransConf)
		tm.StartFetcher()

		chain := zoning.Chain{}
		chain.Register(cm, tm)

		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			raw := make([]byte, size)
			raw[ipVerOffset] = byte(ip4Ver << 4)
			srcIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(srcIP, uint32(100000-1))
			destIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(destIP, uint32(100000-1))
			copy(raw[ip4SrcOff:ip4SrcOff+4], srcIP.To4())
			copy(raw[ip4DstOff:ip4DstOff+4], destIP.To4())
			pkt := zoning.Packet{
				RawPacket: raw,
			}

			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := chain.Handle(pkt)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

}

func BenchmarkRemoteEgress(b *testing.B) {
	cfg := tpconfig.TPConf{}
	cfg.InitDefaults()

	cm := zoning.NewCoreModule()
	subs, trans := setupRules(100000, 100000)
	fetcher := transition.NewMockFetcher(subs, trans)
	tm := transition.NewModule(fetcher, cfg.TransConf)
	tm.StartFetcher()
	km := auth.NewKeyMan([]byte("master_secret"), net.IP{}, cfg.AuthConf, true)
	km.FillKeyStore(100000)
	am := auth.NewModule(km, auth.NewTR(), cfg.AuthConf)

	chain := zoning.Chain{}
	chain.Register(cm, tm, am)

	sizes := []int{64, 128, 256, 512, 1024, 1512}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {

			raw := make([]byte, size)
			raw[ipVerOffset] = byte(ip4Ver << 4)
			copy(raw[ip4SrcOff:ip4SrcOff+4], net.IPv4(0, 0, 0, 1).To4())
			copy(raw[ip4DstOff:ip4DstOff+4], net.IPv4(0, 0, 0, 2).To4())
			pkt := zoning.Packet{
				RawPacket: raw,
			}

			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := chain.Handle(pkt)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

}

func BenchmarkRemoteIngress(b *testing.B) {
	sizes := []int{64, 128, 256, 512, 1024, 1512}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet size %d", size), func(b *testing.B) {
			cfg := tpconfig.TPConf{}
			cfg.InitDefaults()
			cfg.AuthConf.MaxTimeDiff = util.DurWrap{Duration: 24 * time.Hour}

			cm := zoning.NewCoreModule()
			subs, trans := setupRules(100000, 100000)
			fetcher := transition.NewMockFetcher(subs, trans)
			tm := transition.NewModule(fetcher, cfg.TransConf)
			tm.StartFetcher()
			km := auth.NewKeyMan([]byte("master_secret"), net.IP{}, cfg.AuthConf, true)
			km.FillKeyStore(100)
			tr := auth.NewTR()
			am := auth.NewModule(km, tr, cfg.AuthConf)

			chain := zoning.Chain{}
			chain.Register(am, cm, tm)

			raw := make([]byte, size)
			raw[ipVerOffset] = byte(ip4Ver << 4)
			copy(raw[ip4SrcOff:ip4SrcOff+4], net.IPv4(0, 0, 0, 1).To4())
			copy(raw[ip4DstOff:ip4DstOff+4], net.IPv4(0, 0, 0, 2).To4())

			pkt := zoning.Packet{
				RemoteTP:  "0000000000000001",
				RawPacket: raw,
			}
			pkt, err := am.Handle(pkt)
			if err != nil {
				b.Fatal(err)
			}
			pkt.Ingress = true
			buf := make([]byte, size+tr.Overhead())
			copy(buf, pkt.RawPacket)

			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(pkt.RawPacket, buf)
				_, err := chain.Handle(pkt)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func setupRules(subs, trans int) (types.Subnets, types.Transitions) {
	nets := types.Subnets{}
	for i := 0; i < subs; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(i))
		nets = append(nets, &types.Subnet{IPNet: net.IPNet{IP: ip, Mask: net.IPv4Mask(255, 255, 255, 255)}, ZoneID: types.ZoneID(subs) - 1, TPAddr: fmt.Sprintf("%016x", i)})

	}
	t := types.Transitions{
		types.ZoneID(subs) - 1: {},
	}
	for i := 0; i < trans; i++ {
		t[types.ZoneID(subs)-1] = append(t[types.ZoneID(subs)-1], types.ZoneID(i))
	}
	return nets, t
}
