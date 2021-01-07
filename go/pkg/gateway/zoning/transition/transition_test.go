package transition_test

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"testing"

	"github.com/scionproto/scion/go/sig/zoning"
	"github.com/scionproto/scion/go/sig/zoning/tpconfig"
	"github.com/scionproto/scion/go/sig/zoning/transition"
	"github.com/scionproto/scion/go/sig/zoning/types"
)

func BenchmarkHandleIngressSuccess(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}
	for _, s := range sizes {
		b.Run(fmt.Sprintf("%v subnets", s), func(b *testing.B) {
			n, t := setupRules(s, s)
			fetcher := transition.NewMockFetcher(n, t)
			cfg := tpconfig.TransConf{}
			cfg.InitDefaults()
			module := transition.NewModule(fetcher, cfg)
			module.StartFetcher()

			buf := [500]byte{}
			srcIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(srcIP, uint32(s-1))
			destIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(destIP, uint32(s-1))
			pkt := zoning.Packet{Ingress: true, SrcHost: srcIP, DstHost: destIP, RawPacket: buf[:], RemoteTP: "1-ff00:0:1,127.0.0.1"}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := module.Handle(pkt)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

}

func BenchmarkHandleIngressFirstIPNotFound(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}
	for _, s := range sizes {
		b.Run(fmt.Sprintf("%v subnets", s), func(b *testing.B) {
			n, t := setupRules(s, s)
			fetcher := transition.NewMockFetcher(n, t)
			cfg := tpconfig.TransConf{}
			cfg.InitDefaults()
			module := transition.NewModule(fetcher, cfg)
			module.StartFetcher()

			buf := [500]byte{}
			matchingIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(matchingIP, uint32(s-1))
			pkt := zoning.Packet{Ingress: true, SrcHost: net.IPv4(1, 0, 0, 2), DstHost: matchingIP, RawPacket: buf[:], RemoteTP: "1-ff00:0:1,127.0.0.1"}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := module.Handle(pkt)
				if err == nil {
					log.Fatal("expected error")
				}
			}
		})
	}
}

func BenchmarkHandleIngressSecondIPNotFound(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}
	for _, s := range sizes {
		b.Run(fmt.Sprintf("%v subnets", s), func(b *testing.B) {
			n, t := setupRules(s, 1)
			fetcher := transition.NewMockFetcher(n, t)
			cfg := tpconfig.TransConf{}
			cfg.InitDefaults()
			module := transition.NewModule(fetcher, cfg)
			module.StartFetcher()

			buf := [500]byte{}
			matchingIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(matchingIP, uint32(s-1))
			pkt := zoning.Packet{Ingress: true, SrcHost: matchingIP, DstHost: net.IPv4(1, 0, 0, 2), RawPacket: buf[:], RemoteTP: "1-ff00:0:1,127.0.0.1"}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := module.Handle(pkt)
				if err == nil {
					log.Fatal("expected error")
				}
			}
		})
	}
}

func BenchmarkTransferNotAllowed(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}
	for _, s := range sizes {
		b.Run(fmt.Sprintf("%v transition rules", s), func(b *testing.B) {
			n, t := setupRules(s, s-1)
			fetcher := transition.NewMockFetcher(n, t)
			cfg := tpconfig.TransConf{}
			cfg.InitDefaults()
			module := transition.NewModule(fetcher, cfg)
			module.StartFetcher()

			buf := [500]byte{}
			srcIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(srcIP, uint32(s-1))
			destIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(destIP, uint32(s-2))
			pkt := zoning.Packet{Ingress: true, SrcHost: srcIP, DstHost: destIP, RawPacket: buf[:], RemoteTP: "1-ff00:0:1,127.0.0.1"}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := module.Handle(pkt)
				if err == nil {
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
		nets = append(nets, &types.Subnet{IPNet: net.IPNet{IP: ip, Mask: net.IPv4Mask(255, 255, 255, 255)}, ZoneID: types.ZoneID(subs) - 1, TPAddr: "1-ff00:0:1,127.0.0.1"})

	}
	t := types.Transitions{
		types.ZoneID(subs) - 1: {},
	}
	for i := 0; i < trans; i++ {
		t[types.ZoneID(subs)-1] = append(t[types.ZoneID(subs)-1], types.ZoneID(i))
	}
	return nets, t
}
