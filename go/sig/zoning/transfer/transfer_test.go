package transfer_test

import (
	"encoding/binary"
	"log"
	"net"
	"testing"

	"github.com/scionproto/scion/go/lib/fatal"

	"github.com/scionproto/scion/go/sig/zoning"

	"github.com/scionproto/scion/go/sig/zoning/tpconfig"

	"github.com/scionproto/scion/go/sig/zoning/transfer"
	"github.com/scionproto/scion/go/sig/zoning/types"
)

func BenchmarkHandleIngressSuccess(b *testing.B) {
	size := 1000000
	n, t := setupRules(size, 1)
	fetcher := transfer.NewMockFetcher(n, t)
	cfg := tpconfig.TransConf{}
	cfg.InitDefaults()
	module := transfer.NewModule(fetcher, cfg)
	fatal.Init()
	transfer.Init()
	module.StartFetcher()

	buf := [500]byte{}
	srcIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(srcIP, uint32(1))
	destIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(destIP, uint32(1))
	pkt := zoning.Packet{Ingress: false, SrcHost: srcIP, DstHost: destIP, RawPacket: buf[:], RemoteTP: "1-ff00:0:1,127.0.0.1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := module.Handle(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandleIngressFail(b *testing.B) {
	n, t := setupRules(1000000, 1)
	fetcher := transfer.NewMockFetcher(n, t)
	cfg := tpconfig.TransConf{}
	cfg.InitDefaults()
	module := transfer.NewModule(fetcher, cfg)
	fatal.Init()
	transfer.Init()
	module.StartFetcher()

	buf := [500]byte{}
	pkt := zoning.Packet{Ingress: false, SrcHost: net.IPv4(1, 0, 0, 1), DstHost: net.IPv4(0, 0, 0, 2), RawPacket: buf[:], RemoteTP: "1-ff00:0:1,127.0.0.1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := module.Handle(pkt)
		if err == nil {
			log.Fatal("expected error")
		}
	}
}

func setupRules(subs, trans int) (types.Subnets, types.Transfers) {

	nets := types.Subnets{}

	for i := 0; i < subs; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(i))
		nets = append(nets, &types.Subnet{IPNet: net.IPNet{IP: ip, Mask: net.IPv4Mask(255, 255, 255, 255)}, ZoneID: 1, TPAddr: "1-ff00:0:1,127.0.0.1"})

	}

	t := types.Transfers{
		1: {1},
	}
	return nets, t
}
