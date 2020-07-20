package zoning_test

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/sig/zoning"
	"github.com/scionproto/scion/go/sig/zoning/auth"
	"github.com/scionproto/scion/go/sig/zoning/tpconfig"
	"github.com/scionproto/scion/go/sig/zoning/transfer"
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
	cfg := tpconfig.TPConf{}
	cfg.InitDefaults()

	cm := zoning.NewCoreModule()
	subs, trans := setupRules(10000)
	fetcher := transfer.NewMockFetcher(subs, trans)
	tm := transfer.NewModule(fetcher, cfg.TransConf)
	tm.StartFetcher()

	chain := zoning.Chain{}
	chain.Register(cm, tm)

	raw := make([]byte, 1400)
	raw[ipVerOffset] = byte(ip4Ver << 4)
	copy(raw[ip4SrcOff:ip4SrcOff+4], net.IPv4(0, 0, 0, 1).To4())
	copy(raw[ip4DstOff:ip4DstOff+4], net.IPv4(0, 0, 0, 2).To4())
	pkt := zoning.Packet{
		RawPacket: raw,
	}

	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := chain.Handle(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}

}

func BenchmarkRemoteEgress(b *testing.B) {
	cfg := tpconfig.TPConf{}
	cfg.InitDefaults()

	cm := zoning.NewCoreModule()
	subs, trans := setupRules(10000)
	fetcher := transfer.NewMockFetcher(subs, trans)
	tm := transfer.NewModule(fetcher, cfg.TransConf)
	tm.StartFetcher()
	km := auth.NewKeyMan([]byte("master_secret"), net.IP{}, cfg.AuthConf, true)
	mock_km := auth.NewMockKeyMan(km)
	am := auth.NewModule(mock_km, auth.NewTR(), cfg.AuthConf)

	chain := zoning.Chain{}
	chain.Register(cm, tm, am)

	raw := make([]byte, 1400)
	raw[ipVerOffset] = byte(ip4Ver << 4)
	copy(raw[ip4SrcOff:ip4SrcOff+4], net.IPv4(0, 0, 0, 1).To4())
	copy(raw[ip4DstOff:ip4DstOff+4], net.IPv4(0, 0, 0, 2).To4())
	pkt := zoning.Packet{
		RawPacket: raw,
	}

	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := chain.Handle(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}

}

func BenchmarkRemoteInress(b *testing.B) {
	cfg := tpconfig.TPConf{}
	cfg.InitDefaults()
	cfg.AuthConf.MaxTimeDiff = util.DurWrap{Duration: 24 * time.Hour}

	cm := zoning.NewCoreModule()
	subs, trans := setupRules(10000)
	fetcher := transfer.NewMockFetcher(subs, trans)
	tm := transfer.NewModule(fetcher, cfg.TransConf)
	tm.StartFetcher()
	km := auth.NewKeyMan([]byte("master_secret"), net.IP{}, cfg.AuthConf, true)
	mock_km := auth.NewMockKeyMan(km)
	tr := auth.NewTR()
	am := auth.NewModule(mock_km, tr, cfg.AuthConf)

	chain := zoning.Chain{}
	chain.Register(am, cm, tm)

	raw := make([]byte, 1400)
	raw[ipVerOffset] = byte(ip4Ver << 4)
	copy(raw[ip4SrcOff:ip4SrcOff+4], net.IPv4(0, 0, 0, 1).To4())
	copy(raw[ip4DstOff:ip4DstOff+4], net.IPv4(0, 0, 0, 2).To4())

	pkt := zoning.Packet{
		RemoteTP:  "1-ff00:0:1,127.0.0.1",
		RawPacket: raw,
	}
	pkt, err := am.Handle(pkt)
	if err != nil {
		b.Fatal(err)
	}
	pkt.Ingress = true
	buf := make([]byte, 1400+tr.Overhead())
	copy(buf, pkt.RawPacket)

	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(pkt.RawPacket, buf)
		_, err := chain.Handle(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}

}

func setupRules(size int) (types.Subnets, types.Transfers) {
	nets := types.Subnets{}
	for i := 0; i < size; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(i))
		nets = append(nets, &types.Subnet{IPNet: net.IPNet{IP: ip, Mask: net.IPv4Mask(255, 255, 255, 255)}, ZoneID: 1, TPAddr: "1-ff00:0:1,127.0.0.1"})

	}
	t := types.Transfers{
		1: {1},
	}
	return nets, t
}
