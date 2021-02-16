package main

import (
	"fmt"
	"net"
	"time"

	"example.com/gopacket/mondrian"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {

	// Serialize a packet with 3 layers: IP, Mondrian, Payload
	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{5, 6, 7, 8},
		Version:  4,
		Length:   103,
		IHL:      5,
		Protocol: 112, // VRRP
	}

	m := mondrian.MondrianLayer{
		Type:      1,
		ZoneID:    2,
		TimeStamp: time.Now(),
		Nonce:     []byte{11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12},
	}

	ip2 := layers.IPv4{
		SrcIP:    net.IP{3, 3, 3, 3},
		DstIP:    net.IP{4, 4, 4, 4},
		Version:  4,
		Length:   47,
		IHL:      5,
		Protocol: 6, //TCP
	}

	tcp := layers.TCP{
		SrcPort:    12345,
		DstPort:    8080,
		DataOffset: 5,
	}

	rawBytes := []byte{0xF0, 0x0F, 65, 65, 66, 67, 68}
	pld := gopacket.Payload(rawBytes)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{} // See SerializeOptions for more details.
	err := gopacket.SerializeLayers(buf, opts, &ip, &m, &ip2, &tcp, &pld)

	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(buf.Bytes())

	// now decode again
	var ip_new layers.IPv4
	var m_new mondrian.MondrianLayer

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip_new, &m_new)

	decoded := []gopacket.LayerType{}
	err = parser.DecodeLayers(buf.Bytes(), &decoded)

	if err != nil {
		fmt.Println(err)

	}
	/* 	for _, layerType := range decoded {
		fmt.Println(layerType)
	} */

	fmt.Printf("remote tp is: %v\n", ip_new.SrcIP)

	var key [16]byte

	/* fmt.Println("Outer Packet")
	fmt.Printf("%+v\n\n", m_new)
	fmt.Println(len(m_new.Payload))
	m_new.Encrypt(key[:])
	fmt.Printf("%+v\n", m_new)
	fmt.Println(len(m_new.Payload))

	decoded_inner := []gopacket.LayerType{}
	err = parser.DecodeLayers(m_new.Payload, &decoded_inner)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("src Host is: %v\n", ip_new.SrcIP)

	m_new.Decrypt(key[:])
	err = parser.DecodeLayers(m_new.Payload, &decoded_inner)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%+v\n", ip_new)
	fmt.Printf("src Host is: %v\n", ip_new.SrcIP) */

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	fmt.Println("Outer packet")
	fmt.Println(pkt)

	fmt.Println("\nInner packet (encrypted)")

	mlayer := pkt.Layer(mondrian.MondrianLayerType).(*mondrian.MondrianLayer)
	err = mlayer.Encrypt(key[:])
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(mlayer.LayerPayload())
	pkt = gopacket.NewPacket(mlayer.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default)
	fmt.Println(pkt)

	fmt.Println("\nInner packet (decrypted)")
	err = mlayer.Decrypt(key[:])
	if err != nil {
		fmt.Println(err)
		return
	}
	pkt = gopacket.NewPacket(mlayer.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default)
	fmt.Println(pkt)
}
