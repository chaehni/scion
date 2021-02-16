package mondrian

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var headerLength = 36

type MondrianLayer struct {
	layers.BaseLayer           // header content and payload content
	Type             uint8     // one byte
	ZoneID           uint32    // 3 bytes
	TimeStamp        time.Time // 4 bytes
	Nonce            []byte    // 12 bytes
	MAC              []byte    // 16 bytes
}

var MondrianLayerType = gopacket.OverrideLayerType(int(layers.LayerTypeVRRP), gopacket.LayerTypeMetadata{Name: "Mondrian", Decoder: gopacket.DecodeFunc(decodeLayer)})

func (m MondrianLayer) LayerType() gopacket.LayerType {
	return MondrianLayerType
}

func (m *MondrianLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	buf, _ := b.PrependBytes(headerLength)
	buf[0] = m.Type
	dummy := make([]byte, 4)
	binary.LittleEndian.PutUint32(dummy, m.ZoneID)
	copy(buf[1:4], dummy)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(m.TimeStamp.Unix()))
	copy(buf[8:20], m.Nonce)
	copy(buf[20:36], m.MAC)
	return nil
}

func (m *MondrianLayer) LayerContents() []byte {
	return m.Contents
}

func (m *MondrianLayer) LayerPayload() []byte {
	return m.Payload
}

func (m *MondrianLayer) CanDecode() gopacket.LayerClass {
	return MondrianLayerType
}

func (m *MondrianLayer) NextLayerType() gopacket.LayerType {
	//return gopacket.LayerTypePayload
	return gopacket.LayerTypePayload
}

func (m *MondrianLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < headerLength {
		return fmt.Errorf("Not enough bytes for being a Mondrian Header. %v < %v.", len(data), headerLength)
	}
	m.Type = data[0]
	dummy := make([]byte, 4)
	copy(dummy, data[1:4])
	m.ZoneID = binary.LittleEndian.Uint32(dummy)
	m.TimeStamp = time.Unix(int64(binary.LittleEndian.Uint32(data[4:8])), 0)
	m.Nonce = data[8:20]
	m.MAC = data[20:36]

	m.Contents = data[:36]
	m.Payload = data[36:]

	return nil
}

func (m *MondrianLayer) Encrypt(key []byte) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	res := aead.Seal(nil, m.Nonce, m.Payload, m.Contents)
	m.Payload = res[:len(m.Payload)]
	m.MAC = res[len(m.Payload):]

	return nil
}

func (m *MondrianLayer) Decrypt(key []byte) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	buf := append(m.Payload, m.MAC...)
	m.Payload, err = aead.Open(nil, m.Nonce, buf, m.Contents)
	if err != nil {
		return err
	}
	return nil
}

func decodeLayer(data []byte, p gopacket.PacketBuilder) error {
	m := &MondrianLayer{}
	err := m.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(m)
	return p.NextDecoder(m.NextLayerType())
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}
