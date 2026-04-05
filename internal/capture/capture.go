package capture

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type FeatureVector struct {
	Features  [41]float32
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Timestamp time.Time
}

const FeatureChannelBuffer = 512

type PacketCapture interface {
	Start(iface string) error
	StartFromFile(path string) error
	Stop()
	Features() <-chan FeatureVector
}

type Capturer struct {
	features  chan FeatureVector
	stop      chan struct{}
	extractor *Extractor
}

func New() *Capturer {
	return &Capturer{
		features:  make(chan FeatureVector, FeatureChannelBuffer),
		stop:      make(chan struct{}),
		extractor: NewExtractor(),
	}
}

func (c *Capturer) Features() <-chan FeatureVector {
	return c.features
}

func (c *Capturer) Stop() {
	close(c.stop)
}

func (c *Capturer) Start(iface string) error {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("capture: open interface %q: %w", iface, err)
	}

	go c.readPackets(handle)
	return nil
}

func (c *Capturer) StartFromFile(path string) error {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return fmt.Errorf("capture: open pcap file %q: %w", path, err)
	}

	go c.readPackets(handle)
	return nil
}

func (c *Capturer) readPackets(handle *pcap.Handle) {
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	for {
		select {
		case <-c.stop:
			return
		default:
		}

		packet, err := src.NextPacket()
		if err != nil {
			return
		}

		fv, ok := c.extractor.Extract(packet)
		if !ok {
			continue
		}

		select {
		case c.features <- fv:
		default:
			log.Println("capture: channel full, dropping feature vector")
		}
	}
}
