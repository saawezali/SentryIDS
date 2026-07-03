package capture

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"sentryids/internal/engine"
)

const (
	snapshotLen int32 = 65535

	flowTimeout = 30 * time.Second

	tickInterval = 5 * time.Second
)

type Capturer struct {
	iface string
	outCh chan<- engine.Features
	flows map[flowKey]*flowRecord
	mu    sync.Mutex
}

func New(iface string, outCh chan<- engine.Features) *Capturer {
	return &Capturer{
		iface: iface,
		outCh: outCh,
		flows: make(map[flowKey]*flowRecord),
	}
}

func (c *Capturer) Start(ctx context.Context) error {
	handle, err := pcap.OpenLive(c.iface, snapshotLen, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("opening interface %s: %w", c.iface, err)
	}

	if err := handle.SetBPFFilter("tcp or udp or icmp"); err != nil {
		handle.Close()
		return fmt.Errorf("setting BPF filter: %w", err)
	}

	go c.packetLoop(ctx, handle)

	go c.timeoutLoop(ctx)

	return nil
}

func (c *Capturer) packetLoop(ctx context.Context, handle *pcap.Handle) {
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)

	for {
		select {
		case <-ctx.Done():
			c.flushAll()
			return

		case packet, ok := <-src.Packets():
			if !ok {
				return
			}
			c.handlePacket(packet)
		}
	}
}

func (c *Capturer) handlePacket(packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	netFlow := netLayer.NetworkFlow()
	srcIP := netFlow.Src().String()
	dstIP := netFlow.Dst().String()

	var (
		srcPort     uint16
		dstPort     uint16
		proto       string
		pktBytes    int
		synFlag     bool
		finFlag     bool
		rstFlag     bool
		urgFlag     bool
		established bool
	)

	pktBytes = len(packet.Data())

	switch t := packet.TransportLayer().(type) {
	case *layers.TCP:
		proto = "tcp"
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		synFlag = t.SYN
		finFlag = t.FIN
		rstFlag = t.RST
		urgFlag = t.URG
		established = t.ACK && !t.SYN

	case *layers.UDP:
		proto = "udp"
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)

	default:
		if packet.NetworkLayer() != nil {
			if _, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
				proto = "icmp"
			}
		}
		if proto == "" {
			return
		}
	}

	key := flowKey{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: proto,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	flow, exists := c.flows[key]
	if !exists {
		flow = &flowRecord{
			key:       key,
			startTime: packet.Metadata().Timestamp,
			lastSeen:  packet.Metadata().Timestamp,
			service:   serviceFromPort(dstPort, proto),
			flag:      "S0",
		}

		if srcIP == dstIP && srcPort == dstPort {
			flow.land = 1
		}

		c.flows[key] = flow
	}

	flow.lastSeen = packet.Metadata().Timestamp
	flow.srcBytes += int64(pktBytes)
	flow.srcPackets++

	if urgFlag {
		flow.urgent++
	}
	if synFlag {
		flow.synCount++
	}
	if finFlag {
		flow.finCount++
	}
	if rstFlag {
		flow.rstCount++
	}

	if proto == "tcp" && finFlag && established {
		flow.flag = tcpFlagString(flow.synCount, flow.finCount, flow.rstCount, true)
		c.finalise(key, flow)
		return
	}

	if proto == "tcp" && rstFlag {
		flow.flag = tcpFlagString(flow.synCount, flow.finCount, flow.rstCount, established)
		c.finalise(key, flow)
		return
	}
}

func (c *Capturer) timeoutLoop(ctx context.Context) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.scanTimeouts()
		}
	}
}

func (c *Capturer) scanTimeouts() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, flow := range c.flows {
		if now.Sub(flow.lastSeen) > flowTimeout {
			if flow.key.Protocol == "udp" && flow.srcBytes > 0 {
				flow.flag = "SF"
			} else if flow.flag == "S0" {
				flow.flag = "S0"
			}
			c.finalise(key, flow)
		}
	}
}

func (c *Capturer) finalise(key flowKey, flow *flowRecord) {
	c.computeWindowFeatures(flow)
	feat := flow.toFeatures()

	select {
	case c.outCh <- feat:
	default:
		log.Println("capture: engine channel full, dropping flow")
	}

	delete(c.flows, key)
}

func (c *Capturer) computeWindowFeatures(flow *flowRecord) {
	cutoff := flow.lastSeen.Add(-2 * time.Second)
	var sameDst, sameSrv, synErrors, rejErrors int

	for _, f := range c.flows {
		if f.lastSeen.Before(cutoff) {
			continue
		}
		if f.key.DstIP == flow.key.DstIP {
			sameDst++
			if f.key.DstPort == flow.key.DstPort {
				sameSrv++
			}
			if f.flag == "S0" || f.flag == "S1" {
				synErrors++
			}
			if f.flag == "REJ" {
				rejErrors++
			}
		}
	}

	flow.count = sameDst
	flow.srvCount = sameSrv

	if sameDst > 0 {
		flow.serrorRate = float32(synErrors) / float32(sameDst)
		flow.rerrorRate = float32(rejErrors) / float32(sameDst)
		flow.sameSrvRate = float32(sameSrv) / float32(sameDst)
		flow.diffSrvRate = 1 - flow.sameSrvRate
	}

	var hostCount, hostSrvCount, hostSynErr, hostRejErr int
	seen := 0
	for _, f := range c.flows {
		if f.key.DstIP != flow.key.DstIP || seen >= 100 {
			continue
		}
		hostCount++
		seen++
		if f.key.DstPort == flow.key.DstPort {
			hostSrvCount++
		}
		if f.flag == "S0" {
			hostSynErr++
		}
		if f.flag == "REJ" {
			hostRejErr++
		}
	}

	flow.dstHostCount = hostCount
	flow.dstHostSrvCount = hostSrvCount

	if hostCount > 0 {
		flow.dstHostSameSrvRate = float32(hostSrvCount) / float32(hostCount)
		flow.dstHostDiffSrvRate = 1 - flow.dstHostSameSrvRate
		flow.dstHostSerrorRate = float32(hostSynErr) / float32(hostCount)
		flow.dstHostRerrorRate = float32(hostRejErr) / float32(hostCount)
	}
}

func (c *Capturer) flushAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, flow := range c.flows {
		c.finalise(key, flow)
	}
}
