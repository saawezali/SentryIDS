package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"sentryids/internal/engine"
)

func tcpPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, syn, ack bool) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(srcIP), DstIP: net.ParseIP(dstIP)}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: syn, ACK: ack}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload("payload")); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
}

func TestReversePacketsJoinTheSameFlow(t *testing.T) {
	c := New("test", make(chan engine.Features, 1))
	c.handlePacket(tcpPacket(t, "10.0.0.1", "10.0.0.2", 50000, 443, true, false))
	c.handlePacket(tcpPacket(t, "10.0.0.2", "10.0.0.1", 443, 50000, false, true))

	if len(c.flows) != 1 {
		t.Fatalf("got %d flows, want one bidirectional flow", len(c.flows))
	}
	for _, flow := range c.flows {
		if flow.srcBytes == 0 || flow.dstBytes == 0 {
			t.Fatalf("expected bytes in both directions, got src=%d dst=%d", flow.srcBytes, flow.dstBytes)
		}
		if flow.srcPackets != 1 || flow.dstPackets != 1 {
			t.Fatalf("unexpected packet counts: src=%d dst=%d", flow.srcPackets, flow.dstPackets)
		}
	}
}

func TestFeatureEncodingMatchesTrainingMaps(t *testing.T) {
	flow := &flowRecord{key: flowKey{Protocol: "tcp"}, service: "http_443", flag: "SF"}
	features := flow.toFeatures()

	wantProto := protoCode["tcp"]
	wantSvc := serviceCode["http_443"]
	wantFlag := flagCode["SF"]

	if features.Vector[1] != wantProto {
		t.Errorf("protocol: got %v, want %v", features.Vector[1], wantProto)
	}
	if features.Vector[2] != wantSvc {
		t.Errorf("service: got %v, want %v", features.Vector[2], wantSvc)
	}
	if features.Vector[3] != wantFlag {
		t.Errorf("flag: got %v, want %v", features.Vector[3], wantFlag)
	}
}
