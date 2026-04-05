package capture

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var protocolMap = map[string]float32{
	"tcp": 0, "udp": 1, "icmp": 2,
}

var serviceMap = map[string]float32{
	"http": 0, "ftp": 1, "smtp": 2, "ssh": 3, "dns": 4, "ftp_data": 5,
	"telnet": 6, "finger": 7, "domain_u": 8, "auth": 9, "login": 10,
	"other": 11,
}

var flagMap = map[string]float32{
	"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTS": 4,
	"SH": 5, "S1": 6, "S2": 7, "S3": 8, "OTH": 9,
}

type Extractor struct{}

func NewExtractor() *Extractor { return &Extractor{} }

func (e *Extractor) Extract(packet gopacket.Packet) (FeatureVector, bool) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return FeatureVector{}, false
	}

	var fv FeatureVector
	fv.Timestamp = time.Now()

	ipv4, isIPv4 := netLayer.(*layers.IPv4)
	if !isIPv4 {
		return FeatureVector{}, false
	}

	fv.SrcIP = ipv4.SrcIP.String()
	fv.DstIP = ipv4.DstIP.String()

	fv.Features[4] = float32(ipv4.Length)

	transportLayer := packet.TransportLayer()

	var srcPort, dstPort uint16
	var tcpFlags string = "OTH"
	var service string = "other"

	switch t := transportLayer.(type) {
	case *layers.TCP:
		fv.Protocol = "tcp"
		fv.Features[1] = protocolMap["tcp"]
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		fv.SrcPort = srcPort
		fv.DstPort = dstPort

		fv.Features[5] = float32(len(t.Payload))

		if t.URG {
			fv.Features[8] = 1
		}

		tcpFlags = encodeTCPFlags(t)
		service = encodeService(dstPort)

	case *layers.UDP:
		fv.Protocol = "udp"
		fv.Features[1] = protocolMap["udp"]
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		fv.SrcPort = srcPort
		fv.DstPort = dstPort
		fv.Features[5] = float32(len(t.Payload))
		service = encodeService(dstPort)

	case *layers.ICMPv4:
		fv.Protocol = "icmp"
		fv.Features[1] = protocolMap["icmp"]

	default:
		return FeatureVector{}, false
	}

	if s, ok := serviceMap[service]; ok {
		fv.Features[2] = s
	}

	if f, ok := flagMap[tcpFlags]; ok {
		fv.Features[3] = f
	}

	if fv.SrcIP == fv.DstIP && srcPort == dstPort {
		fv.Features[6] = 1
	}

	fv.Features[7] = float32(ipv4.FragOffset)
	fv.Features[0] = 0

	return fv, true
}

func encodeTCPFlags(t *layers.TCP) string {
	switch {
	case t.SYN && t.ACK:
		return "SF"
	case t.SYN && !t.ACK:
		return "S0"
	case t.RST:
		return "REJ"
	case t.FIN:
		return "SF"
	default:
		return "OTH"
	}
}

func encodeService(port uint16) string {
	switch port {
	case 80, 8080, 443:
		return "http"
	case 21:
		return "ftp"
	case 20:
		return "ftp_data"
	case 25, 587:
		return "smtp"
	case 22:
		return "ssh"
	case 53:
		return "dns"
	case 23:
		return "telnet"
	case 79:
		return "finger"
	case 113:
		return "auth"
	default:
		return "other"
	}
}
