package capture

import (
	"net"
	"time"

	"sentryids/internal/engine"
)

type flowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

type flowRecord struct {
	key flowKey

	startTime time.Time
	lastSeen  time.Time

	srcBytes   int64
	dstBytes   int64
	srcPackets int64
	dstPackets int64

	synCount int
	finCount int
	rstCount int
	urgCount int

	wrongFragments int
	urgent         int

	flag string
	land int

	service string

	count           int
	srvCount        int
	serrorRate      float32
	srvSerrorRate   float32
	rerrorRate      float32
	srvRerrorRate   float32
	sameSrvRate     float32
	diffSrvRate     float32
	srvDiffHostRate float32

	dstHostCount           int
	dstHostSrvCount        int
	dstHostSameSrvRate     float32
	dstHostDiffSrvRate     float32
	dstHostSameSrcPortRate float32
	dstHostSrvDiffHostRate float32
	dstHostSerrorRate      float32
	dstHostSrvSerrorRate   float32
	dstHostRerrorRate      float32
	dstHostSrvRerrorRate   float32
}

func serviceFromPort(port uint16, proto string) string {
	if proto == "udp" {
		switch port {
		case 53:
			return "domain_u"
		case 123:
			return "ntp_u"
		case 69:
			return "tftp_u"
		}
		return "other"
	}
	switch port {
	case 80:
		return "http"
	case 21:
		return "ftp"
	case 20:
		return "ftp_data"
	case 25:
		return "smtp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 443:
		return "http_443"
	case 110:
		return "pop_3"
	case 143:
		return "imap4"
	case 389:
		return "ldap"
	case 513:
		return "login"
	case 514:
		return "shell"
	case 37:
		return "time"
	case 79:
		return "finger"
	case 43:
		return "whois"
	case 119:
		return "nntp"
	case 13:
		return "daytime"
	case 9:
		return "discard"
	case 7:
		return "echo"
	case 111:
		return "sunrpc"
	case 1521:
		return "sql_net"
	}
	return "other"
}

func tcpFlagString(syn, fin, rst int, established bool) string {
	switch {
	case established && fin > 0:
		return "SF"
	case syn > 0 && fin == 0 && rst == 0:
		return "S0"
	case rst > 0 && !established:
		return "REJ"
	case rst > 0 && established:
		return "RSTO"
	case syn > 0 && rst > 0:
		return "RSTS"
	default:
		return "OTH"
	}
}

func (f *flowRecord) toFeatures() engine.Features {
	duration := f.lastSeen.Sub(f.startTime).Seconds()

	protoCode := map[string]float32{"tcp": 0, "udp": 1, "icmp": 2}
	serviceCode := map[string]float32{
		"http": 0, "ftp": 1, "smtp": 2, "ssh": 3, "dns": 4,
		"ftp_data": 5, "telnet": 8, "other": 10, "private": 11,
		"domain_u": 12, "ntp_u": 14, "http_443": 15, "ldap": 17,
		"imap4": 20, "pop_3": 21, "sunrpc": 24, "nntp": 28,
		"whois": 29, "shell": 30, "sql_net": 55, "time": 57,
		"tftp_u": 68, "icmp": 69, "login": 45, "finger": 7,
		"echo": 37, "daytime": 34, "discard": 35,
	}
	flagCode := map[string]float32{
		"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTS": 4,
		"SH": 5, "S1": 6, "S2": 7, "S3": 8, "OTH": 9,
	}

	pc := protoCode[f.key.Protocol]
	sc := serviceCode[f.service]
	fc := flagCode[f.flag]

	var v [41]float32
	v[0] = float32(duration)
	v[1] = pc
	v[2] = sc
	v[3] = fc
	v[4] = float32(f.srcBytes)
	v[5] = float32(f.dstBytes)
	v[6] = float32(f.land)
	v[7] = float32(f.wrongFragments)
	v[8] = float32(f.urgent)
	v[9] = 0
	v[10] = 0
	v[11] = 0
	v[12] = 0
	v[13] = 0
	v[14] = 0
	v[15] = 0
	v[16] = 0
	v[17] = 0
	v[18] = 0
	v[19] = 0
	v[20] = 0
	v[21] = 0
	v[22] = float32(f.count)
	v[23] = float32(f.srvCount)
	v[24] = f.serrorRate
	v[25] = f.srvSerrorRate
	v[26] = f.rerrorRate
	v[27] = f.srvRerrorRate
	v[28] = f.sameSrvRate
	v[29] = f.diffSrvRate
	v[30] = f.srvDiffHostRate
	v[31] = float32(f.dstHostCount)
	v[32] = float32(f.dstHostSrvCount)
	v[33] = f.dstHostSameSrvRate
	v[34] = f.dstHostDiffSrvRate
	v[35] = f.dstHostSameSrcPortRate
	v[36] = f.dstHostSrvDiffHostRate
	v[37] = f.dstHostSerrorRate
	v[38] = f.dstHostSrvSerrorRate
	v[39] = f.dstHostRerrorRate
	v[40] = f.dstHostSrvRerrorRate

	return engine.Features{
		SrcIP:       f.key.SrcIP,
		DstIP:       f.key.DstIP,
		SrcPort:     f.key.SrcPort,
		DstPort:     f.key.DstPort,
		Protocol:    f.key.Protocol,
		PacketCount: f.srcPackets + f.dstPackets,
		Vector:      v,
	}
}

func isPrivateIP(ip net.IP) bool {
	private := []net.IPNet{
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
	}
	for _, block := range private {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
