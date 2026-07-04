package engine

type ClassLabel int

const (
	Normal ClassLabel = iota
	LabelDoS
	Probe
	R2L
	U2R
)

func (c ClassLabel) String() string {
	switch c {
	case Normal:
		return "Normal"
	case LabelDoS:
		return "DoS"
	case Probe:
		return "Probe"
	case R2L:
		return "R2L"
	case U2R:
		return "U2R"
	default:
		return "Unknown"
	}
}

func (c ClassLabel) Severity() string {
	switch c {
	case LabelDoS:
		return "high"
	case Probe:
		return "medium"
	case R2L:
		return "high"
	case U2R:
		return "critical"
	default:
		return ""
	}
}

type Features struct {
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	PacketCount int64

	Vector [41]float32
}
