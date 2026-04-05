package capture

type PCAPReader struct {
	*Capturer
}

func NewPCAPReader() *PCAPReader {
	return &PCAPReader{New()}
}
