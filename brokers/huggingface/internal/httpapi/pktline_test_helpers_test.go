package httpapi

import "github.com/osolmaz/brokerkit/git/protocol"

func appendTestPkt(dst, payload []byte) []byte {
	encoded, err := gitx.AppendPktLine(dst, payload)
	if err != nil {
		panic(err)
	}
	return encoded
}

func appendTestPktString(dst []byte, payload string) []byte {
	encoded, err := gitx.AppendPktLineString(dst, payload)
	if err != nil {
		panic(err)
	}
	return encoded
}

func appendTestFlush(dst []byte) []byte {
	return gitx.AppendFlushPkt(dst)
}
