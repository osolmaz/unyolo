package gitx

import (
	"strings"
)

const maxSideBandDataPayload = MaxPktLinePayload - 1

// ReceivePackFailure describes one refused ref update.
type ReceivePackFailure struct {
	Ref    string
	Reason string
}

// BuildReceivePackRefusal returns a receive-pack result that stock Git prints
// as a remote rejection instead of a generic smart-HTTP failure.
func BuildReceivePackRefusal(service string, request ReceivePackRequest, failures []ReceivePackFailure) ([]byte, error) {
	reasons, firstReason := receivePackFailureReasons(failures)
	status, err := appendReceivePackFailures(nil, service, request.Commands, reasons)
	if err != nil {
		return nil, err
	}
	status = AppendFlushPkt(status)
	if !receivePackUsesSideBand(request.Capabilities) {
		return status, nil
	}
	return wrapReceivePackSideBand(service, firstReason, status)
}

func receivePackFailureReasons(failures []ReceivePackFailure) (map[string]string, string) {
	reasons := map[string]string{}
	firstReason := "push refused"
	for index, failure := range failures {
		reason := cleanReceivePackReason(failure.Reason)
		if index == 0 {
			firstReason = reason
		}
		reasons[failure.Ref] = reason
	}
	return reasons, firstReason
}

func receivePackUsesSideBand(capabilities map[string]bool) bool {
	return capabilities["side-band-64k"] || capabilities["side-band"]
}

func wrapReceivePackSideBand(service, reason string, status []byte) ([]byte, error) {
	var out []byte
	out, err := appendReceivePackBand(out, 2, service+": "+reason+"\n")
	if err != nil {
		return nil, err
	}
	out, err = appendReceivePackBandBytes(out, 1, status)
	if err != nil {
		return nil, err
	}
	return AppendFlushPkt(out), nil
}

func appendReceivePackFailures(dst []byte, service string, commands []ReceivePackCommand, reasons map[string]string) ([]byte, error) {
	dst, err := AppendPktLineString(dst, "unpack ok\n")
	if err != nil {
		return nil, err
	}
	for _, command := range commands {
		reason := reasons[command.Ref]
		if reason == "" {
			reason = "push refused by " + service + " because another ref failed"
		}
		dst, err = AppendPktLineString(dst, "ng "+command.Ref+" "+service+": "+reason+"\n")
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

func appendReceivePackBand(dst []byte, band byte, payload string) ([]byte, error) {
	return appendReceivePackBandBytes(dst, band, []byte(payload))
}

func appendReceivePackBandBytes(dst []byte, band byte, payload []byte) ([]byte, error) {
	for len(payload) > 0 {
		length := min(len(payload), maxSideBandDataPayload)
		data := append([]byte{band}, payload[:length]...)
		var err error
		dst, err = AppendPktLine(dst, data)
		if err != nil {
			return nil, err
		}
		payload = payload[length:]
	}
	return dst, nil
}

func cleanReceivePackReason(reason string) string {
	reason = strings.TrimSpace(reason)
	reason = strings.NewReplacer("\n", " ", "\r", " ").Replace(reason)
	if reason == "" {
		return "refused"
	}
	return reason
}
