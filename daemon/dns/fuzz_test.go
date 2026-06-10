package dns

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FuzzTrackAnswers feeds arbitrary bytes through gopacket into the DNS-response
// tracker. TrackAnswers() parses replies that arrive from the network (the
// daemon inspects DNS answers to map IPs back to hostnames), so it must never
// panic on a malformed or hostile packet. The fuzzer asserts only that: no
// panic regardless of input.
func FuzzTrackAnswers(f *testing.F) {
	// A couple of seeds: an empty packet and a minimal UDP/53 shape.
	f.Add([]byte{})
	f.Add([]byte{0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 0x40, 0x11, 0, 0,
		127, 0, 0, 1, 127, 0, 0, 1, 0, 53, 0, 53, 0, 8, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, lt := range []gopacket.LayerType{
			layers.LayerTypeIPv4,
			layers.LayerTypeIPv6,
			layers.LayerTypeEthernet,
		} {
			pkt := gopacket.NewPacket(data, lt, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			// Must not panic.
			_ = TrackAnswers(pkt)
		}
	})
}
