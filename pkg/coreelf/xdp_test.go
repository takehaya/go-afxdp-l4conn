package coreelf_test

import (
	"net"
	"testing"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/go-afxdp-l4conn/pkg/coreelf"
	"github.com/takehaya/go-afxdp-l4conn/pkg/xdptool"
)

var payload = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

func generateInput(t *testing.T) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	iph := &layers.IPv4{
		Version: 4, Protocol: layers.IPProtocolUDP, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1212,
		SrcIP: net.IP{192, 168, 10, 1}, DstIP: net.IP{192, 168, 10, 5},
	}
	udp := &layers.UDP{SrcPort: 4789, DstPort: 4789}
	udp.SetNetworkLayerForChecksum(iph)
	vxlan := &layers.VXLAN{VNI: 0x123456}
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x02}, EthernetType: layers.EthernetTypeIPv4},
		iph, udp, vxlan,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x01}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x02}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{
			Version: 4, Protocol: layers.IPProtocolICMPv4, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
			SrcIP: net.IP{192, 168, 100, 200}, DstIP: net.IP{192, 168, 30, 1},
		},
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func generateOutput(t *testing.T) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x01}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x02}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{
			Version: 4, Protocol: layers.IPProtocolICMPv4, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
			SrcIP: net.IP{192, 168, 100, 200}, DstIP: net.IP{192, 168, 30, 1},
		},
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestXDPProg(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	port := 4789
	devices := []string{"lo"}
	// get ebpf binary
	ebpfoptions := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  102400 * 1024,
		},
	}
	afxdpProg, err := coreelf.NewAfXdpProgram(uint32(port), ebpfoptions)
	if err != nil {
		t.Fatal(err)
	}
	defer afxdpProg.Close()

	afxdpl4Hd, err := xdptool.NewAfXdpL4Handler(xdptool.AfXdpL4HandlerOptions{
		Port:           uint32(port),
		Devices:        devices,
		QueueIDs:       queueid,
		ProgramOptions: ebpfoptions,
		SocketOptions: &xdp.SocketOptions{
			NumFrames:              204800,
			FrameSize:              4096,
			FillRingNumDescs:       8192,
			CompletionRingNumDescs: 64,
			RxRingNumDescs:         8192,
			TxRingNumDescs:         64,
		},
	})
	if err != nil {
		t.Fatal(t)
	}

	ret, got, err := afxdpl4Hd.AfxdpProg.Program.Test(generateInput(t))
	if err != nil {
		t.Error(err)
	}

	// retern code should be XDP_TX
	if ret != 3 {
		t.Errorf("got %d want %d", ret, 3)
	}

	// check output
	want := generateOutput(t)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch (-want +got):\n%s", diff)
	}
}
