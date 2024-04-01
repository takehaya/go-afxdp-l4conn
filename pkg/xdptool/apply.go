package xdptool

import (
	"fmt"
	"os"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func LoadElf(filepath string) (*ebpf.Collection, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}

	// Read ELF
	spec, err := ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to load ELF: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %w", err)
	}
	return coll, nil
}

func Attach(prog *ebpf.Program, device string) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return fmt.Errorf("%s not found in object", device)
	}
	if err := netlink.LinkSetXdpFd(link, prog.FD()); err != nil {
		return fmt.Errorf("failed to attach XDP program to %s: %w", device, err)
	}
	return nil
}

func Detach(device string) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return fmt.Errorf("failed to get device %s: %w", device, err)
	}
	if err := netlink.LinkSetXdpFd(link, -1); err != nil {
		return fmt.Errorf("failed to detach XDP program from %s: %w", device, err)
	}
	return nil
}

// device 1 - N NICQueueの組で Socketを作る
func XskAttach(devices []string, queueIDs []int, prog *xdp.Program, options *xdp.SocketOptions) (map[string][]*AfXdpL4Socket, error) {
	xskmap := make(map[string][]*AfXdpL4Socket)
	for _, dev := range devices {
		link, err := netlink.LinkByName(dev)
		if err != nil {
			return nil, fmt.Errorf("%s not found in object", dev)
		}
		if err := prog.Attach(link.Attrs().Index); err != nil {
			return nil, fmt.Errorf("failed to attach XDP program to %s: %w", dev, err)
		}
		for _, queueID := range queueIDs {
			xsk, err := xdp.NewSocket(link.Attrs().Index, queueID, options)
			if err != nil {
				return nil, fmt.Errorf("failed to create an XDP socket: %w", err)
			}
			if err := prog.Register(queueID, xsk.FD()); err != nil {
				return nil, fmt.Errorf("failed to register socket in eBPF map: %w", err)
			}
			l4sock := &AfXdpL4Socket{
				deviceID: dev,
				queueID:  uint8(queueID),
				xsk:      xsk,
				rxChan:   make(chan []byte),
				txChan:   make(chan []byte),
			}
			xskmap[dev] = append(xskmap[dev], l4sock)
		}
	}
	return xskmap, nil
}

func XskDetach(xskmap map[string][]*AfXdpL4Socket, queueIDs []int, prog *xdp.Program) error {
	for _, queueID := range queueIDs {
		if err := prog.Unregister(queueID); err != nil {
			return fmt.Errorf("failed to unregister socket in eBPF map: %w", err)
		}
	}
	for dev, xsks := range xskmap {
		for _, v := range xsks {
			if err := v.xsk.Close(); err != nil {
				return fmt.Errorf("failed to close XDP socket: %w", err)
			}
		}
		link, err := netlink.LinkByName(dev)
		if err != nil {
			return fmt.Errorf("%s not found in object", dev)
		}
		if err := prog.Detach(link.Attrs().Index); err != nil {
			return fmt.Errorf("failed to detach XDP program from %s: %w", dev, err)
		}
	}
	return nil
}
