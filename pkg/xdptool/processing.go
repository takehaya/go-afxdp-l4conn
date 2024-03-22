package xdptool

import (
	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/takehaya/goxdp-template/pkg/coreelf"
)

type AfXdpL4Handler struct {
	options   AfXdpL4HandlerOptions
	afxdpProg *xdp.Program
	xskmap    map[string][]*xdp.Socket
}

type AfXdpL4HandlerOptions struct {
	Port           uint32
	Devices        []string
	QueueIDs       []int
	ProgramOptions *ebpf.CollectionOptions
	SocketOptions  *xdp.SocketOptions
}

func NewAfXdpL4Handler(options AfXdpL4HandlerOptions) (*AfXdpL4Handler, error) {
	afxdpProg, err := coreelf.NewAfXdpProgram(uint32(options.Port), options.ProgramOptions)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	//attach afxdp
	xskmap, err := XskAttach(
		options.Devices,
		options.QueueIDs,
		afxdpProg,
		&xdp.SocketOptions{
			NumFrames:              204800,
			FrameSize:              4096,
			FillRingNumDescs:       8192,
			CompletionRingNumDescs: 64,
			RxRingNumDescs:         8192,
			TxRingNumDescs:         64,
		})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &AfXdpL4Handler{
		afxdpProg: afxdpProg,
		xskmap:    xskmap,
		options:   options,
	}, nil
}

func (a *AfXdpL4Handler) Run() error {

	return nil
}

func (a *AfXdpL4Handler) Close() error {
	err := XskDetach(a.xskmap, a.options.QueueIDs, a.afxdpProg)
	if err != nil {
		return errors.WithStack(err)
	}
	err = a.afxdpProg.Close()
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
