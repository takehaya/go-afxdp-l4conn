package coreelf

import (
	"fmt"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf xdp ../../src/xdp_prog.c -- -I./../../include -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wnull-character -g -c -O2 -D__KERNEL__

func NewAfXdpProgram(destPort uint32, options *ebpf.CollectionOptions) (*xdp.Program, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, errors.WithStack(err)
	}
	spec, err := loadXdp()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	consts := map[string]interface{}{
		"TARGET_PORT": uint16(destPort),
	}
	if destPort > 0 && destPort <= 65535 {
		if err := spec.RewriteConstants(consts); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	objs := &xdpObjects{}
	err = spec.LoadAndAssign(objs, options)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
			return nil, errors.WithStack(verr)
		}
		return nil, errors.WithStack(err)
	}
	p := &xdp.Program{
		Program: objs.XdpSockProg,
		Queues:  objs.RxQueueIdMap,
		Sockets: objs.XsksMap,
	}

	return p, nil
}
