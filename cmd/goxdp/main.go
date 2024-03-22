package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/takehaya/goxdp-template/pkg/coreelf"
	"github.com/takehaya/goxdp-template/pkg/version"
	"github.com/takehaya/goxdp-template/pkg/xdptool"
	"github.com/urfave/cli"
)

func main() {
	app := newApp(version.Version)
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "goxdp_tmp"
	app.Version = version

	app.Usage = "A template for writing XDP programs in Go"

	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringSliceFlag{
			Name:  "device",
			Value: &cli.StringSlice{"eth1", "eth2"},
			Usage: "Adding a device to attach",
		},
		cli.IntSliceFlag{
			Name:  "queueid",
			Value: &cli.IntSlice{0, 1},
			Usage: "The ID of the Rx queue",
		},
		cli.IntFlag{
			Name:  "port",
			Value: 0,
			Usage: "The Bind Port Number",
		},
		cli.IntFlag{
			Name:  "multipleReceiverPoolSize",
			Value: 1,
			Usage: "Start multiple receivers pool size",
		},
	}
	app.Action = run
	return app
}

func run(ctx *cli.Context) error {
	devices := ctx.StringSlice("devices")
	log.Println(devices)
	port := ctx.Int("port")
	log.Println(port)
	queueid := ctx.IntSlice("queueid")
	log.Println(queueid)
	multipleReceiverPoolSize := ctx.Int("multipleReceiverPoolSize")
	log.Println(multipleReceiverPoolSize)

	// get ebpf binary
	ebpfoptions := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  102400 * 1024,
		},
	}
	afxdpProg, err := coreelf.NewAfXdpProgram(uint32(port), ebpfoptions)
	if err != nil {
		return errors.WithStack(err)
	}
	defer afxdpProg.Close()

	//attach afxdp
	xskmap, err := xdptool.XskAttach(devices, queueid, afxdpProg, &xdp.SocketOptions{
		NumFrames:              204800,
		FrameSize:              4096,
		FillRingNumDescs:       8192,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         8192,
		TxRingNumDescs:         64,
	})
	if err != nil {
		return errors.WithStack(err)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	log.Println("XDP program successfully loaded and attached.")
	log.Println("Press CTRL+C to stop.")
	go func() {
		<-signalChan
		err := xdptool.XskDetach(xskmap, queueid, afxdpProg)
		if err != nil {
			log.Printf("detach error: %v\n", err)
		}
		os.Exit(1)
	}()
	for {
		// If there are any free slots on the Fill queue...
		if n := xsk.NumFreeFillSlots(); n > 0 {
			// ...then fetch up to that number of not-in-use
			// descriptors and push them onto the Fill ring queue
			// for the kernel to fill them with the received
			// frames.
			xsk.Fill(xsk.GetDescs(n))
		}
		// Wait for receive - meaning the kernel has
		// produced one or more descriptors filled with a received
		// frame onto the Rx ring queue.
		// log.Printf("waiting for frame(s) to be received...")
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}

		if numRx > 0 {
			// Consume the descriptors filled with received frames
			// from the Rx ring queue.
			rxDescs := xsk.Receive(numRx)
			// Print the received frames and also modify them
			// in-place replacing the destination MAC address with
			// broadcast address.
			for i := 0; i < len(rxDescs); i++ {
				pktData := xsk.GetFrame(rxDescs[i])
				limits <- pktData
			}
		}
	}
	return nil
}
