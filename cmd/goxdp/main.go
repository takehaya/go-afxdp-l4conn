package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	"github.com/takehaya/go-afxdp-l4conn/pkg/coreelf"
	"github.com/takehaya/go-afxdp-l4conn/pkg/version"
	"github.com/takehaya/go-afxdp-l4conn/pkg/xdptool"
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
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
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
		return errors.WithStack(err)
	}
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	log.Println("XDP program successfully loaded and attached.")
	log.Println("Press CTRL+C to stop.")
	go func() {
		<-signalChan
		err := afxdpl4Hd.Close()
		if err != nil {
			log.Printf("close error: %v\n", err)
		}
		os.Exit(1)
	}()

	rxChan, _ := afxdpl4Hd.Invoke(context.Background())
	count := 0
	for pktData := range rxChan {
		// PAYLOAD
		// _ = pktData
		count++
		log.Println("Count: ", count)
		log.Println("Received")
		log.Println(pktData)
	}
	return nil
}
