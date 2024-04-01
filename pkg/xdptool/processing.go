package xdptool

import (
	"context"
	"fmt"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/takehaya/go-afxdp-l4conn/pkg/coreelf"
)

type AfXdpL4Handler struct {
	options   AfXdpL4HandlerOptions
	AfxdpProg *xdp.Program
	// xskmap    map[string][]*xdp.Socket
	Xskmap map[string][]*AfXdpL4Socket
}

type AfXdpL4Socket struct {
	deviceID string
	queueID  uint8
	xsk      *xdp.Socket
	rxChan   chan []byte
	txChan   chan []byte
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
		options.SocketOptions,
	)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &AfXdpL4Handler{
		AfxdpProg: afxdpProg,
		Xskmap:    xskmap,
		options:   options,
	}, nil
}

type AfXdpL4Worker func(chan []byte)

func rxBundleWorker(chanList []chan []byte, mergedChan chan []byte) {
	for _, rxChan := range chanList {
		go func(rxChan chan []byte) {
			for data := range rxChan {
				mergedChan <- data
			}
		}(rxChan)
	}
}

func txBundleWorker(chanList []chan []byte, muxerChan chan []byte) {
	// どうにかしてばらばらにする(chanListに分配する)
	i := 0 // 現在のチャネルインデックス
	for data := range muxerChan {
		// ラウンドロビンでチャネルを選択してデータを送信
		chanList[i] <- data
		i = (i + 1) % len(chanList) // 次のチャネルへ
	}
}

func (a *AfXdpL4Handler) Invoke(ctx context.Context) (chan []byte, chan []byte) {
	rxChanBundleList := make([]chan []byte, 0)
	txChanBundleList := make([]chan []byte, 0)
	rxChan := make(chan []byte)
	txChan := make(chan []byte)
	for _, xsklist := range a.Xskmap {
		for _, xsk := range xsklist {
			// go rxwk(xsk.rxChan)
			// go txwk(xsk.txChan)
			rxChanBundleList = append(rxChanBundleList, xsk.rxChan)
			txChanBundleList = append(txChanBundleList, xsk.txChan)
			go a.rxWorker(ctx, xsk.rxChan, xsk.xsk)
			go a.txWorker(ctx, xsk.txChan, xsk.xsk)
		}
	}
	go rxBundleWorker(rxChanBundleList, rxChan)
	go txBundleWorker(txChanBundleList, txChan)

	return rxChan, txChan
}

func (a *AfXdpL4Handler) rxWorker(ctx context.Context, pktchan chan []byte, xsk *xdp.Socket) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if n := xsk.NumFreeFillSlots(); n > 0 {
				xsk.Fill(xsk.GetDescs(n))
			}
			numRx, _, err := xsk.Poll(-1)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			if numRx > 0 {
				rxDescs := xsk.Receive(numRx)
				for i := 0; i < len(rxDescs); i++ {
					pktData := xsk.GetFrame(rxDescs[i])
					pktchan <- pktData
				}
			}
		}
	}
}

func (a *AfXdpL4Handler) txWorker(ctx context.Context, pktChan chan []byte, xsk *xdp.Socket) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-pktChan:
			descs := xsk.GetDescs(xsk.NumFreeTxSlots())
			for i := range descs {
				descs[i].Len = uint32(len(pkt))
			}
			xsk.Transmit(descs)

			_, _, err := xsk.Poll(-1)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (a *AfXdpL4Handler) Close() error {
	err := XskDetach(a.Xskmap, a.options.QueueIDs, a.afxdpProg)
	if err != nil {
		return errors.WithStack(err)
	}
	err = a.afxdpProg.Close()
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
