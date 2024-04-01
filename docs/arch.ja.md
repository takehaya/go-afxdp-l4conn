# go-afxdp-l4conn design docs

author: takeru hayasaka(taketarou2 at gmail.com)

ここでは go-afxdp-l4conn の低レベルアーキテクチャを説明する

## 用語定義
TBA

## 処理フローについて
```go
// AFXDP に関するProgを生成する
afxdpProg, err := coreelf.NewAfXdpProgram(bindPort, ebpfoptions)
if err != nil {
    return err
}
defer afxdpProg.Close()

// socket をアタッチする
xskmap, err := xdptool.XskAttach(devices, queueid, afxdpProg, sockoptions)
if err != nil{
    return err
}

for i := 0; i < ThreadSize; i++{
    go func (threadnum int){
        for{
            if n := xsk.Numm
        }
    }(i)
}
```

## 対応関係
- Device(Interface)とNIC Queueは1対Nの関係を持つ
- NIC QueueとXSK Socketは1対Nの関係を持つ
- XSK SocketとThreadは1対Nの関係を持つ