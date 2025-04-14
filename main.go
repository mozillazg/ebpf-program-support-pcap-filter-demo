package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/jschwinger233/elibpcap"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf bpf.c

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func attachTc(devID *net.Interface, prog *ebpf.Program) (func(), error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}
	closeFunc := func() {
		if err := tcnl.Close(); err != nil {
			log.Println(err)
		}
	}

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		return closeFunc, err
	}
	newCloseFunc := func() {
		if err := tcnl.Qdisc().Delete(&qdisc); err != nil {
			log.Println(err)
		}
		closeFunc()
	}

	fd := uint32(prog.FD())
	name := "pcap_filter_inject_test"

	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    uint32(htons(unix.ETH_P_ALL)),
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:   &fd,
				Name: &name,
			},
		},
	}
	if err := tcnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
		return newCloseFunc, err
	}
	return newCloseFunc, nil
}

func injectFilter(spec *ebpf.CollectionSpec, expr string) error {
	if expr == "" {
		return nil
	}
	log.Printf("inject pcap filter %s", expr)
	oldInsts := spec.Programs["tc_prog"].Instructions
	// 手动实现
	//newInsts, err := injectPacpFilter(oldInsts, "pcap_filter", expr)
	// 使用 elibpcap 实现
	newInsts, err := elibpcap.Inject(expr, oldInsts, elibpcap.Options{
		AtBpf2Bpf:  "pcap_filter",
		DirectRead: true,
		L2Skb:      true,
	})
	if err != nil {
		return err
	}
	log.Printf("oldInsts: %s", oldInsts)
	log.Printf("newInsts: %s", newInsts)
	spec.Programs["tc_prog"].Instructions = newInsts
	return nil

}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	var expr string
	if len(os.Args) > 1 {
		expr = os.Args[1]
	}
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatal(err)
	}

	if err := injectFilter(spec, expr); err != nil {
		log.Fatal(err)
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		ve := &ebpf.VerifierError{}
		if errors.As(err, &ve) {
			log.Printf("verifier error: %+v", ve)
		}
		log.Fatalf("%+v", err)
	}
	defer objs.Close()

	tcIface := "lo"
	if v := os.Getenv("INFACE"); v != "" {
		tcIface = v
	}
	devID, err := net.InterfaceByName(tcIface)
	if err != nil {
		log.Println(err)
		return
	}
	closeFunc, err := attachTc(devID, objs.TcProg)
	if err != nil {
		if closeFunc != nil {
			closeFunc()
		}
		log.Println(err)
		return
	}
	defer closeFunc()

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	log.Println("...")
	<-ctx.Done()
	log.Println("bye bye")
}
