package main

import (
	"fmt"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/bpf"
)

func injectPacpFilter(oldInsts asm.Instructions, funcName, expr string) (asm.Instructions, error) {
	injectIndex := -1
	for idx, inst := range oldInsts {
		if inst.Symbol() == funcName {
			injectIndex = idx
			break
		}
	}
	if injectIndex == -1 {
		return nil, fmt.Errorf("cannot find function name: %s", funcName)
	}

	filterInsts, err := pcapFilterToEbpf(expr)
	if err != nil {
		return nil, fmt.Errorf("pcapFilterToEbpf(%s): %v", expr, err)
	}

	filterInsts[0] = filterInsts[0].WithMetadata(oldInsts[injectIndex].Metadata)
	oldInsts[injectIndex] = oldInsts[injectIndex].WithMetadata(asm.Metadata{})

	newInsts := asm.Instructions{}
	newInsts = append(newInsts, oldInsts[:injectIndex]...)
	newInsts = append(newInsts, filterInsts...)
	newInsts = append(newInsts, oldInsts[injectIndex:]...)

	return newInsts, nil
}

func pcapFilterToEbpf(expr string) (asm.Instructions, error) {
	resultLabel := "result"
	cbpfInsts, err := compileFilterToCbpf(expr)
	if err != nil {
		return nil, fmt.Errorf("compileFilterToCbpf: %w", err)
	}
	ebpfInsts, err := cbpfc.ToEBPF(cbpfInsts, cbpfc.EBPFOpts{
		PacketStart: asm.R4,
		PacketEnd:   asm.R5,
		Result:      asm.R0,
		ResultLabel: resultLabel,
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: "pcap_filter",
	})
	if err != nil {
		return nil, fmt.Errorf("ToEBPF: %w", err)
	}
	ebpfInsts = append(ebpfInsts,
		asm.Mov.Imm(asm.R1, 0).WithSymbol(resultLabel),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Imm(asm.R3, 0),
		asm.Mov.Reg(asm.R4, asm.R0),
		asm.Mov.Imm(asm.R5, 0),
	)
	return ebpfInsts, nil
}

func compileFilterToCbpf(expr string) ([]bpf.Instruction, error) {
	var pcapBPF []pcap.BPFInstruction
	var bpfIns []bpf.Instruction
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, expr)
	if err != nil {
		return nil, fmt.Errorf("pcap.CompileBPFFilter: %w", err)
	}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}.Disassemble()
		bpfIns = append(bpfIns, bpfIns2)
	}
	return bpfIns, nil
}
