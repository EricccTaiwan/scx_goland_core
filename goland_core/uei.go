package core

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	UEI_REASON_LEN = 128
	UEI_MSG_LEN    = 1024
)

type UserExitInfo struct {
	Kind     int32
	Paid     uint32
	ExitCode int64
	Reason   [UEI_REASON_LEN]C.char
	Message  [UEI_MSG_LEN]C.char
}

type UeiMap struct {
	*bpf.BPFMap
}

func (s *Sched) Stopped() bool {
	err, uei := s.GetUeiData()
	if err != nil {
		log.Printf("uei: %v", err)
		return true
	}
	if uei.Kind != 0 || uei.ExitCode != 0 {
		log.Printf("uei.kind %v, uei.ExitCode: %v", uei.Kind, uei.ExitCode)
		return true
	}
	return false
}

func (s *Sched) GetUeiData() (UserExitInfo, error) {
	if s.uei == nil {
		return UserExitInfo{}, fmt.Errorf("UeiMap is nil")
	}
	i := 0
	b, err := s.uei.BPFMap.GetValue(unsafe.Pointer(&i))
	if err != nil {
		return UserExitInfo{}, err
	}
	var uei UserExitInfo
	buff := bytes.NewBuffer(b)
	err = binary.Read(buff, binary.LittleEndian, &uei)
	if err != nil {
		return UserExitInfo{}, err
	}
	return uei, nil
}
