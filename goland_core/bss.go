package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

/*
#include "wrapper.h"
*/
import "C"

type BssData struct {
	Usersched_pid        uint32
	Paid                 uint32
	Nr_queued            uint64
	Nr_scheduled         uint64
	Nr_running           uint64
	Nr_online_cpus       uint64
	Nr_user_dispatches   uint64
	Nr_kernel_dispatches uint64
	Nr_cancel_dispatches uint64
	Nr_bounce_dispatches uint64
	Nr_failed_dispatches uint64
	Nr_sched_congested   uint64
}

func (data BssData) String() string {
	return fmt.Sprintf("Usersched_pid: %v, Nr_queued: %v ", data.Usersched_pid, data.Nr_queued) +
		fmt.Sprintf("Nr_scheduled: %v, Nr_running: %v ", data.Nr_scheduled, data.Nr_running) +
		fmt.Sprintf("Nr_online_cpus: %v, Nr_user_dispatches: %v ", data.Nr_online_cpus, data.Nr_user_dispatches) +
		fmt.Sprintf("Nr_kernel_dispatches: %v, Nr_cancel_dispatches: %v ", data.Nr_kernel_dispatches, data.Nr_cancel_dispatches) +
		fmt.Sprintf("Nr_bounce_dispatches: %v, Nr_failed_dispatches: %v", data.Nr_bounce_dispatches, data.Nr_failed_dispatches) +
		fmt.Sprintf("Nr_sched_congested: %v", data.Nr_sched_congested)
}

func LoadSkel() unsafe.Pointer {
	return C.open_skel()
}

func GetUserSchedPid() int {
	return int(C.get_usersched_pid())
}

func GetNrQueued() uint64 {
	return uint64(C.get_nr_queued())
}
func GetNrScheduled() uint64 {
	return uint64(C.get_nr_scheduled())
}

func NotifyComplete(nr_pending uint64) error {
	C.notify_complete(C.u64(nr_pending))
	return nil
}

func (s *Sched) SubNrQueued() error {
	C.sub_nr_queued()
	return nil
}

type BssMap struct {
	*bpf.BPFMap
}

func (s *Sched) GetBssData() (error, BssData) {
	if s.bss == nil {
		return fmt.Errorf("BssMap is nil"), BssData{}
	}
	i := 0
	b, err := s.bss.BPFMap.GetValue(unsafe.Pointer(&i))
	if err != nil {
		return err, BssData{}
	}
	var bss BssData
	buff := bytes.NewBuffer(b)
	err = binary.Read(buff, binary.LittleEndian, &bss)
	if err != nil {
		return err, BssData{}
	}
	return nil, bss
}

func (s *Sched) AssignUserSchedPid(pid int) error {
	if s.bss == nil {
		return fmt.Errorf("BssMap is nil")
	}
	i := 0
	return s.bss.BPFMap.Update(unsafe.Pointer(&i), unsafe.Pointer(&BssData{
		Usersched_pid: uint32(pid),
	}))
}
