package core

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

// Task queued for scheduling from the BPF component (see bpf_intf::queued_task_ctx).
type QueuedTask struct {
	Pid            int32  // pid that uniquely identifies a task
	Cpu            int32  // CPU where the task is running
	Flags          uint64 // task enqueue flags
	SumExecRuntime uint64 // Total cpu time
	Nvcsw          uint64 // Total amount of voluntary context switches
	Weight         uint64 // Task static priority
	Slice          uint64 // Time slice budget
	Vtime          uint64 // Current vruntime
	CpuMaskCnt     uint64 // cpumask generation counter (private)
}

func (s *Sched) ReceiveProcExitEvt() int {
	select {
	case e := <-s.exitEvt:
		if len(e) < int(unsafe.Sizeof(int32(0))) {
			log.Printf("ReceiveProcExitEvt: data length is less than int32 size, %d", len(e))
			return -1
		}
		pid := int(binary.LittleEndian.Uint32(e[0:4]))
		return pid
	default:
		return -1
	}
}

func (s *Sched) BlockTilReadyForDequeue() {
	select {
	case t := <-s.queue:
		s.queue <- t
		return
	}
}

func (s *Sched) ReadyForDequeue() bool {
	select {
	case t := <-s.queue:
		s.queue <- t
		return true
	default:
		return false
	}
}

func (s *Sched) DequeueTask(task *QueuedTask) {
	select {
	case t := <-s.queue:
		err := fastDecode(t, task)
		if err != nil {
			task.Pid = -1
			return
		}
		err = s.SubNrQueuedSkel()
		if err != nil {
			task.Pid = -1
			log.Printf("SubNrQueued err: %v", err)
			return
		}
		return
	default:
		task.Pid = -1
		return
	}
}

// Task queued for dispatching to the BPF component (see bpf_intf::dispatched_task_ctx).
type DispatchedTask struct {
	Pid        int32  // pid that uniquely identifies a task
	Cpu        int32  // target CPU selected by the scheduler
	Flags      uint64 // special dispatch flags
	SliceNs    uint64 // time slice assigned to the task (0 = default)
	Vtime      uint64 // task deadline / vruntime
	CpuMaskCnt uint64 // cpumask generation counter (private)
}

// NewDispatchedTask creates a DispatchedTask from a QueuedTask.
func NewDispatchedTask(task *QueuedTask) *DispatchedTask {
	return &DispatchedTask{
		Pid:        task.Pid,
		Cpu:        task.Cpu,
		Flags:      task.Flags,
		SliceNs:    0, // use default time slice
		Vtime:      0,
		CpuMaskCnt: task.CpuMaskCnt,
	}
}

func (s *Sched) DispatchTask(t *DispatchedTask) error {
	if err := s.urb.Error(); err != nil {
		return err
	}
	s.dispatch <- fastEncode(t)
	return nil
}

func fastDecode(data []byte, task *QueuedTask) error {
	if len(data) < int(unsafe.Sizeof(QueuedTask{})) {
		return fmt.Errorf("data length is less than QueuedTask size")
	}
	task.Pid = int32(binary.LittleEndian.Uint32(data[0:4]))
	task.Cpu = int32(binary.LittleEndian.Uint32(data[4:8]))
	task.Flags = binary.LittleEndian.Uint64(data[8:16])
	task.SumExecRuntime = binary.LittleEndian.Uint64(data[16:24])
	task.Nvcsw = binary.LittleEndian.Uint64(data[24:32])
	task.Weight = binary.LittleEndian.Uint64(data[32:40])
	task.Slice = binary.LittleEndian.Uint64(data[40:48])
	task.Vtime = binary.LittleEndian.Uint64(data[48:56])
	task.CpuMaskCnt = binary.LittleEndian.Uint64(data[56:64])

	return nil
}

func fastEncode(t *DispatchedTask) []byte {
	data := make([]byte, 8*8) // 64 bytes

	binary.LittleEndian.PutUint32(data[0:4], uint32(t.Pid))
	binary.LittleEndian.PutUint32(data[4:8], uint32(t.Cpu))
	binary.LittleEndian.PutUint64(data[8:16], t.Flags)
	binary.LittleEndian.PutUint64(data[16:24], t.SliceNs)
	binary.LittleEndian.PutUint64(data[24:32], t.Vtime)
	binary.LittleEndian.PutUint64(data[32:40], t.CpuMaskCnt)

	return data
}

func IsSMTActive() (bool, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/smt/active")
	if err != nil {
		return false, err
	}

	contents := strings.TrimSpace(string(data))
	smtActive, err := strconv.Atoi(contents)
	if err != nil {
		return false, err
	}

	return smtActive == 1, nil
}
