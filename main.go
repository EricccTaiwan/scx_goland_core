package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"encoding/binary"
	"unsafe"

	core "github.com/Gthulhu/scx_goland_core/goland_core"
	"github.com/Gthulhu/scx_goland_core/util"
)

func endian() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

const (
	MAX_LATENCY_WEIGHT = 1000
	SLICE_NS_DEFAULT   = 5000 * 1000 // 5ms
	SLICE_NS_MIN       = 500 * 1000
	SCX_ENQ_WAKEUP     = 1
	NSEC_PER_SEC       = 1000000000 // 1 second in nanoseconds
)

var taskPool []*core.QueuedTask = []*core.QueuedTask{}

func DrainQueuedTask(s *core.Sched) {
	for {
		task := s.DequeueTask()
		if task == nil {
			return
		}
		taskPool = append(taskPool, task)
	}
}

func GetTaskFromPool() *core.QueuedTask {
	if len(taskPool) == 0 {
		return nil
	}
	t := taskPool[0]
	taskPool = taskPool[1:]
	return t
}

func init() {
	runtime.GOMAXPROCS(1)
}

// TaskInfo stores task statistics
type TaskInfo struct {
	sumExecRuntime  uint64
	prevExecRuntime uint64
	vruntime        uint64
	avgNvcsw        uint64
	nvcsw           uint64
	nvcswTs         uint64
}

var taskInfoMap = make(map[int32]*TaskInfo)
var minVruntime uint64 = 0 // 全局最小 vruntime

func now() uint64 {
	return uint64(time.Now().UnixNano())
}

func calcAvg(oldVal uint64, newVal uint64) uint64 {
	return (oldVal - (oldVal >> 2)) + (newVal >> 2)
}

func saturating_sub(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return 0
}

func main() {
	bpfModule := core.LoadSched("main.bpf.o")
	defer bpfModule.Close()
	pid := os.Getpid()
	err := bpfModule.AssignUserSchedPid(pid)
	if err != nil {
		log.Printf("AssignUserSchedPid failed: %v", err)
	}
	log.Printf("pid: %v", pid)

	err = util.InitCacheDomains(bpfModule)
	if err != nil {
		log.Panicf("InitCacheDomains failed: %v", err)
	}

	if err := bpfModule.Attach(); err != nil {
		log.Printf("bpfModule attach failed: %v", err)
	}

	go func() {
		for {
			DrainQueuedTask(bpfModule)
			t := GetTaskFromPool()

			if t != nil {
				task := core.NewDispatchedTask(t)
				err, cpu := bpfModule.SelectCPU(t)
				if err != nil {
					log.Printf("SelectCPU failed: %v", err)
				}
				if cpu < 0 {
					cpu = core.RL_CPU_ANY
				}

				info, exists := taskInfoMap[t.Pid]
				if !exists {
					info = &TaskInfo{
						prevExecRuntime: t.SumExecRuntime,
						vruntime:        minVruntime,
						nvcsw:           t.Nvcsw,
						nvcswTs:         now(),
					}
					taskInfoMap[t.Pid] = info
				}

				deltaT := now() - info.nvcswTs
				if deltaT >= NSEC_PER_SEC {
					deltaNvcsw := t.Nvcsw - info.nvcsw
					avgNvcsw := uint64(0)
					if deltaT > 0 {
						avgNvcsw = min(deltaNvcsw*NSEC_PER_SEC/deltaT, 1000)
					}
					info.nvcsw = t.Nvcsw
					info.nvcswTs = now()
					info.avgNvcsw = calcAvg(info.avgNvcsw, avgNvcsw)
				}

				// Evaluate used task time slice.
				err, bss := bpfModule.GetBssData()
				if err != nil {
					log.Fatalf("GetBssData failed: %v", err)
				}
				nrWaiting := bss.Nr_queued + bss.Nr_scheduled + 1
				sliceNs := max(SLICE_NS_DEFAULT/nrWaiting, SLICE_NS_MIN)
				task.SliceNs = sliceNs

				// Evaluate used task time slice.
				slice := min(
					saturating_sub(t.SumExecRuntime, info.prevExecRuntime),
					sliceNs,
				)
				// Update total task cputime.
				info.prevExecRuntime = t.SumExecRuntime

				// Update task's vruntime re-aligning it to min_vruntime.
				//
				// The amount of vruntime budget an idle task can accumulate is adjusted in function of its
				// latency weight, which is derived from the average number of voluntary context switches.
				// This ensures that latency-sensitive tasks receive a priority boost.
				baseWeight := min(info.avgNvcsw, MAX_LATENCY_WEIGHT)
				weightMultiplier := uint64(1)
				if t.Flags&SCX_ENQ_WAKEUP != 0 {
					weightMultiplier = 2
				}
				latencyWeight := (baseWeight * weightMultiplier) + 1

				var minVruntimeLimit uint64 = saturating_sub(minVruntime, sliceNs*latencyWeight)

				if info.vruntime < minVruntimeLimit {
					info.vruntime = minVruntimeLimit
				}
				vslice := slice * 100 / t.Weight
				info.vruntime += vslice
				minVruntime += vslice
				task.Vtime = info.vruntime
				taskInfoMap[t.Pid] = info

				bpfModule.DispatchTask(task)

				err = bpfModule.NotifyComplete(uint64(len(taskPool)))
				if err != nil {
					log.Printf("NotifyComplete failed: %v", err)
				}
				runtime.Gosched()
			}
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	log.Println("receive os signal")
	log.Println("scheduler exit")
}
