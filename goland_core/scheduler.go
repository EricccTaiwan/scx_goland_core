package core

import (
	"github.com/Gthulhu/plugin/models"
	"github.com/Gthulhu/plugin/plugin"
)

type CustomScheduler interface {
	// Drain the queued task from eBPF and return the number of tasks drained
	DrainQueuedTask(s plugin.Sched) int
	// Select a task from the queued tasks and return it
	SelectQueuedTask(s plugin.Sched) *models.QueuedTask
	// Select a CPU for the given queued task, After selecting the CPU, the task will be dispatched to that CPU by Scheduler
	SelectCPU(s plugin.Sched, t *models.QueuedTask) (error, int32)
	// Determine the time slice for the given task
	DetermineTimeSlice(s plugin.Sched, t *models.QueuedTask) uint64
	// Get the number of objects in the pool (waiting to be dispatched)
	// GetPoolCount will be called by the scheduler to notify the number of tasks waiting to be dispatched (NotifyComplete)
	GetPoolCount() uint64
}

func (s *Sched) DrainQueuedTask() int {
	if s.plugin != nil {
		return s.plugin.DrainQueuedTask(s)
	}
	return 0
}

func (s *Sched) SelectQueuedTask() *models.QueuedTask {
	if s.plugin != nil {
		return s.plugin.SelectQueuedTask(s)
	}
	return nil
}

func (s *Sched) SelectCPU(t *models.QueuedTask) (error, int32) {
	if s.plugin != nil {
		return s.plugin.SelectCPU(s, t)
	}
	return s.selectCPU(t)
}

func (s *Sched) DetermineTimeSlice(t *models.QueuedTask) uint64 {
	if s.plugin != nil {
		return s.plugin.DetermineTimeSlice(s, t)
	}
	return 0
}

func (s *Sched) GetPoolCount() uint64 {
	if s.plugin != nil {
		return s.plugin.GetPoolCount()
	}
	return 0
}
