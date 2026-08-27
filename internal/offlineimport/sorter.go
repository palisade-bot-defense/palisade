package offlineimport

import (
	"bufio"
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const mergeFanIn = 32

type eventSink interface {
	Write(Event) error
}

type sortableEvent struct {
	ObservedSeconds int64  `json:"s"`
	ObservedNanos   int32  `json:"n"`
	Ordinal         uint64 `json:"o"`
	Event           Event  `json:"e"`
}

type sortRun struct {
	path string
	size int64
}

type eventSorter struct {
	dir       string
	chunkSize int
	budget    *budgets
	chunk     []sortableEvent
	runs      []sortRun
	ordinal   uint64
	nextRun   uint64
}

func newEventSorter(dir string, chunkSize int, budget *budgets) *eventSorter {
	return &eventSorter{dir: dir, chunkSize: chunkSize, budget: budget, chunk: make([]sortableEvent, 0, chunkSize)}
}

func (s *eventSorter) Write(event Event) error {
	observedAt, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
	if err != nil {
		return errors.New("sort normalized event: invalid observation time")
	}
	if err := s.budget.addEvent(); err != nil {
		return err
	}
	s.ordinal++
	s.chunk = append(s.chunk, sortableEvent{ObservedSeconds: observedAt.Unix(), ObservedNanos: int32(observedAt.Nanosecond()), Ordinal: s.ordinal, Event: event})
	if len(s.chunk) >= s.chunkSize {
		return s.flushChunk()
	}
	return nil
}

func (s *eventSorter) Finish(writer *shardWriter) error {
	if err := s.flushChunk(); err != nil {
		return err
	}
	for len(s.runs) > mergeFanIn {
		var next []sortRun
		for start := 0; start < len(s.runs); start += mergeFanIn {
			end := start + mergeFanIn
			if end > len(s.runs) {
				end = len(s.runs)
			}
			run, err := s.mergeToRun(s.runs[start:end])
			if err != nil {
				return err
			}
			next = append(next, run)
		}
		s.runs = next
	}
	if len(s.runs) > 0 {
		if err := s.mergeRuns(s.runs, func(item sortableEvent) error { return writer.Write(item.Event) }); err != nil {
			return err
		}
	}
	if err := writer.Finish(); err != nil {
		return err
	}
	return s.removeRuns(s.runs)
}

func (s *eventSorter) Abort() error {
	return s.removeRuns(s.runs)
}

func (s *eventSorter) flushChunk() error {
	if len(s.chunk) == 0 {
		return nil
	}
	sort.SliceStable(s.chunk, func(i, j int) bool {
		if s.chunk[i].ObservedSeconds != s.chunk[j].ObservedSeconds {
			return s.chunk[i].ObservedSeconds < s.chunk[j].ObservedSeconds
		}
		if s.chunk[i].ObservedNanos != s.chunk[j].ObservedNanos {
			return s.chunk[i].ObservedNanos < s.chunk[j].ObservedNanos
		}
		return s.chunk[i].Ordinal < s.chunk[j].Ordinal
	})
	run, err := s.writeRun(func(encoder *json.Encoder) error {
		for _, item := range s.chunk {
			if err := encoder.Encode(item); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.runs = append(s.runs, run)
	s.chunk = s.chunk[:0]
	return nil
}

func (s *eventSorter) mergeToRun(inputs []sortRun) (sortRun, error) {
	run, err := s.writeRun(func(encoder *json.Encoder) error {
		return s.mergeRuns(inputs, func(item sortableEvent) error { return encoder.Encode(item) })
	})
	if err != nil {
		return sortRun{}, err
	}
	if err := s.removeRuns(inputs); err != nil {
		_ = os.Remove(run.path)
		s.budget.releaseWorking(run.size)
		return sortRun{}, err
	}
	return run, nil
}

func (s *eventSorter) writeRun(write func(*json.Encoder) error) (sortRun, error) {
	s.nextRun++
	path := filepath.Join(s.dir, fmt.Sprintf(".sort-%09d.jsonl", s.nextRun))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return sortRun{}, errors.New("create offline sort run")
	}
	ok := false
	counted := int64(0)
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
			s.budget.releaseWorking(counted)
		}
	}()
	workingWriter := &workingBudgetWriter{writer: file, budget: s.budget, counted: &counted}
	buffer := bufio.NewWriterSize(workingWriter, 64<<10)
	if err := write(json.NewEncoder(buffer)); err != nil {
		return sortRun{}, fmt.Errorf("write offline sort run: %w", err)
	}
	if err := buffer.Flush(); err != nil {
		return sortRun{}, fmt.Errorf("flush offline sort run: %w", err)
	}
	if err := file.Sync(); err != nil {
		return sortRun{}, errors.New("sync offline sort run")
	}
	if err := file.Close(); err != nil {
		return sortRun{}, errors.New("close offline sort run")
	}
	info, err := os.Stat(path)
	if err != nil {
		return sortRun{}, errors.New("inspect offline sort run")
	}
	if info.Size() != counted {
		return sortRun{}, errors.New("offline sort run byte accounting mismatch")
	}
	ok = true
	return sortRun{path: path, size: info.Size()}, nil
}

type workingBudgetWriter struct {
	writer  io.Writer
	budget  *budgets
	counted *int64
}

func (w *workingBudgetWriter) Write(p []byte) (int, error) {
	if err := w.budget.addWorking(int64(len(p))); err != nil {
		return 0, err
	}
	n, err := w.writer.Write(p)
	*w.counted += int64(n)
	if n < len(p) {
		w.budget.releaseWorking(int64(len(p) - n))
	}
	return n, err
}

type runReader struct {
	file    *os.File
	decoder *json.Decoder
}

type heapItem struct {
	value sortableEvent
	run   int
}

type mergeHeap []heapItem

func (h mergeHeap) Len() int { return len(h) }
func (h mergeHeap) Less(i, j int) bool {
	if h[i].value.ObservedSeconds != h[j].value.ObservedSeconds {
		return h[i].value.ObservedSeconds < h[j].value.ObservedSeconds
	}
	if h[i].value.ObservedNanos != h[j].value.ObservedNanos {
		return h[i].value.ObservedNanos < h[j].value.ObservedNanos
	}
	return h[i].value.Ordinal < h[j].value.Ordinal
}
func (h mergeHeap) Swap(i, j int)   { h[i], h[j] = h[j], h[i] }
func (h *mergeHeap) Push(value any) { *h = append(*h, value.(heapItem)) }
func (h *mergeHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func (s *eventSorter) mergeRuns(inputs []sortRun, emit func(sortableEvent) error) (returnErr error) {
	readers := make([]runReader, len(inputs))
	defer func() {
		for index := range readers {
			if readers[index].file != nil {
				if err := readers[index].file.Close(); err != nil {
					returnErr = errors.Join(returnErr, fmt.Errorf("close offline sort run: %w", err))
				}
			}
		}
	}()
	h := &mergeHeap{}
	heap.Init(h)
	for index, run := range inputs {
		file, err := os.Open(run.path)
		if err != nil {
			return errors.New("open offline sort run")
		}
		readers[index] = runReader{file: file, decoder: json.NewDecoder(bufio.NewReaderSize(file, 64<<10))}
		var item sortableEvent
		if err := readers[index].decoder.Decode(&item); err != nil {
			if err == io.EOF {
				continue
			}
			return errors.New("decode offline sort run")
		}
		heap.Push(h, heapItem{value: item, run: index})
	}
	for h.Len() > 0 {
		item := heap.Pop(h).(heapItem)
		if err := emit(item.value); err != nil {
			return err
		}
		var next sortableEvent
		err := readers[item.run].decoder.Decode(&next)
		if err == nil {
			heap.Push(h, heapItem{value: next, run: item.run})
		} else if err != io.EOF {
			return errors.New("decode offline sort run")
		}
	}
	return nil
}

func (s *eventSorter) removeRuns(runs []sortRun) error {
	var result error
	for _, run := range runs {
		if err := os.Remove(run.path); err != nil && !os.IsNotExist(err) {
			result = errors.Join(result, fmt.Errorf("%w: remove offline sort run", ErrCleanup))
			continue
		}
		s.budget.releaseWorking(run.size)
	}
	return result
}
