package duplicacy

import (
	"sync"
	"time"
)

type ratePair struct {
	insertedTime int64
	value        int64
}

type WindowedRate struct {
	arrayCapacity int
	insertIndex   int
	arraySize     int
	mutex         sync.Mutex

	values []ratePair
}

func NewWindowedRate(arrayCapacity int) *WindowedRate {
	rpm := WindowedRate{}
	rpm.arrayCapacity = arrayCapacity
	rpm.insertIndex = -1
	rpm.values = make([]ratePair, arrayCapacity)

	for i := 0; i < arrayCapacity; i++ {
		rpm.values[i].insertedTime = time.Now().UnixNano()
	}

	return &rpm
}

/**
ComputeAverage calculates the average rate of transfer
between the earliest entry in the values array
and the latest submitted value.

Values are the total completed amount at a specific time.

It handles the case where the array was not filled completely.
*/
func (rpm *WindowedRate) ComputeAverage(value int64) int64 {
	rpm.mutex.Lock()
	rpm.insertIndex = (rpm.insertIndex + 1) % rpm.arrayCapacity
	if rpm.arraySize < rpm.arrayCapacity {
		rpm.arraySize++
	}

	latestEntry := ratePair{time.Now().UnixNano(), value}
	rpm.values[rpm.insertIndex] = latestEntry

	firstEntry := rpm.values[0] // this handles the case rpm.arraySize < rpm.arrayCapacity
	if rpm.arraySize == rpm.arrayCapacity {
		firstEntry = rpm.values[(rpm.insertIndex+1)%rpm.arrayCapacity]
	}
	rpm.mutex.Unlock()

	totalTransferred := latestEntry.value - firstEntry.value

	duration := latestEntry.insertedTime - firstEntry.insertedTime
	if duration == 0 {
		duration = 1
	}

	avg := (totalTransferred * 1e9) / duration
	return avg
}
