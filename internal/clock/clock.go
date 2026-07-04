package clock

import "time"

// Clock provides time operations for deterministic testing
type Clock interface {
	Now() time.Time
}

// RealClock returns the actual system time
type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}

// FixedClock returns a fixed time for testing
type FixedClock struct {
	Time time.Time
}

func (c FixedClock) Now() time.Time {
	return c.Time
}
