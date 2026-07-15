// Package clockx contains shared clock selection helpers.
package clockx

import "time"

// OrNow returns clock when configured and time.Now otherwise.
func OrNow(clock func() time.Time) func() time.Time {
	if clock != nil {
		return clock
	}
	return time.Now
}
