package main

import (
	"fmt"
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
)

func main() {
	notifyLmt := tollbooth.NewLimiter(1.0/60.0, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Minute,
	}).SetBurst(1)

	ip := "127.0.0.1"

	err := tollbooth.LimitByKeys(notifyLmt, []string{ip})
	fmt.Printf("Initial: err=%v\n", err)

	start := time.Now()
	for {
		err := tollbooth.LimitByKeys(notifyLmt, []string{ip})
		if err == nil {
			fmt.Printf("Allowed after %v\n", time.Since(start))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}
