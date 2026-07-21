package testutil

import (
	"context"
	"time"
)

func HelperStamp() time.Time {
	return time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
}

func HelperCanceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	return ctx
}
