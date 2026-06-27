//go:build !windows && !darwin

package main

import (
	"context"
	"runtime"
)

func RunApp(ctx context.Context) error {
	panic("app not implemented for os=" + runtime.GOOS + " arch=" + runtime.GOARCH)
}
