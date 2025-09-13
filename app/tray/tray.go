package tray

import (
	"runtime"

	"github.com/oshynsong/netunnel/app/tray/menu"
)

func init() {
	runtime.LockOSThread()
}

// New creates a tray program service instance with given name and icon.
func New(name string, icon []byte) (Service, error) {
	return newService(name, icon)
}

// Service represents an abstract tray program with essential operations to be
// implemented by different platforms with their own native APIs.
type Service interface {
	Run()
	Quit()
	OnExit() <-chan struct{}
	OnMainWindow() <-chan struct{}

	UpsertMenuItem(items ...*menu.Item) error
	ShowMenuItem(item *menu.Item) error
	HideMenuItem(item *menu.Item) error
	AddSeperator() error
}
