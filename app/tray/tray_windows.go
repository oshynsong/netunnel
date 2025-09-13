package tray

import (
	"github.com/oshynsong/netunnel/app/tray/menu"
	"github.com/oshynsong/netunnel/app/tray/wintray"
)

type service struct {
	impl *wintray.Instance
}

func newService(name string, icon []byte) (Service, error) {
	impl, err := wintray.New(name, icon)
	if err != nil {
		return nil, err
	}
	return &service{impl: impl}, nil
}

func (s *service) Run() { s.impl.Run() }

func (s *service) Quit() { s.impl.Quit() }

func (s *service) OnExit() <-chan struct{} { return s.OnExit() }

func (s *service) OnMainWindow() <-chan struct{} { return s.OnMainWindow() }

func (s *service) UpsertMenuItem(items ...*menu.Item) error {
	for _, item := range items {
		err := s.impl.UpsertMenuItem(item.ID(), item.ParentID(), item.Title, item.Disabled, item.Checked)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *service) ShowMenuItem(item *menu.Item) error {
	return s.UpsertMenuItem(item)
}

func (s *service) HideMenuItem(item *menu.Item) error {
	return s.impl.HideMenuItem(item.ID(), item.ParentID())
}

func (s *service) AddSeperator() error {
	seperator := menu.Add("", "", nil)
	return s.impl.AddSepMenuItem(seperator.ID(), 0)
}
