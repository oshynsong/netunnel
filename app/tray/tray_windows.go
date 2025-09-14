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

func (s *service) OnClicked() <-chan struct{} { return s.impl.OnClicked() }

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

func (s *service) ShowMainWindow() {
	/*name, closed := "Settings", make(chan struct{})

	wHandle, _, err := s.impl.NewWindow(name, 200, 400, false, nil, nil)

	wHandle, _, err := s.impl.CreateWindow(wintray.CreateWindowParam{
		Name:        name,
		Width:       300,
		Height:      400,
		CmdMessage:  make(chan any),
		ExitMessage: make(chan any),
	})
	if err != nil {
		slog.Error(fmt.Sprintf("create window failed: %v", err))
		return
	}
	go s.impl.RunWindowLoop(name, wHandle, closed)
	*/
	//time.Sleep(time.Second * 10)
	//s.impl.ExitWindow(name, wHandle, closed)
}
