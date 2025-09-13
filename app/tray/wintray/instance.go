//go:build windows
// +build windows

package wintray

import (
	"fmt"
	"log/slog"
	"sync"
	"syscall"
	"unsafe"

	"github.com/oshynsong/netunnel/app/tray/menu"
	"golang.org/x/sys/windows"
)

// Instance stands for an tray program in windows platform.
type Instance struct {
	instance, icon, cursor, window windows.Handle
	name                           string

	loadedImages   map[string]windows.Handle
	muLoadedImages sync.RWMutex

	// menus keeps track of the submenus keyed by the menu item ID, plus 0
	// which corresponds to the main popup menu.
	menus   map[uint32]windows.Handle
	muMenus sync.RWMutex

	// menuOf keeps track of the menu each menu item belongs to.
	menuOf   map[uint32]windows.Handle
	muMenuOf sync.RWMutex

	// menuItemIcons maintains the bitmap of each menu item (if applies). It's
	// needed to show the icon correctly when showing a previously hidden menu
	// item again.
	menuItemIcons   map[uint32]windows.Handle
	muMenuItemIcons sync.RWMutex
	visibleItems    map[uint32][]uint32
	muVisibleItems  sync.RWMutex

	nid              *NotifyIconData
	muNID            sync.RWMutex
	wcex             *WindowClassEx
	wmSystrayMessage uint32
	wmTaskbarCreated uint32

	quitOnce     sync.Once
	onExit       chan struct{}
	onMainWindow chan struct{}
}

// New creates a windows tray program instance.
func New(name string, icon []byte) (*Instance, error) {
	s := &Instance{
		name:             name,
		loadedImages:     make(map[string]windows.Handle),
		menus:            make(map[uint32]windows.Handle),
		menuOf:           make(map[uint32]windows.Handle),
		menuItemIcons:    make(map[uint32]windows.Handle),
		visibleItems:     make(map[uint32][]uint32),
		wmSystrayMessage: WM_USER + 1,
		onExit:           make(chan struct{}),
		onMainWindow:     make(chan struct{}),
	}

	taskbarEventNamePtr, _ := syscall.UTF16PtrFromString("TaskbarCreated")
	res, _, err := pRegisterWindowMessage.Call(uintptr(unsafe.Pointer(taskbarEventNamePtr)))
	if res == 0 { // success 0xc000-0xfff
		return nil, fmt.Errorf("failed to register window: %w", err)
	}
	s.wmTaskbarCreated = uint32(res)

	instanceHandle, _, err := pGetModuleHandle.Call(0)
	if instanceHandle == 0 {
		return nil, fmt.Errorf("get instance module failed: %w", err)
	}
	s.instance = windows.Handle(instanceHandle)

	iconHandle, _, err := pLoadIcon.Call(0, uintptr(IDI_APPLICATION))
	if iconHandle == 0 {
		return nil, fmt.Errorf("load icon failed: %w", err)
	}
	s.icon = windows.Handle(iconHandle)

	cursorHandle, _, err := pLoadCursor.Call(0, uintptr(IDC_ARROW))
	if cursorHandle == 0 {
		return nil, fmt.Errorf("load cursor failed: %w", err)
	}
	s.cursor = windows.Handle(cursorHandle)

	classNamePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	windowNamePtr, err := windows.UTF16PtrFromString("")
	if err != nil {
		return nil, err
	}
	s.wcex = &WindowClassEx{
		Style:      CS_HREDRAW | CS_VREDRAW,
		WndProc:    windows.NewCallback(s.messageHandler),
		Instance:   s.instance,
		Icon:       s.icon,
		Cursor:     s.cursor,
		Background: windows.Handle(6), // (COLOR_WINDOW + 1)
		ClassName:  classNamePtr,
		IconSm:     s.icon,
	}
	if err := s.wcex.Register(); err != nil {
		return nil, fmt.Errorf("register window class error: %w", err)
	}

	windowHandle, _, err := pCreateWindowEx.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(classNamePtr)),
		uintptr(unsafe.Pointer(windowNamePtr)),
		uintptr(WS_OVERLAPPEDWINDOW),
		uintptr(CW_USEDEFAULT),
		uintptr(CW_USEDEFAULT),
		uintptr(CW_USEDEFAULT),
		uintptr(CW_USEDEFAULT),
		uintptr(0),
		uintptr(0),
		uintptr(s.instance),
		uintptr(0),
	)
	if windowHandle == 0 {
		return nil, fmt.Errorf("create window error: %w", err)
	}
	s.window = windows.Handle(windowHandle)

	pShowWindow.Call(uintptr(s.window), uintptr(SW_HIDE))
	if ret, _, err := pUpdateWindow.Call(uintptr(s.window)); ret == 0 {
		slog.Error(fmt.Sprintf("failed to update window: %s", err))
	}
	s.nid = &NotifyIconData{
		Wnd:             s.window,
		ID:              100,
		Flags:           NIF_MESSAGE,
		CallbackMessage: s.wmSystrayMessage,
	}
	s.nid.Size = uint32(unsafe.Sizeof(*s.nid))
	s.muNID.Lock()
	err = s.nid.Add()
	s.muNID.Unlock()
	if err != nil {
		return nil, fmt.Errorf("add notify icon data error: %w", err)
	}

	if err = s.createMainMenu(); err != nil {
		return nil, fmt.Errorf("create main menu failed: %w", err)
	}
	iconPath, err := s.iconBytesToFilePath(icon)
	if err != nil {
		return nil, fmt.Errorf("gen icon file path failed: %w", err)
	}
	if err := s.setMainMenuIcon(iconPath, name); err != nil {
		return nil, fmt.Errorf("set icon failed: %w", err)
	}
	return s, nil
}

func (s *Instance) Run() { s.messageLoop() }

func (s *Instance) Quit() {
	s.quitOnce.Do(func() {
		boolRet, _, err := pPostMessage.Call(
			uintptr(s.window),
			WM_CLOSE,
			0,
			0,
		)
		if boolRet == 0 {
			slog.Error(fmt.Sprintf("failed to close post message on shutdown %s", err))
		}
	})
}

func (s *Instance) OnExit() <-chan struct{} { return s.onExit }

func (s *Instance) OnMainWindow() <-chan struct{} { return s.onMainWindow }

func (s *Instance) messageLoop() {
	slog.Debug("start running event handling loop")
	m := &struct {
		WindowHandle windows.Handle
		Message      uint32
		Wparam       uintptr
		Lparam       uintptr
		Time         uint32
		Pt           Point
		LPrivate     uint32
	}{}

	// The typical message handling procedure for windows events process.
	for {
		ret, _, err := pGetMessage.Call(uintptr(unsafe.Pointer(m)), 0, 0, 0)

		// If the function retrieves a message other than WM_QUIT, the return value is nonzero.
		// If the function retrieves the WM_QUIT message, the return value is zero.
		// If there is an error, the return value is -1
		switch int32(ret) {
		case -1:
			slog.Error(fmt.Sprintf("get message failure: %v", err))
			return
		case 0:
			return
		default:
			pTranslateMessage.Call(uintptr(unsafe.Pointer(m))) //nolint:errcheck
			pDispatchMessage.Call(uintptr(unsafe.Pointer(m)))  //nolint:errcheck
		}
	}
}

func (s *Instance) messageHandler(hWnd windows.Handle, message uint32, wParam, lParam uintptr) (lResult uintptr) {
	const (
		WM_COMMAND    = 0x0111
		WM_ENDSESSION = 0x0016
		WM_CLOSE      = 0x0010
		WM_DESTROY    = 0x0002

		WM_MOUSEMOVE     = 0x0200
		WM_LBUTTONDOWN   = 0x0201
		WM_LBUTTONUP     = 0x0202
		WM_LBUTTONDBLCLK = 0x0203
		WM_RBUTTONDOWN   = 0x0204
		WM_RBUTTONUP     = 0x0205
	)
	switch message {
	case WM_COMMAND:
		item := menu.Get(uint32(wParam))
		if item == nil {
			slog.Debug(fmt.Sprintf("unexpected menu item id: %d", int32(wParam)))
			break
		}
		select {
		case item.NotifyEvent() <- struct{}{}: // send the command event to the menu item handler
		default:
			slog.Error(fmt.Sprintf("no handler for menu item id %d", int32(wParam)))
		}
	case WM_CLOSE:
		boolRet, _, err := pDestroyWindow.Call(uintptr(s.window))
		if boolRet == 0 {
			slog.Error(fmt.Sprintf("failed to destroy window: %s", err))
		}
		if err = s.wcex.Unregister(); err != nil {
			slog.Error(fmt.Sprintf("failed to unregister window %s", err))
		}
		slog.Info(fmt.Sprintf("closed: DestroyWindow=%v Unregister=%v", boolRet, err))
	case WM_DESTROY:
		// same as WM_ENDSESSION, but throws 0 exit code after all
		defer pPostQuitMessage.Call(uintptr(int32(0)))
		fallthrough
	case WM_ENDSESSION:
		s.muNID.Lock()
		if s.nid != nil {
			slog.Info(fmt.Sprintf("end session to delete notify icon data: %v", s.nid.Delete()))
		}
		s.muNID.Unlock()
		select {
		case s.onExit <- struct{}{}:
		default:
		}
	case s.wmSystrayMessage:
		switch lParam {
		case WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_RBUTTONDOWN: // ignore these messages
		case WM_LBUTTONUP, WM_LBUTTONDBLCLK: // show main window event
			select {
			case s.onMainWindow <- struct{}{}:
			default:
			}
			slog.Info("got show main window event")
		case WM_RBUTTONUP:
			err := s.showMainMenu()
			if err != nil {
				slog.Error(fmt.Sprintf("failed to show main menu: %s", err))
			}
		default:
			slog.Info(fmt.Sprintf("unmanaged message, lParm: 0x%x", lParam))
		}
	case s.wmTaskbarCreated: // on explorer.exe restarts
		s.muNID.Lock()
		err := s.nid.Add()
		if err != nil {
			slog.Error(fmt.Sprintf("failed to refresh the taskbar on explorer restart: %s", err))
		}
		s.muNID.Unlock()
	default:
		// Calls the default window procedure to provide default processing for
		// any window messages that an application does not process.
		lResult, _, _ = pDefWindowProc.Call(
			uintptr(hWnd),
			uintptr(message),
			uintptr(wParam),
			uintptr(lParam),
		)
	}
	return
}
