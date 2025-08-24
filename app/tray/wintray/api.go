//go:build windows
// +build windows

package wintray

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	k32 = windows.NewLazySystemDLL("Kernel32.dll")
	u32 = windows.NewLazySystemDLL("User32.dll")
	s32 = windows.NewLazySystemDLL("Shell32.dll")

	pCreateMenu            = u32.NewProc("CreateMenu")
	pCreatePopupMenu       = u32.NewProc("CreatePopupMenu")
	pCreateWindowEx        = u32.NewProc("CreateWindowExW")
	pDefWindowProc         = u32.NewProc("DefWindowProcW")
	pDestroyWindow         = u32.NewProc("DestroyWindow")
	pRemoveMenu            = u32.NewProc("RemoveMenu")
	pDispatchMessage       = u32.NewProc("DispatchMessageW")
	pGetCursorPos          = u32.NewProc("GetCursorPos")
	pGetMessage            = u32.NewProc("GetMessageW")
	pGetModuleHandle       = k32.NewProc("GetModuleHandleW")
	pInsertMenuItem        = u32.NewProc("InsertMenuItemW")
	pLoadCursor            = u32.NewProc("LoadCursorW")
	pLoadIcon              = u32.NewProc("LoadIconW")
	pLoadImage             = u32.NewProc("LoadImageW")
	pPostMessage           = u32.NewProc("PostMessageW")
	pPostQuitMessage       = u32.NewProc("PostQuitMessage")
	pRegisterClass         = u32.NewProc("RegisterClassExW")
	pRegisterWindowMessage = u32.NewProc("RegisterWindowMessageW")
	pSetForegroundWindow   = u32.NewProc("SetForegroundWindow")
	pSetMenuInfo           = u32.NewProc("SetMenuInfo")
	pSetMenuItemInfo       = u32.NewProc("SetMenuItemInfoW")
	pShellNotifyIcon       = s32.NewProc("Shell_NotifyIconW")
	pShowWindow            = u32.NewProc("ShowWindow")
	pTrackPopupMenu        = u32.NewProc("TrackPopupMenu")
	pTranslateMessage      = u32.NewProc("TranslateMessage")
	pUnregisterClass       = u32.NewProc("UnregisterClassW")
	pUpdateWindow          = u32.NewProc("UpdateWindow")
)

const (
	CS_HREDRAW          = 0x0002
	CS_VREDRAW          = 0x0001
	CW_USEDEFAULT       = 0x80000000
	IDC_ARROW           = 32512 // Standard arrow
	IDI_APPLICATION     = 32512
	IMAGE_ICON          = 1          // Loads an icon
	LR_DEFAULTSIZE      = 0x00000040 // Loads default-size icon for windows(SM_CXICON x SM_CYICON) if cx, cy are set to zero
	LR_LOADFROMFILE     = 0x00000010 // Loads the stand-alone image from the file
	MF_BYCOMMAND        = 0x00000000
	MFS_DISABLED        = 0x00000003
	MFS_CHECKED         = 0x00000008
	MFT_SEPARATOR       = 0x00000800
	MFT_STRING          = 0x00000000
	MIIM_BITMAP         = 0x00000080
	MIIM_FTYPE          = 0x00000100
	MIIM_ID             = 0x00000002
	MIIM_STATE          = 0x00000001
	MIIM_STRING         = 0x00000040
	MIIM_SUBMENU        = 0x00000004
	MIM_APPLYTOSUBMENUS = 0x80000000
	NIF_ICON            = 0x00000002
	NIF_TIP             = 0x00000004
	NIF_INFO            = 0x00000010
	NIF_MESSAGE         = 0x00000001
	SW_HIDE             = 0
	TPM_BOTTOMALIGN     = 0x0020
	TPM_LEFTALIGN       = 0x0000
	TPM_RIGHTBUTTON     = 0x0002
	WM_CLOSE            = 0x0010
	WM_USER             = 0x0400
	WS_CAPTION          = 0x00C00000
	WS_MAXIMIZEBOX      = 0x00010000
	WS_MINIMIZEBOX      = 0x00020000
	WS_OVERLAPPED       = 0x00000000
	WS_OVERLAPPEDWINDOW = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX
	WS_SYSMENU          = 0x00080000
	WS_THICKFRAME       = 0x00040000
)

// Not sure if this is actually needed on windows
func init() {
	runtime.LockOSThread()
}

// Point defines the x- and y- coordinates of a point.
type Point struct {
	X, Y int32
}

// WindowClassEx holds the window information used by RegisterClassEx and
// GetClassInfoEx functions.
type WindowClassEx struct {
	Size, Style                        uint32
	WndProc                            uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background windows.Handle
	MenuName, ClassName                *uint16
	IconSm                             windows.Handle
}

// Register registers a window class for subsequent use in calls to the method
// CreateWindow or CreateWindowEx function.
func (w *WindowClassEx) Register() error {
	w.Size = uint32(unsafe.Sizeof(*w))
	res, _, err := pRegisterClass.Call(uintptr(unsafe.Pointer(w)))
	if res == 0 {
		return err
	}
	return nil
}

// Unregister unregisters a window class, freeing the memory for the class.
func (w *WindowClassEx) Unregister() error {
	res, _, err := pUnregisterClass.Call(
		uintptr(unsafe.Pointer(w.ClassName)),
		uintptr(w.Instance),
	)
	if res == 0 {
		return err
	}
	return nil
}

// NotifyIconData contains the information that the system needs to display
// notifications in the notification area.
type NotifyIconData struct {
	Size                       uint32
	Wnd                        windows.Handle
	ID, Flags, CallbackMessage uint32
	Icon                       windows.Handle
	Tip                        [128]uint16
	State, StateMask           uint32
	Info                       [256]uint16
	Timeout, Version           uint32

	InfoTitle   [64]uint16
	InfoFlags   uint32
	GuidItem    windows.GUID
	BalloonIcon windows.Handle
}

func (n *NotifyIconData) Add() error {
	const NIM_ADD = 0x00000000
	res, _, err := pShellNotifyIcon.Call(
		uintptr(NIM_ADD),
		uintptr(unsafe.Pointer(n)),
	)
	if res == 0 {
		return err
	}
	return nil
}

func (n *NotifyIconData) Modify() error {
	const NIM_MODIFY = 0x00000001
	res, _, err := pShellNotifyIcon.Call(
		uintptr(NIM_MODIFY),
		uintptr(unsafe.Pointer(n)),
	)
	if res == 0 {
		return err
	}
	return nil
}

func (n *NotifyIconData) Delete() error {
	const NIM_DELETE = 0x00000002
	res, _, err := pShellNotifyIcon.Call(
		uintptr(NIM_DELETE),
		uintptr(unsafe.Pointer(n)),
	)
	if res == 0 {
		return err
	}
	return nil
}

// MenuItemInfo contains information about a menu item.
type MenuItemInfo struct {
	Size, Mask, Type, State     uint32
	ID                          uint32
	SubMenu, Checked, Unchecked windows.Handle
	ItemData                    uintptr
	TypeData                    *uint16
	Cch                         uint32
	BMPItem                     windows.Handle
}
