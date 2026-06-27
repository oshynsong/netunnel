//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/lxn/win"
	"github.com/oshynsong/netunnel/statics"
	"golang.org/x/sys/windows"
)

var (
	gInstance   win.HINSTANCE
	gNotifyData win.NOTIFYICONDATA
	gTrayMenu   win.HMENU
	gTrayIcon   win.HICON

	gMainWindow          win.HWND
	gMainWinProcCallback uintptr
	gMainClassName       = utf16PtrOf("NetunnelApp")
)

const (
	WM_TRAY_MSG  = win.WM_USER + 1
	NIF_MESSAGE  = 0x00000001
	NIF_ICON     = 0x00000002
	NIF_TIP      = 0x00000004
	TRAY_ICON_ID = 1
	IDM_LOGFILE  = 1001
	IDM_START    = 1002
	IDM_QUIT     = 1003
)

func RunApp(ctx context.Context) (err error) {
	// Create the module instance and register window classes.
	gInstance = win.GetModuleHandle(nil)
	if err = registerMainWindowClass(); err != nil {
		return err
	}

	// Create the invisible message window and tray icon.
	gMainWindow = win.CreateWindowEx(
		0, gMainClassName, utf16PtrOf("Netunnel"),
		0, 0, 0, 0, 0, win.HWND_MESSAGE, 0, gInstance, nil)
	if gMainWindow == 0 {
		return fmt.Errorf("app CreateWindowEx failed")
	}
	gTrayIcon = loadTrayIcon()
	gNotifyData.CbSize = uint32(unsafe.Sizeof(gNotifyData))
	gNotifyData.HWnd = gMainWindow
	gNotifyData.UID = TRAY_ICON_ID
	gNotifyData.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	gNotifyData.UCallbackMessage = WM_TRAY_MSG
	gNotifyData.HIcon = gTrayIcon
	tip, _ := syscall.UTF16FromString("Netunnel")
	copy(gNotifyData.SzTip[:], tip)
	shellNotifyIcon(&gNotifyData, win.NIM_ADD)

	// Start the message event loop.
	var msg win.MSG
	for win.GetMessage(&msg, 0, 0, 0) > 0 {
		win.TranslateMessage(&msg)
		win.DispatchMessage(&msg)
	}
	return nil
}

func registerMainWindowClass() error {
	gMainWinProcCallback = syscall.NewCallback(mainWinProc)

	var wclass win.WNDCLASSEX
	wclass.CbSize = uint32(unsafe.Sizeof(wclass))
	wclass.LpfnWndProc = gMainWinProcCallback
	wclass.HInstance = gInstance
	wclass.LpszClassName = gMainClassName
	if win.RegisterClassEx(&wclass) == 0 {
		return fmt.Errorf("app RegisterClassEx for main window failed")
	}
	return nil
}

func mainWinProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) (lResult uintptr) {
	switch msg {
	case WM_TRAY_MSG:
		switch lParam {
		case win.WM_LBUTTONUP, win.WM_RBUTTONUP: // show main window event
			showTrayMenu()
		}

	case win.WM_COMMAND:
		switch win.LOWORD(uint32(wParam)) {
		case IDM_LOGFILE:
			openLogFile()

		case IDM_START:
			startClientEndpoint()

		case IDM_QUIT:
			stopClientEndpoint()
			removeTrayIcon()
			win.PostQuitMessage(0)
		}

	case win.WM_DESTROY:
		stopClientEndpoint()
		removeTrayIcon()
		win.PostQuitMessage(0)

	default:
		return win.DefWindowProc(hwnd, msg, wParam, lParam)
	}
	return
}

func loadTrayIcon() win.HICON {
	var hicon win.HICON
	iconBytes, err := statics.Get("app.ico")
	if err == nil {
		var tmpFile *os.File
		tmpFile, err = os.CreateTemp("", "app.ico")
		if err == nil {
			tmpFilePath := tmpFile.Name()
			_, err = tmpFile.Write(iconBytes)
			tmpFile.Close()
			if err == nil {
				hicon = win.HICON(win.LoadImage(
					0, utf16PtrOf(tmpFilePath),
					win.IMAGE_ICON,
					0, 0,
					win.LR_LOADFROMFILE|win.LR_DEFAULTSIZE,
				))
			}
			os.Remove(tmpFilePath)
		}
	}
	if hicon == 0 {
		hicon = win.HICON(win.LoadImage(
			0, (*uint16)(unsafe.Pointer(uintptr(win.IDI_APPLICATION))),
			win.IMAGE_ICON,
			0, 0,
			win.LR_SHARED|win.LR_DEFAULTSIZE,
		))
	}
	return hicon
}

func removeTrayIcon() {
	shellNotifyIcon(&gNotifyData, win.NIM_DELETE)
}

func showTrayMenu() {
	if gTrayMenu != 0 {
		destroyMenu(gTrayMenu)
	}
	gTrayMenu = createPopupMenu()

	appendMenu(gTrayMenu, win.MF_STRING, IDM_LOGFILE, "View logs")
	runningFlags := uint32(win.MF_STRING)
	if gClientRunning {
		runningFlags |= win.MF_CHECKED
	}
	appendMenu(gTrayMenu, runningFlags, IDM_START, "Start Netunnel")
	appendMenu(gTrayMenu, win.MF_SEPARATOR, 0, "")
	appendMenu(gTrayMenu, win.MF_STRING, IDM_QUIT, "Quit")

	pt := getCursorPos()
	setForegroundWindow(gMainWindow)
	trackPopupMenu(gTrayMenu, win.TPM_BOTTOMALIGN|win.TPM_LEFTALIGN, pt.X, pt.Y, gMainWindow)

	win.PostMessage(gMainWindow, win.WM_NULL, 0, 0)
}

func openLogFile() {
	pShellExecute.Call(
		0,
		uintptr(unsafe.Pointer(utf16PtrOf("open"))),
		uintptr(unsafe.Pointer(utf16PtrOf(gLogFile))),
		0, 0, win.SW_SHOWNORMAL,
	)
}

//==================================API and helpers===============================//

var (
	u32 = windows.NewLazySystemDLL("User32.dll")
	s32 = windows.NewLazySystemDLL("Shell32.dll")

	pShellNotifyIcon     = s32.NewProc("Shell_NotifyIconW")
	pShellExecute        = s32.NewProc("ShellExecuteW")
	pDestroyMenu         = u32.NewProc("DestroyMenu")
	pTrackPopupMenu      = u32.NewProc("TrackPopupMenu")
	pCreatePopupMenu     = u32.NewProc("CreatePopupMenu")
	pAppendMenu          = u32.NewProc("AppendMenuW")
	pSetForegroundWindow = u32.NewProc("SetForegroundWindow")
	pGetCursorPos        = u32.NewProc("GetCursorPos")
)

func shellNotifyIcon(notifyData *win.NOTIFYICONDATA, action int) {
	pShellNotifyIcon.Call(uintptr(action), uintptr(unsafe.Pointer(notifyData)))
}

func destroyMenu(hMenu win.HMENU) {
	pDestroyMenu.Call(uintptr(hMenu))
}

func trackPopupMenu(hMenu win.HMENU, flags uint32, x, y int32, hwnd win.HWND) {
	pTrackPopupMenu.Call(
		uintptr(hMenu),
		uintptr(flags),
		uintptr(x), uintptr(y),
		0, uintptr(hwnd), 0,
	)
}

func createPopupMenu() win.HMENU {
	ret, _, _ := pCreatePopupMenu.Call()
	return win.HMENU(ret)
}

func appendMenu(hMenu win.HMENU, flags uint32, id uintptr, text string) {
	var ptr uintptr
	if len(text) != 0 {
		ptr = uintptr(unsafe.Pointer(utf16PtrOf(text)))
	}
	pAppendMenu.Call(uintptr(hMenu), uintptr(flags), id, ptr)
}

func setForegroundWindow(hwnd win.HWND) {
	pSetForegroundWindow.Call(uintptr(hwnd))
}

func getCursorPos() win.POINT {
	var pt win.POINT
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	return pt
}

func utf16PtrOf(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}
