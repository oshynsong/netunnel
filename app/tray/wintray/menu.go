//go:build windows
// +build windows

package wintray

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (s *Instance) createMainMenu() error {
	handle, _, createErr := pCreatePopupMenu.Call()
	if handle == 0 {
		return createErr
	}
	s.menus[0] = windows.Handle(handle)

	mi := struct {
		Size, Mask, Style, Max uint32
		Background             windows.Handle
		ContextHelpID          uint32
		MenuData               uintptr
	}{
		Mask: MIM_APPLYTOSUBMENUS,
	}
	mi.Size = uint32(unsafe.Sizeof(mi))

	res, _, err := pSetMenuInfo.Call(
		uintptr(s.menus[0]),
		uintptr(unsafe.Pointer(&mi)),
	)
	if res == 0 {
		return err
	}
	return nil
}

func (s *Instance) showMainMenu() error {
	var p Point
	boolRet, _, err := pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	if boolRet == 0 {
		return err
	}
	boolRet, _, err = pSetForegroundWindow.Call(uintptr(s.window))
	if boolRet == 0 {
		slog.Warn(fmt.Sprintf("failed to bring menu to foreground: %s", err))
	}

	boolRet, _, err = pTrackPopupMenu.Call(
		uintptr(s.menus[0]),
		TPM_BOTTOMALIGN|TPM_LEFTALIGN|TPM_RIGHTBUTTON,
		uintptr(p.X),
		uintptr(p.Y),
		0,
		uintptr(s.window),
		0,
	)
	if boolRet == 0 {
		return err
	}
	return nil
}

func (s *Instance) AddSepMenuItem(menuItemId, parentId uint32) error {
	mi := MenuItemInfo{
		Mask: MIIM_FTYPE | MIIM_ID | MIIM_STATE,
		Type: MFT_SEPARATOR,
		ID:   menuItemId,
	}

	mi.Size = uint32(unsafe.Sizeof(mi))

	s.addToVisibleItems(parentId, menuItemId)
	position := s.getVisibleItemIndex(parentId, menuItemId)
	s.muMenus.RLock()
	menu := uintptr(s.menus[parentId])
	s.muMenus.RUnlock()
	res, _, err := pInsertMenuItem.Call(
		menu,
		uintptr(position),
		1,
		uintptr(unsafe.Pointer(&mi)),
	)
	if res == 0 {
		return err
	}

	return nil
}

func (s *Instance) UpsertMenuItem(menuItemId uint32, parentId uint32, title string, disabled, checked bool) error {
	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return err
	}
	mi := MenuItemInfo{
		Mask:     MIIM_FTYPE | MIIM_STRING | MIIM_ID | MIIM_STATE,
		Type:     MFT_STRING,
		ID:       uint32(menuItemId),
		TypeData: titlePtr,
		Cch:      uint32(len(title)),
	}
	mi.Size = uint32(unsafe.Sizeof(mi))
	if disabled {
		mi.State |= MFS_DISABLED
	}
	if checked {
		mi.State |= MFS_CHECKED
	}
	s.muMenuItemIcons.RLock()
	hIcon := s.menuItemIcons[menuItemId]
	s.muMenuItemIcons.RUnlock()
	if hIcon > 0 {
		mi.Mask |= MIIM_BITMAP
		mi.BMPItem = hIcon
	}

	var res uintptr
	s.muMenus.RLock()
	menu, exists := s.menus[parentId]
	s.muMenus.RUnlock()
	if !exists {
		menu, err = s.convertToSubMenu(parentId)
		if err != nil {
			return err
		}
		s.muMenus.Lock()
		s.menus[parentId] = menu
		s.muMenus.Unlock()
	} else if s.getVisibleItemIndex(parentId, menuItemId) != -1 {
		res, _, err = pSetMenuItemInfo.Call(
			uintptr(menu),
			uintptr(menuItemId),
			0,
			uintptr(unsafe.Pointer(&mi)),
		)
	}

	if res == 0 { // item does not already exist, create it
		s.muMenus.RLock()
		submenu, exists := s.menus[menuItemId]
		s.muMenus.RUnlock()
		if exists {
			mi.Mask |= MIIM_SUBMENU
			mi.SubMenu = submenu
		}
		s.addToVisibleItems(parentId, menuItemId)
		position := s.getVisibleItemIndex(parentId, menuItemId)
		res, _, err = pInsertMenuItem.Call(
			uintptr(menu),
			uintptr(position),
			1,
			uintptr(unsafe.Pointer(&mi)),
		)
		if res == 0 {
			s.delFromVisibleItems(parentId, menuItemId)
			return err
		}
		s.muMenuOf.Lock()
		s.menuOf[menuItemId] = menu
		s.muMenuOf.Unlock()
	}
	return nil
}

func (s *Instance) convertToSubMenu(menuItemId uint32) (windows.Handle, error) {
	res, _, err := pCreateMenu.Call()
	if res == 0 {
		return 0, err
	}
	menu := windows.Handle(res)

	mi := MenuItemInfo{Mask: MIIM_SUBMENU, SubMenu: menu}
	mi.Size = uint32(unsafe.Sizeof(mi))
	s.muMenuOf.RLock()
	hMenu := s.menuOf[menuItemId]
	s.muMenuOf.RUnlock()
	res, _, err = pSetMenuItemInfo.Call(
		uintptr(hMenu),
		uintptr(menuItemId),
		0,
		uintptr(unsafe.Pointer(&mi)),
	)
	if res == 0 {
		return 0, err
	}
	s.muMenus.Lock()
	s.menus[menuItemId] = menu
	s.muMenus.Unlock()
	return menu, nil
}

func (s *Instance) HideMenuItem(menuItemId, parentId uint32) error {
	const ERROR_SUCCESS syscall.Errno = 0

	s.muMenus.RLock()
	menu := uintptr(s.menus[parentId])
	s.muMenus.RUnlock()
	res, _, err := pRemoveMenu.Call(
		menu,
		uintptr(menuItemId),
		MF_BYCOMMAND,
	)
	if res == 0 && err.(syscall.Errno) != ERROR_SUCCESS {
		return err
	}
	s.delFromVisibleItems(parentId, menuItemId)

	return nil
}

func (s *Instance) getVisibleItemIndex(parent, val uint32) int {
	s.muVisibleItems.RLock()
	defer s.muVisibleItems.RUnlock()
	for i, itemval := range s.visibleItems[parent] {
		if val == itemval {
			return i
		}
	}
	return -1
}

func (s *Instance) addToVisibleItems(parent, val uint32) {
	s.muVisibleItems.Lock()
	defer s.muVisibleItems.Unlock()
	if visibleItems, exists := s.visibleItems[parent]; !exists {
		s.visibleItems[parent] = []uint32{val}
	} else {
		newvisible := append(visibleItems, val)
		sort.Slice(newvisible, func(i, j int) bool { return newvisible[i] < newvisible[j] })
		s.visibleItems[parent] = newvisible
	}
}

func (s *Instance) delFromVisibleItems(parent, val uint32) {
	s.muVisibleItems.Lock()
	defer s.muVisibleItems.Unlock()
	visibleItems := s.visibleItems[parent]
	for i, itemval := range visibleItems {
		if val == itemval {
			s.visibleItems[parent] = append(visibleItems[:i], visibleItems[i+1:]...)
			break
		}
	}
}

func (s *Instance) iconBytesToFilePath(iconBytes []byte) (string, error) {
	bh := md5.Sum(iconBytes)
	dataHash := hex.EncodeToString(bh[:])
	iconFilePath := filepath.Join(os.TempDir(), s.name+"_"+dataHash)

	if _, err := os.Stat(iconFilePath); os.IsNotExist(err) {
		if err := os.WriteFile(iconFilePath, iconBytes, 0o644); err != nil {
			return "", err
		}
	}
	return iconFilePath, nil
}

func (s *Instance) setMainMenuIcon(iconPath, toolTip string) error {
	h, err := s.loadIcon(iconPath)
	if err != nil {
		return fmt.Errorf("load icon: %w", err)
	}

	s.muNID.Lock()
	defer s.muNID.Unlock()
	s.nid.Icon = h
	s.nid.Flags |= NIF_ICON | NIF_TIP
	if toolTipUTF16, err := syscall.UTF16FromString(toolTip); err == nil {
		copy(s.nid.Tip[:], toolTipUTF16)
	} else {
		return err
	}
	s.nid.Size = uint32(unsafe.Sizeof(*s.nid))

	return s.nid.Modify()
}

func (s *Instance) loadIcon(iconPath string) (windows.Handle, error) {
	s.muLoadedImages.RLock()
	h, ok := s.loadedImages[iconPath]
	s.muLoadedImages.RUnlock()
	if !ok {
		srcPtr, err := windows.UTF16PtrFromString(iconPath)
		if err != nil {
			return 0, err
		}
		res, _, err := pLoadImage.Call(
			0,
			uintptr(unsafe.Pointer(srcPtr)),
			IMAGE_ICON,
			0,
			0,
			LR_LOADFROMFILE|LR_DEFAULTSIZE,
		)
		if res == 0 {
			return 0, fmt.Errorf("call LoadImage error: %w", err)
		}
		h = windows.Handle(res)
		s.muLoadedImages.Lock()
		s.loadedImages[iconPath] = h
		s.muLoadedImages.Unlock()
	}
	return h, nil
}
