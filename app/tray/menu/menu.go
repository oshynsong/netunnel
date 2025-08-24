package menu

import (
	"fmt"
	"sync"
	"sync/atomic"
)

var (
	globalItemID uint32
	globalItems  map[uint32]*Item
	globalItemMu sync.RWMutex
)

func init() {
	globalItems = make(map[uint32]*Item)
}

// Item is the custom defined application menu item, and will keep track each
// item in the systray by this package.
type Item struct {
	parent  *Item
	eventCh chan struct{}
	id      uint32

	Title    string
	Tooltip  string
	Disabled bool
	Checked  bool
}

// Add creates a new menu item and save in the package level map.
func Add(title, tooltip string, parent *Item) *Item {
	return newItem(title, tooltip, parent)
}

// Get gets the menu item with given id from the package level map.
func Get(id uint32) *Item {
	globalItemMu.RLock()
	defer globalItemMu.RUnlock()
	item, existed := globalItems[id]
	if !existed {
		return nil
	}
	return item
}

// Remove removes the menu item with the given id from the package level map.
func Remove(id uint32) {
	globalItemMu.Lock()
	defer globalItemMu.Unlock()
	delete(globalItems, id)
}

func newItem(title, tooltip string, parent *Item) *Item {
	item := &Item{
		parent:  parent,
		eventCh: make(chan struct{}, 1),
		id:      atomic.AddUint32(&globalItemID, 1),
		Title:   title,
		Tooltip: tooltip,
	}
	globalItemMu.Lock()
	globalItems[item.id] = item
	globalItemMu.Unlock()
	return item
}

func (item *Item) ID() uint32 {
	return item.id
}

func (item *Item) ParentID() uint32 {
	if item.parent != nil {
		return uint32(item.parent.id)
	}
	return 0
}

func (item *Item) NotifyEvent() chan<- struct{} {
	return item.eventCh
}

func (item *Item) Event() <-chan struct{} {
	return item.eventCh
}

func (item *Item) AddSubItem(title, tooltip string) *Item {
	return newItem(title, tooltip, item)
}

func (item *Item) String() string {
	if item.parent == nil {
		return fmt.Sprintf("MenuItem[%d, %q]", item.id, item.Title)
	}
	return fmt.Sprintf("MenuItem[%d, parent %d, %q]", item.id, item.parent.id, item.Title)
}
