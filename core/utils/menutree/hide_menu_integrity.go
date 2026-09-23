package menutree

import "github.com/3panel-dev/3panel/core/app/dto"

const legacyExtensionMenuID = "11"

func PreserveMissingMenus(menus, fallback []dto.ShowMenu) ([]dto.ShowMenu, bool) {
	updated := cloneMenus(menus)
	changed := preserveMissingMenus(&updated, &updated, fallback)
	return updated, changed
}

func preserveMissingMenus(root, current *[]dto.ShowMenu, fallback []dto.ShowMenu) bool {
	changed := false
	for _, previous := range fallback {
		menuIndex := findMatchingMenu(*current, previous)
		if menuIndex < 0 {
			if containsMenu(*root, previous) {
				continue
			}
			*current = append(*current, cloneMenu(previous))
			changed = true
			continue
		}
		if preserveMissingMenus(root, &(*current)[menuIndex].Children, previous.Children) {
			changed = true
		}
	}
	return changed
}

func RemoveLegacyExtensionMenus(menus []dto.ShowMenu) ([]dto.ShowMenu, bool) {
	updated := cloneMenus(menus)
	for i := range updated {
		if updated[i].ID == legacyExtensionMenuID {
			return append(updated[:i], updated[i+1:]...), true
		}
	}
	return updated, false
}

func findMatchingMenu(menus []dto.ShowMenu, target dto.ShowMenu) int {
	if target.ID != "" {
		for i := range menus {
			if menus[i].ID == target.ID {
				return i
			}
		}
	}
	if target.Label != "" {
		for i := range menus {
			if menus[i].Label == target.Label {
				return i
			}
		}
	}
	if target.Path != "" {
		for i := range menus {
			if menus[i].Path == target.Path {
				return i
			}
		}
	}
	return -1
}

func containsMenu(menus []dto.ShowMenu, target dto.ShowMenu) bool {
	if findMatchingMenu(menus, target) >= 0 {
		return true
	}
	for i := range menus {
		if containsMenu(menus[i].Children, target) {
			return true
		}
	}
	return false
}

func cloneMenus(menus []dto.ShowMenu) []dto.ShowMenu {
	if menus == nil {
		return nil
	}
	cloned := make([]dto.ShowMenu, len(menus))
	for i := range menus {
		cloned[i] = cloneMenu(menus[i])
	}
	return cloned
}

func cloneMenu(menu dto.ShowMenu) dto.ShowMenu {
	menu.Children = cloneMenus(menu.Children)
	return menu
}
