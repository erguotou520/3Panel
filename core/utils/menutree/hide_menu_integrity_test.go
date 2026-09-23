package menutree

import (
	"testing"

	"github.com/3panel-dev/3panel/core/app/dto"
)

func TestRemoveLegacyExtensionMenus(t *testing.T) {
	menus := []dto.ShowMenu{
		{ID: "1", Label: "Home-Menu"},
		{ID: "11", Label: "Legacy-Menu"},
		{ID: "13", Label: "Setting-Menu"},
	}

	got, changed := RemoveLegacyExtensionMenus(menus)
	if !changed {
		t.Fatal("expected legacy menu removal to be reported")
	}
	if len(got) != 2 || got[0].ID != "1" || got[1].ID != "13" {
		t.Fatalf("unexpected menus after cleanup: %#v", got)
	}
	if len(menus) != 3 {
		t.Fatal("cleanup must not mutate the input slice")
	}
}

func TestRemoveLegacyExtensionMenusWithoutLegacyMenu(t *testing.T) {
	menus := []dto.ShowMenu{{ID: "1", Label: "Home-Menu"}}

	got, changed := RemoveLegacyExtensionMenus(menus)
	if changed {
		t.Fatal("unexpected change without a legacy menu")
	}
	if len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("unexpected menus: %#v", got)
	}
}
