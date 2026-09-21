package global

import "testing"

func TestAlternateAppRepoURL(t *testing.T) {
	if _, ok := AlternateAppRepoURL("https://generic.cloudsmith.io/3panel/3panel/stable/3panel/app/version/file.tar.gz"); ok {
		t.Fatal("Cloudsmith requests must not be rewritten to a proxy")
	}
}
