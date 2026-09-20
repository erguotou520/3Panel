package global

import "testing"

func TestAlternateAppRepoURL(t *testing.T) {
	direct := "https://3panel.erguotou.me/stable/3panel/app/version/file.tar.gz"
	proxy := "https://proxy.erguotou.me/" + direct

	if got, ok := AlternateAppRepoURL(direct); !ok || got != proxy {
		t.Fatalf("direct to proxy: got %q, ok=%v", got, ok)
	}
	if got, ok := AlternateAppRepoURL(proxy); !ok || got != direct {
		t.Fatalf("proxy to direct: got %q, ok=%v", got, ok)
	}
	if _, ok := AlternateAppRepoURL("https://example.com/file"); ok {
		t.Fatal("unrelated URL must not be rewritten")
	}
}
