package http_test

//nolint:depguard // HTTP request integration tests use internal test helpers.
import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

// TestRedirectDNSFailureKeepsHealthyTarget exercises the complete HTTP request
// path rather than only the cache helper: an unresolved redirect destination
// must not suppress later requests sent to the healthy original target.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // Fixtures use zero-value defaults; testutils.Init is global.
func TestRedirectDNSFailureKeepsHealthyTarget(t *testing.T) {
	const redirectHost = "nx-nuclei-redirect-regression.invalid"
	var mu sync.Mutex
	var paths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()

		if r.URL.Path == "/admin" {
			w.Header().Set("Location", "http://"+redirectHost+"/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	cache := hosterrorscache.New(1, 100, nil)
	t.Cleanup(cache.Close)

	request := &httpprotocol.Request{
		ID:           "redirect-dns-failure-keeps-original",
		Method:       methodGet(),
		Path:         []string{"{{BaseURL}}/admin", "{{BaseURL}}/ok", "{{BaseURL}}/also-ok"},
		Redirects:    true,
		MaxRedirects: 2,
	}
	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: request.ID,
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Name:           "test",
		},
	})
	executerOpts.HostErrorsCache = cache
	t.Cleanup(executerOpts.RateLimiter.Stop)
	require.NoError(t, request.Compile(executerOpts))

	// The first URL fails at the redirected destination. The request block can
	// still return that error; the observable guarantee is that later paths run.
	_, _ = executeSkippable(request, server.URL)

	mu.Lock()
	visited := append([]string(nil), paths...)
	mu.Unlock()

	require.Equal(t, []string{"/admin", "/ok", "/also-ok"}, visited)
	require.False(t, cache.Check("http", contextargs.NewWithInput(context.Background(), server.URL)),
		"DNS failure at the redirect must not blacklist the healthy server")
	// OS-specific DNS/proxy behavior can change the error classification.
	// The dedicated permanent-error cache test asserts destination attribution.
}
