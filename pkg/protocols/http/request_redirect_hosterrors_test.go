package http

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache" //nolint:depguard // HTTP integration tests exercise the internal host cache.
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/utils/errkit"
)

// Redirect failures must not permanently poison the otherwise healthy source.
// The cache spy checks the actual address passed to MarkFailedOrRemove.
func TestRecordHostResultRedirectFailureUsesDestination(t *testing.T) {
	tests := []struct {
		name      string
		original  string
		pinnedIP  string
		err       error
		wantCache string
	}{
		{
			name:      "redirect to unresolvable host",
			original:  "https://live.example/app",
			err:       &url.Error{Op: "Get", URL: "http://nx.invalid/login", Err: errors.New("no address found for host")},
			wantCache: "nx.invalid:80",
		},
		{
			name:      "redirect to disallowed private address",
			original:  "https://live.example/app",
			err:       &url.Error{Op: "Get", URL: "http://127.0.0.1/private", Err: errors.New("denied address found for host")},
			wantCache: "127.0.0.1:80",
		},
		{
			name:      "direct failure stays on original host",
			original:  "https://live.example/app",
			err:       &url.Error{Op: "Get", URL: "https://live.example/app", Err: errors.New("no address found for host")},
			wantCache: "live.example:443",
		},
		{
			name:      "redirect away from pinned host drops pin",
			original:  "https://live.example/app",
			pinnedIP:  "192.0.2.10",
			err:       &url.Error{Op: "Get", URL: "https://nx.invalid/login", Err: errors.New("no address found for host")},
			wantCache: "nx.invalid:443",
		},
		{
			name:      "same-host scheme redirect retains pin",
			original:  "http://live.example/app",
			pinnedIP:  "192.0.2.10",
			err:       &url.Error{Op: "Get", URL: "https://live.example/login", Err: errors.New("connection refused")},
			wantCache: "192.0.2.10:443",
		},
		{
			name:      "errors without redirect information retain original",
			original:  "https://live.example/app",
			err:       errors.New("connection refused"),
			wantCache: "live.example:443",
		},
		{
			name:      "malformed redirect URL retains original",
			original:  "https://live.example/app",
			err:       &url.Error{Op: "Get", URL: ":bad:url", Err: errors.New("connection refused")},
			wantCache: "live.example:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &addressSpyHostErrorsCache{}
			req := &Request{options: &protocols.ExecutorOptions{
				ProtocolType:    templateTypes.HTTPProtocol,
				HostErrorsCache: spy,
			}}
			input := contextargs.NewWithInput(context.Background(), tt.original)
			input.MetaInput.CustomIP = tt.pinnedIP

			req.recordHostResult(input, tt.err)
			require.Equal(t, []string{tt.wantCache}, spy.marks)
			require.Equal(t, tt.original, input.MetaInput.Input, "original input must not be mutated")

			// Subsequent successful requests must still reset the original host.
			req.recordHostResult(input, nil)
			require.Equal(t, []string{input.MetaInput.Address()}, spy.resets)
		})
	}
}

// A redirect to an unknown hostname must not blacklist the healthy target.
// This test uses the real cache, including its permanent-error behavior.
func TestRedirectFailureDoesNotPermanentlySkipOriginal(t *testing.T) {
	cache := hosterrorscache.New(1, 100, nil)
	defer cache.Close()
	req := &Request{options: &protocols.ExecutorOptions{
		ProtocolType:    templateTypes.HTTPProtocol,
		HostErrorsCache: cache,
	}}
	original := contextargs.NewWithInput(context.Background(), "http://healthy.test:8080")
	failed := contextargs.NewWithInput(context.Background(), "http://nx.invalid:80")
	cause := errkit.New("no address found for host").SetKind(errkit.ErrKindNetworkPermanent)
	req.recordHostResult(original, &url.Error{Op: "Get", URL: "http://nx.invalid:80/login", Err: cause})

	require.False(t, cache.Check("http", original), "failed redirect must not suppress the healthy target")
	require.True(t, cache.Check("http", failed), "the failed redirect hostname is permanently unavailable")
}
