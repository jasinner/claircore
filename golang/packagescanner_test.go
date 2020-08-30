package python_test

import (
	"context"
	"path"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

// TestScan runs the python scanner over some layers known to have python
// packages installed.
func TestScan(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	for _, tc := range scanTable {
		t.Run(path.Base(tc.Name), tc.Run(ctx))
	}
}

var scanTable = []test.ScannerTestcase{
	{
		Domain: "registry.redhat.io",
		Name:   "rhel7/etcd",
		Hash:   "sha256:04ac5c8cee7c41b966024a307175a9b3cdbdaac331e11870408413c06a8cbae1",
		Want: []*claircore.Package{
			&claircore.Package{
				Name:           "golang",
				Version:        "1.10.3",
				Kind:           claircore.SOURCE,
				PackageDB:      "/usr/bin/etcd",
				RepositoryHint: "nvd-golang",
			},
		},
		Scanner: &golang.Scanner{},
	},
}
