package golang_test

import (
	"context"
	"path"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/golang"
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
				Name:           "/usr/bin/etcd",
				Version:        "1.10.3",
				Kind:           claircore.SOURCE,
				PackageDB:      "golang:/usr/bin",
				RepositoryHint: "nvd-golang",
			},
			&claircore.Package{
				Name:           "/usr/bin/etcdctl",
				Version:        "1.10.3",
				Kind:           claircore.SOURCE,
				PackageDB:      "golang:/usr/bin",
				RepositoryHint: "nvd-golang",
			},
		},
		Scanner: &golang.Scanner{},
	},
	{
		Domain: "registry.redhat.io",
		Name:   "openshift4/ose-cli",
		Hash:   "sha256:926323f38f36d42281a384cdd2d5ff1da921ea0a37cfa77acb74a8c1aee035c7",
		Want: []*claircore.Package{
			&claircore.Package{
				Name:           "/usr/bin/oc",
				Version:        "1.13.4",
				Kind:           claircore.SOURCE,
				PackageDB:      "golang:/usr/bin",
				RepositoryHint: "nvd-golang",
			},
		},
		Scanner: &golang.Scanner{},
	},
	{
		Domain: "registry.redhat.io",
		Name:   "openshift3/ose-docker-registry",
		Hash:   "sha256:f4c0f4add381f4d9ce2bb32df9d38b3363a94d52fd40d78f896bc6333ab4d430",
		Want: []*claircore.Package{
			&claircore.Package{
				Name:           "/usr/bin/dockerregistry",
				Version:        "1.9.4",
				Kind:           claircore.SOURCE,
				PackageDB:      "golang:/usr/bin",
				RepositoryHint: "nvd-golang",
			},
		},
		Scanner: &golang.Scanner{},
	},
	{
		Domain: "docker.io",
		Name:   "library/caddy",
		Hash:   "sha256:4c061a8d220609365e9b730c004a55a5156c0cc0970d0ea7eb0a43ba10f25e16",
		Want: []*claircore.Package{
			&claircore.Package{
				Name:           "/usr/bin/caddy",
				Version:        "1.14.4",
				Kind:           claircore.SOURCE,
				PackageDB:      "golang:/usr/bin",
				RepositoryHint: "nvd-golang",
			},
		},
		Scanner: &golang.Scanner{},
	},
}
