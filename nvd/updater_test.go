package pyupio

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/log"
)

func TestDB(t *testing.T) {
	tt := []dbTestcase{
		{
			Name: "db_golang-2020",
			Want: []*claircore.Vulnerability{
				&claircore.Vulnerability{
					Name:           "CVE-2020-14039",
					Description:    "In Go before 1.13.13 and 1.14.x before 1.14.5, Certificate.Verify may lack a check on the VerifyOptions.KeyUsages EKU requirements (if VerifyOptions.Roots equals nil and the installation is on Windows). Thus, X.509 certificate verification is incomplete.",
					Package:        &claircore.Package{Name: "golang", Kind: claircore.BINARY},
					FixedInVersion: "1.14.5",
					//TODO add 1.13 range
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}

type dbTestcase struct {
	Name string
	Want []*claircore.Vulnerability
}

func (tc dbTestcase) filename() string {
	return filepath.Join("testdata", fmt.Sprintf("db_%s.json", tc.Name))
}

func (tc dbTestcase) Run(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()

	f, err := os.Open(tc.filename())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var db db
	if err := json.NewDecoder(f).Decode(&db); err != nil {
		t.Fatal(err)
	}

	got, err := db.Vulnerabilites(ctx, nil, "")
	if err != nil {
		t.Error(err)
	}
	// Sort for the comparison, because the Vulnerabilities method can return
	// the slice in any order.
	sort.SliceStable(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	if !cmp.Equal(tc.Want, got) {
		t.Error(cmp.Diff(tc.Want, got))
	}
}
