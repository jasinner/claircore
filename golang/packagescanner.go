// Package python contains components for interrogating python packages in
// container layers.
package python

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for directories that seem like wheels or eggs, and looks at the
// metadata recorded there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "golang" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

//Find global variable backing runtime.Version
//https://blog.filippo.io/reproducing-go-binaries-byte-by-byte/
func runtimeVersion(file string) string {
	cmdeGrep := exec.Command("egrep", "-a", "-o", "go[0-9\\.]+", os.Args[1])
	cmdSort := exec.Command("sort", "-u", "-n")

	reader, writer := io.Pipe()
	var buf bytes.Buffer

	cmdeGrep.Stdout = writer
	cmdSort.Stdin = reader
	cmdSort.Stdout = &buf

	cmdeGrep.Start()
	cmdSort.Start()

	cmdeGrep.Wait()
	writer.Close()

	cmdSort.Wait()
	reader.Close()

	return buf.String()
}

// Scan attempts to find elf binaries with a global variable backing runtime.Version
//
// A return of (nil, nil) is expected if there's nothing found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	log := zerolog.Ctx(ctx).With().
		Str("component", "golang/Scanner.Scan").
		Str("version", ps.Version()).
		Str("layer", layer.Hash.String()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rd, ok := r.(interface {
		io.ReadCloser
		io.Seeker
	})
	if !ok {
		return nil, errors.New("golang: cannot seek on returned layer Reader")
	}

	var ret []*claircore.Package
	tr := tar.NewReader(rd)
	var h *tar.Header
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		n, err := filepath.Rel("/", filepath.Join("/", h.Name))
		if err != nil {
			return nil, err
		}

		readerAt, err := os.Open(n)
		f := readerAt(n)
		var ident [16]uint8
		f.ReadAt(ident[0:], 0)
		if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
			continue
		}
		goVersion := runtimeVersion(n)

		ret = append(ret, &claircore.Package{
			Name:           strings.ToLower(hdr.Get("Name")),
			Version:        goVersion,
			PackageDB:      "golang:" + filepath.Join(n, "..", ".."),
			Kind:           claircore.SOURCE,
			RepositoryHint: "nvd-golang",
		})
	}
	if err != io.EOF {
		return nil, err
	}
	return ret, nil
}
