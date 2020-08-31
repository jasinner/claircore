// Package pyupio provides an updater for importing pyup vulnerability
// information.
package nvd

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/pep440"
	"github.com/quay/claircore/pkg/tmp"
)

const DATA_URL = `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz`
const META_URL = `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.meta`

var (
	_ driver.Updater = (*Updater)(nil)

	defaultRepo = claircore.Repository{
		Name: "nvd",
		URI:  "https://nvd.nist.gov/vuln/data-feeds#JSON_FEED",
	}
)

// Updater reads the National Vulnerability Database JSON feed for vulnerabilities.
//
// The zero value is not safe to use.
type Updater struct {
	url    *url.URL
	meta   *url.URL
	client *http.Client
	year   int16
	repo   *claircore.Repository
}

func NewUpdater(year int16) *Updater {

	url := fmt.Sprintf(DATA_URL, year)
	meta := fmt.Sprintf(META_URL, year)

	return &Updater{
		url:  url,
		meta: meta,
		year: year,
		c:    http.DefaultClient,
	}
}

func (u *Updater) Name() string {
	return fmt.Sprintf("nvd-%d-updater", u.year)
}

// Option controls the configuration of an Updater.
type Option func(*Updater) error

// WithClient sets the http.Client that the updater should use for requests.
//
// If not passed to NewUpdater, http.DefaultClient will be used.
func WithClient(c *http.Client) Option {
	return func(u *Updater) error {
		u.client = c
		return nil
	}
}

// WithRepo sets the repository information that will be associated with all the
// vulnerabilites found.
//
// If not passed to NewUpdater, a default Repository will be used.
func WithRepo(r *claircore.Repository) Option {
	return func(u *Updater) error {
		u.repo = r
		return nil
	}
}

// WithURL sets the URL the updater should fetch.
//
// The URL should point to a gzip compressed tarball containing a properly
// formatted json object in a file named `insecure_full.json`.
//
// If not passed to NewUpdater, the master branch of github.com/pyupio/safety-db
// will be fetched.
func WithURL(uri string) Option {
	u, err := url.Parse(uri)
	return func(up *Updater) error {
		if err != nil {
			return err
		}
		up.url = u
		return nil
	}
}

// Name implements driver.Updater.
func (*Updater) Name() string { return "nvd" }

// Fetch implements driver.Updater.
func (u *Updater) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "nvd/Updater.Fetch").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Str("database", u.url.String()).Msg("starting fetch")
	metaReq := http.Request{
		Method:     http.MethodGet,
		Header:     http.Header{"User-Agent": {"claircore/nvd/Updater"}},
		URL:        u.meta,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       u.url.Host,
	}

	res, err := u.client.Do(req.WithContext(ctx))
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, hint, err
	}
	if res.StatusCode != http.StatusOK{
		return nil, hint, fmt.Errorf("nvd: fetcher got unexpected HTTP response: %d (%s)", res.StatusCode, res.Status)
	}
	log.Debug().Msg("request ok")

	scanner := bufio.NewScanner(res.
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "sha256:")
	}
	if err := scanner.Err(); err != nil {
		return nil, hint, err
	}

	//TODO get the actual (data)
	// tf, err := tmp.NewFile("", "pyupio.")
	// if err != nil {
		// return nil, hint, err
	// }
	// log.Debug().
		// Str("path", tf.Name()).
		// Msg("using tempfile")
	// success := false
	// defer func() {
		// if !success {
			// log.Debug().Msg("unsuccessful, cleaning up tempfile")
			// if err := tf.Close(); err != nil {
				// log.Warn().Err(err).Msg("failed to close tempfile")
			// }
		// }
	// }()
// 
	// if _, err := io.Copy(tf, r); err != nil {
		// return nil, hint, err
	// }
	// if o, err := tf.Seek(0, io.SeekStart); err != nil || o != 0 {
		// return nil, hint, err
	// }
	// log.Debug().Msg("decompressed and buffered database")

	if t := res.Header.Get("etag"); t != "" {
		log.Debug().
			Str("hint", t).
			Msg("using new hint")
		hint = driver.Fingerprint(t)
	}
	success = true
	return tf, hint, nil
}

//TODO make this work for nvd
// Parse implements driver.Updater.
func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "pyupio/Updater.Parse").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("parse start")
	defer r.Close()
	defer log.Info().Msg("parse done")

	var db db
	tr := tar.NewReader(r)
	h, err := tr.Next()
	done := false
	for ; err == nil && !done; h, err = tr.Next() {
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != "insecure_full.json" {
			continue
		}
		if err := json.NewDecoder(tr).Decode(&db); err != nil {
			return nil, err
		}
	}
	if err != io.EOF {
		return nil, err
	}
	log.Debug().
		Int("count", len(db)).
		Msg("found raw entries")

	ret, err := db.Vulnerabilites(ctx, u.repo, u.Name())
	if err != nil {
		return nil, err
	}
	log.Debug().
		Int("count", len(ret)).
		Msg("found vulnerabilities")
	return ret, nil
}

type db map[string][]entry

type entry struct {
	Advisory string   `json:"advisory"`
	CVE      *string  `json:"cve"`
	ID       string   `json:"id"`
	Specs    []string `json:"specs"`
	V        string   `json:"v"`
}

var vZero pep440.Version

func init() {
	var err error
	vZero, err = pep440.Parse("0")
	if err != nil {
		panic(err)
	}
}


//TODO make this work for nvd
func (db db) Vulnerabilites(ctx context.Context, repo *claircore.Repository, updater string) ([]*claircore.Vulnerability, error) {
	const opSet = `<>=!`
	log := zerolog.Ctx(ctx).With().
		Str("component", "pyupio/db.Vulnerabilities").
		Logger()

	var mungeCt int
	var ret []*claircore.Vulnerability
	for k, es := range db {
		for _, e := range es {
		Vuln:
			for _, spec := range e.Specs {
				v := &claircore.Vulnerability{
					Name:        e.ID,
					Updater:     updater,
					Description: e.Advisory,
					Package:     &claircore.Package{Name: strings.ToLower(k), Kind: claircore.BINARY},
					Repo:        repo,
					Range:       &claircore.Range{},
				}
				if e.CVE != nil {
					v.Name += fmt.Sprintf(" (%s)", *e.CVE)
				}
				specs := strings.Split(spec, ",")
				ls := len(specs)
				if ls == 1 {
					v.Range.Lower = vZero.Version()
				}
				if ls > 2 && ls%2 == 1 {
					log.Warn().
						Str("spec", spec).
						Msg("malformed database entry")
					continue
				}
				for _, r := range specs {
					i := strings.LastIndexAny(r, opSet) + 1
					ver, err := pep440.Parse(r[i:])
					if err != nil {
						log.Info().
							Err(err).
							Str("version", r[i:]).
							Msg("unable to parse version as pep440")
						continue Vuln
					}
					switch strings.TrimSpace(r[:i]) {
					case ">":
						// Treat the same as greater-than-equal becase we can't
						// turn one into the other without having a list of
						// versions.
						mungeCt++
						fallthrough
					case ">=":
						v.Range.Lower = ver.Version()
					case "<=":
						mungeCt++
						ver.Post++
						fallthrough
					case "<":
						v.FixedInVersion = ver.String()
						v.Range.Upper = ver.Version()
					case "==":
						// Since range is half-open, this is equivalent to
						// specifying exactly one version.
						v.Range.Lower = ver.Version()
						v.Range.Upper = ver.Version()
					default:
						log.Warn().
							Str("comparison", r[:i]).
							Msg("unexpected comparison, please file an issue")
					}
				}
				if v.Range.Lower.Compare(&v.Range.Upper) == 1 {
					log.Debug().
						Str("id", e.ID).
						Str("name", k).
						Str("spec", spec).
						Msg("malformed range")
					continue
				}
				ret = append(ret, v)
			}
		}
	}
	if mungeCt > 0 {
		log.Debug().
			Int("count", mungeCt).
			Msg("munged bounds on some vulnerabilities 😬")
	}
	return ret, nil
}
