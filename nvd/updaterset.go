package nvd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/quay/claircore/libvuln/driver"
)

const startYear = 2002

type Year int16

type Factory struct {
	Years []Year
}

// NewFactory creates a Factory making updaters based on the current year
// TODO figure out where to add Updaters dynamically (in case a change in year occurs while running)
func NewFactory(ctx context.Context, manifest string, opts ...FactoryOption) (*Factory, error) {
	var err error
	f := Factory{
		client: http.DefaultClient,
	}

	currentYear := time.Now().Format("2006")
	for currentYear >= startYear{
		f.Years.append(currentYear--)
	}

	for _, o := range opts {
		if err := o(&f); err != nil {
			return nil, err
		}
	}
	return &f, nil
}

// UpdaterSet returns updaters for all releases that have available databases.
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "nvd/Factory/UpdaterSet").
		Logger()
	ctx = log.WithContext(ctx)

	us := make([]*Updater, len(f.Years))
	ch := make(chan int, len(f.Years))
	var wg sync.WaitGroup
	for i, lim := 0, runtime.NumCPU(); i < lim; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := ctx.Done()
			for i := range ch {
				select {
				case <-done:
					return
				default:
				}
				log := log.With().
					Str("year", string(us[i].year)).
					Logger()
				req, err := http.NewRequestWithContext(ctx, http.MethodHead, us[i].url, nil)
				if err != nil {
					log.Warn().Err(err).Msg("unable to create request")
					us[i] = nil
					return
				}
				res, err := http.DefaultClient.Do(req)
				if res != nil {
					res.Body.Close()
				}
				if err != nil || res.StatusCode != http.StatusOK {
					ev := log.Info()
					if err != nil {
						ev = ev.Err(err)
					} else {
						ev = ev.Int("status_code", res.StatusCode)
					}
					ev.Msg("ignoring release")
					us[i] = nil
				}
			}
		}()
	}

	for i, r := range f.Releases {
		us[i] = NewUpdater(r)
		ch <- i
	}
	close(ch)
	wg.Wait()

	set := driver.NewUpdaterSet()
	if err := ctx.Err(); err != nil {
		return set, err
	}
	for _, u := range us {
		if u == nil {
			continue
		}
		if err := set.Add(u); err != nil {
			return set, err
		}
	}
	return set, nil
}