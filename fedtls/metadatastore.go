/*
 * Copyright (c) 2020-2025 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package fedtls

import (
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joesiltberg/bowness/util"
)

// IssuersPerEntity is a map of certificate issuers, ordered by entity ID
type IssuersPerEntity map[string][]Issuer

// A MetadataStore regularly downloads, verifies and parses the metadata from
// a federation.
type MetadataStore struct {
	quit        chan int
	addListener chan chan int

	// This is the in-memory, latest verified metadata. It should never be nil,
	// but it can be a pointer to a default constructed Metadata (which has
	// no entries). This is the case before we've managed to read, verify and
	// parse the metadata, or if we fail to do so.
	parsed *Metadata

	// This mutex protects the parsed pointer
	lock sync.Mutex
}

// MetadataStoreOptions are configuration options for the metadata store
type MetadataStoreOptions struct {
	// Used when the metadata doesn't have a CacheTTL attribute
	DefaultCacheTTL time.Duration

	// Used when we fail to get the jws from the federation's web server
	NetworkRetry time.Duration

	// Used when the verification fails or we can't parse the metadata
	BadContentRetry time.Duration

	// Timeout for HTTP requests when fetching metadata
	FetchTimeout time.Duration

	// Maximum size in bytes of a metadata response body
	MaxMetadataSize int64
}

// An OptionSetter is a function for modifying the metadata store options
type OptionSetter func(*MetadataStoreOptions)

// DefaultCacheTTL creates an OptionSetter for setting the default cache TTL
func DefaultCacheTTL(duration time.Duration) OptionSetter {
	return func(options *MetadataStoreOptions) {
		options.DefaultCacheTTL = duration
	}
}

// NetworkRetry creates an OptionSetter for setting the network retry
func NetworkRetry(duration time.Duration) OptionSetter {
	return func(options *MetadataStoreOptions) {
		options.NetworkRetry = duration
	}
}

// BadContentRetry creates an OptionSetter for setting the bad content retry
func BadContentRetry(duration time.Duration) OptionSetter {
	return func(options *MetadataStoreOptions) {
		options.BadContentRetry = duration
	}
}

// FetchTimeout creates an OptionSetter for setting the HTTP request timeout
func FetchTimeout(duration time.Duration) OptionSetter {
	return func(options *MetadataStoreOptions) {
		options.FetchTimeout = duration
	}
}

// MaxMetadataSize creates an OptionSetter for setting the maximum metadata response size in bytes
func MaxMetadataSize(size int64) OptionSetter {
	return func(options *MetadataStoreOptions) {
		options.MaxMetadataSize = size
	}
}

// NewMetadataStore constructs a new MetadataStore and starts its goroutine
func NewMetadataStore(url, jwksPath, cachedPath string, setters ...OptionSetter) *MetadataStore {
	ms := MetadataStore{
		quit:        make(chan int),
		addListener: make(chan chan int),
		parsed:      &Metadata{},
	}

	options := &MetadataStoreOptions{
		DefaultCacheTTL: 3600 * time.Second,
		NetworkRetry:    1 * time.Minute,
		BadContentRetry: 1 * time.Hour,
		FetchTimeout:    30 * time.Second,
		MaxMetadataSize: 50 * 1024 * 1024, // 50 MiB
	}

	for _, setter := range setters {
		setter(options)
	}

	go metadataFetcher(url, jwksPath, cachedPath, options, &ms)
	return &ms
}

// Quit tells the MetadataStore's goroutine to quit and waits until it's done
func (mdstore *MetadataStore) Quit() {
	mdstore.quit <- 0
	<-mdstore.quit
}

func (mdstore *MetadataStore) getParsed() *Metadata {
	mdstore.lock.Lock()
	defer mdstore.lock.Unlock()
	return mdstore.parsed
}

func (mdstore *MetadataStore) setNewParsed(newParsed *Metadata) {
	mdstore.lock.Lock()
	defer mdstore.lock.Unlock()
	mdstore.parsed = newParsed
}

func (mdstore *MetadataStore) AddChangeListener(listener chan int) {
	mdstore.addListener <- listener
}

func (mdstore *MetadataStore) GetIssuerCertificates() IssuersPerEntity {
	return issuersPerEntity(mdstore.getParsed())
}

// GetMetadata returns the current parsed metadata.
// The returned pointer should be treated as read-only.
func (mdstore *MetadataStore) GetMetadata() *Metadata {
	return mdstore.getParsed()
}

func durationToRefresh(lastFetch time.Time, cacheTTL time.Duration) time.Duration {
	if lastFetch.After(time.Now()) {
		// Shouldn't really happen, but could happen e.g. if the cache file's
		// modification time is in the future
		lastFetch = time.Now()
	}

	timeToRefresh := lastFetch.Add(cacheTTL)

	now := time.Now()

	if timeToRefresh.Before(now) {
		return 0
	}
	return timeToRefresh.Sub(now)
}

// The result of an async HTTP GET (see fetch())
type fetchResult struct {
	body []byte
	err  error
}

// An async HTTP GET, sends its result to a channel
func fetch(url string, client *http.Client, maxSize int64, fetched chan<- fetchResult) {
	log.Printf("Fetching new metadata from %s", url)
	go func() {
		response, err := client.Get(url)

		if err != nil {
			fetched <- fetchResult{nil, err}
		} else {
			body, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
			//nolint:errcheck
			response.Body.Close()
			if err != nil {
				fetched <- fetchResult{nil, err}
			} else if int64(len(body)) > maxSize {
				fetched <- fetchResult{nil, fmt.Errorf("metadata response exceeds maximum size (%d bytes)", maxSize)}
			} else {
				fetched <- fetchResult{body, nil}
			}
		}
	}()
}

// Gives a files modification time, or now if we fail to stat the file
func fileModTimeOrNow(path string) time.Time {
	file, err := os.Stat(path)

	if err != nil {
		return time.Now()
	}

	return file.ModTime()
}

func cacheTTL(metadataTTL, defaultTTL time.Duration) time.Duration {
	if metadataTTL != 0 {
		return metadataTTL
	}
	return defaultTTL
}

func issuersPerEntity(metadata *Metadata) IssuersPerEntity {
	result := make(IssuersPerEntity)

	for _, entity := range metadata.Entities {
		issuers := make([]Issuer, len(entity.Issuers))
		copy(issuers, entity.Issuers)
		result[entity.EntityID] = issuers
	}

	return result
}

// LookupClient finds an entity with a client that has a pin that matches the peer's leaf certificate
// Returns the entity id and if available also the organization and organization id
func (mdstore *MetadataStore) LookupClient(verifiedChains [][]*x509.Certificate) (string, *string, *string, error) {
	fingerprint := util.Fingerprint(verifiedChains[0][0])
	parsed := mdstore.getParsed()

	for i := range parsed.Entities {
		entity := parsed.Entities[i].EntityID
		for c := range parsed.Entities[i].Clients {
			for _, pin := range parsed.Entities[i].Clients[c].Pins {
				if pin.Digest == fingerprint {
					return entity, parsed.Entities[i].Organization, parsed.Entities[i].OrganizationID, nil
				}
			}
		}
	}
	return "", nil, nil, fmt.Errorf("failed to find client pin (%s) in metadata", fingerprint)
}

// This function is the actual metadata store. It runs in a goroutine and
// contains a parsed in-memory copy of the latest verified metadata.
// If possible it will read from the cached file at start up, otherwise it will
// fetch from the federation's URL. It will regularly fetch new versions from
// the federation URL as often as the cache TTL indicates in the latest
// metadata.
func metadataFetcher(
	url, jwksPath, cachedPath string,
	options *MetadataStoreOptions,
	mdstore *MetadataStore) {

	listeners := make([]chan int, 0)

	notifyAll := func() {
		for _, listener := range listeners {
			listener <- 0
		}
	}

	jwks, err := os.ReadFile(jwksPath)

	if err != nil {
		log.Fatalf("Failed to read from JWKS file (%s): %v", jwksPath, err)
	}

	workingCache := false

	content, err := os.ReadFile(cachedPath)

	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to read from metadata cache file (%s): %v", cachedPath, err)
	}

	if err == nil {
		metadata, err := Verify(content, jwks)

		if err != nil {
			log.Printf("Failed to verify cached file: %v", err)
		} else {
			workingCache = true
			mdstore.setNewParsed(metadata)
			notifyAll()
		}
	}

	retry := time.After(0) // When to do the next fetch
	if workingCache {
		parsed := mdstore.getParsed()
		duration := durationToRefresh(fileModTimeOrNow(cachedPath),
			cacheTTL(time.Duration(parsed.CacheTTL)*time.Second, options.DefaultCacheTTL))
		retry = time.After(duration)
	}

	fetched := make(chan fetchResult)

	client := &http.Client{
		Timeout: options.FetchTimeout,
	}

	for {
		select {
		case <-mdstore.quit:
			mdstore.quit <- 0
			return
		case newListener := <-mdstore.addListener:
			listeners = append(listeners, newListener)
		case fetchResult := <-fetched:
			if fetchResult.err != nil {
				log.Printf("Failed to get metadata from federation operator: %v", fetchResult.err)
				retry = time.After(options.NetworkRetry)
				continue
			}
			newParsed, err := Verify(fetchResult.body, jwks)

			if err != nil {
				log.Printf("Failed to verify metadata: %v", err)
				retry = time.After(options.BadContentRetry)
			} else {
				log.Println("Successfully downloaded and verified new metadata")
				mdstore.setNewParsed(newParsed)
				notifyAll()
				retry = time.After(durationToRefresh(time.Now(),
					cacheTTL(time.Duration(newParsed.CacheTTL)*time.Second, options.DefaultCacheTTL)))
				err := os.WriteFile(cachedPath, fetchResult.body, 0600)
				if err != nil {
					log.Printf("Failed to write to cache file (%s): %v", cachedPath, err)
				}
			}
		case <-retry:
			fetch(url, client, options.MaxMetadataSize, fetched)
		}
	}
}
