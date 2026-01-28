/*
 * Copyright (c) 2026 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/joesiltberg/bowness/fedtls"
)

const defaultCacheTTL = 3600

func main() {
	keysPath := flag.String("keys", "", "path to jwks file (required)")
	urlStr := flag.String("url", "", "URL for signed metadata to download and verify (required)")
	outputPath := flag.String("output", "", "path to file where the verified payload should be written (required)")
	cachedPath := flag.String("cached", "", "path to previously downloaded and verified payload (optional)")
	inferAlg := flag.Bool("inferalg", false, "infer algorithm from key type if key is missing alg property (optional)")

	flag.Parse()

	if *keysPath == "" || *urlStr == "" || *outputPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Check if we can use the cached file
	if *cachedPath != "" {
		if useCached(*cachedPath, *outputPath) {
			return
		}
	}

	// Download and verify metadata
	if err := downloadAndVerify(*keysPath, *urlStr, *outputPath, *inferAlg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// useCached checks if the cached file exists and is still valid.
// If so, it copies it to the output path and returns true.
// If output and cached point to the same file, no copy is performed.
func useCached(cachedPath, outputPath string) bool {
	cachedInfo, err := os.Stat(cachedPath)
	if err != nil {
		return false
	}

	data, err := os.ReadFile(cachedPath)
	if err != nil {
		return false
	}

	cacheTTL := getCacheTTL(data)
	expirationTime := cachedInfo.ModTime().Add(time.Duration(cacheTTL) * time.Second)

	if time.Now().After(expirationTime) {
		return false
	}

	// Check if output and cached are the same file to avoid updating mtime
	outputInfo, err := os.Stat(outputPath)
	if err == nil && os.SameFile(cachedInfo, outputInfo) {
		return true
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return false
	}

	return true
}

// getCacheTTL extracts the cache_ttl from the JSON data, or returns the default.
func getCacheTTL(data []byte) int {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return defaultCacheTTL
	}

	if ttl, ok := obj["cache_ttl"]; ok {
		switch v := ttl.(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
	}

	return defaultCacheTTL
}

// downloadAndVerify downloads the signed metadata, verifies it, and writes the payload to output.
func downloadAndVerify(keysPath, urlStr, outputPath string, inferAlg bool) error {
	jwks, err := os.ReadFile(keysPath)
	if err != nil {
		return fmt.Errorf("failed to read JWKS file: %w", err)
	}

	resp, err := http.Get(urlStr)
	if err != nil {
		return fmt.Errorf("failed to download metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	signed, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	payload, err := fedtls.VerifyRaw(signed, jwks, fedtls.WithInferAlgorithm(inferAlg))
	if err != nil {
		return fmt.Errorf("failed to verify metadata: %w", err)
	}

	if err := os.WriteFile(outputPath, payload, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}
