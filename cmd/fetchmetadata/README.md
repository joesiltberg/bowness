# fetchmetadata

A command-line tool for downloading and verifying signed FedTLS metadata.

## Usage

```
fetchmetadata -keys <jwks-file> -url <metadata-url> -output <output-file> [options]
```

## Required Parameters

| Parameter | Description |
|-----------|-------------|
| `-keys`   | Path to the JWKS file containing trusted signing keys |
| `-url`    | URL of the signed metadata to download |
| `-output` | Path where the verified payload will be written |

## Optional Parameters

| Parameter   | Description |
|-------------|-------------|
| `-cached`   | Path to a previously downloaded and verified payload for caching |
| `-inferalg` | Infer signature algorithm from key type if the key is missing the `alg` property |
| `-timeout`  | HTTP request timeout in seconds (default: 30) |

## Caching

The `-cached` parameter enables caching to avoid unnecessary downloads. When provided:

1. If the cached file exists and is still valid, it will be copied to the output path
2. If the cached file is missing or expired, a fresh download and verification is performed

Cache validity is determined by the file's modification time and the `cache_ttl` attribute in the metadata. If `cache_ttl` is not present in the metadata, a default of 3600 seconds (1 hour) is used.

**Tip:** If `-cached` and `-output` point to the same file, the file will not be rewritten when the cache is valid, preserving its modification timestamp.

## Algorithm Inference

By default, each key in the JWKS must have an `alg` property specifying the signature algorithm. If your JWKS lacks this property, use `-inferalg` to let the tool infer compatible algorithms based on the key type.

## HTTP Timeout

The `-timeout` parameter controls how long the tool will wait for the HTTP request to complete when downloading metadata. The default is 30 seconds.

The timeout must be a positive integer value in seconds.

## Examples

Basic usage:

```
fetchmetadata -keys federation.jwks -url https://md.example.org/metadata.jws -output metadata.json
```

With caching (separate cache and output files):

```
fetchmetadata -keys federation.jwks -url https://md.example.org/metadata.jws -output metadata.json -cached cache/metadata.json
```

With caching (same file for cache and output):

```
fetchmetadata -keys federation.jwks -url https://md.example.org/metadata.jws -output metadata.json -cached metadata.json
```

With algorithm inference:

```
fetchmetadata -keys federation.jwks -url https://md.example.org/metadata.jws -output metadata.json -inferalg
```

With custom timeout (60 seconds):

```
fetchmetadata -keys federation.jwks -url https://md.example.org/metadata.jws -output metadata.json -timeout 60
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Error (missing parameters, download failure, verification failure, etc.) |
