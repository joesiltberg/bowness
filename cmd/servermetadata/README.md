# servermetadata

A command line tool for generating Federated TLS server metadata.

## Overview

`servermetadata` generates metadata JSON according to the Federated TLS Authentication specification. The output can be submitted to a federation operator for inclusion in the federation's metadata.

## Building

```
cd cmd/servermetadata
go build
```

## Usage

```
servermetadata [options]
```

### Required Options

| Option | Description |
|--------|-------------|
| `-organization` | Your organization's name |
| `-organization-id` | Your organization's identifier |
| `-entity-id` | Unique identifier for this server entity |
| `-base-uri` | The base URI where your server is accessible |
| `-cert` | Path to server certificate (PEM format) |

### Optional Options

| Option | Description |
|--------|-------------|
| `-description` | Human-readable description of the server |
| `-issuer` | Path to issuer certificate (PEM format). Can be specified multiple times for certificate chains. |
| `-tag` | Tag for the server. Can be specified multiple times. |

## Examples

### Using a CA-issued certificate

When using a certificate issued by a Certificate Authority, specify the server certificate with `-cert` and the issuer certificate(s) with `-issuer`:

```
servermetadata \
  -organization "Example Organization" \
  -organization-id "SE2233445566" \
  -entity-id "https://api.example.org" \
  -base-uri "https://api.example.org/v1" \
  -cert server.pem \
  -issuer intermediate-ca.pem \
  -issuer root-ca.pem \
  -description "Example API Server" \
  -tag "apiv1"
```

### Using a self-signed certificate

When using a self-signed certificate, the same certificate serves as both the server certificate and the issuer. Specify it twice:

```
servermetadata \
  -organization "Example Organization" \
  -organization-id "SE2233445566" \
  -entity-id "https://api.example.org" \
  -base-uri "https://api.example.org/v1" \
  -cert selfsigned.pem \
  -issuer selfsigned.pem \
  -description "Example API Server" \
  -tag "apiv1"
```

## Output

The tool writes the generated metadata JSON to standard output. You can redirect it to a file:

```
servermetadata [options] > metadata.json
```

The output follows the Federated TLS metadata format and includes:

- Server information (base URI, description, tags)
- Public key pin (SHA-256 hash of the server certificate's public key)
- Issuer certificates
- Organization details
