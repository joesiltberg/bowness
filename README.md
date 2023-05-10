# Bowness (Federated TLS Authentication in Go)

Bowness is an implementation of 
[Federated TLS Authentication](https://github.com/dotse/tls-fed-auth) in Go.

It can be used as a stand-alone reverse proxy, or as Go authentication 
middleware for servers implemented in Go.

## Why use it?

### Open source
Bowness is free and open source software using the MIT license.

### Simple to use
Bowness is easy to build and deploy. It takes care of regularly downloading
and verifying metadata from the federation operator, as well as acting
as an authentication reverse proxy in front of your backend.

You can also use it as a Go authentication middleware if your backend
is implemented in Go.

### Hot-swapping of client certificates
When new metadata is published by the federation operator the new set of
client certificates are loaded without any need for restarting the 
service.

### Rate limiting based on entity id
If you wish to enforce rate limiting, it can be done based on entity id
rather than IP. This means a single client machine representing multiple 
organizations will be allowed to perform more requests.

## Reverse proxy
By deploying Bowness as a reverse proxy infront of your backend you let
Bowness handle the authentication while your backend simply reads the
authenticated client's information from HTTP headers.

The reverse proxy will regularly download and verify the metadata from
the federation operator. As new clients are added to the metadata the
proxy's CA store will be hot-swapped, there is no need for downtime
in order to load new metadata.

The following headers will be added by the reverse proxy:

 * X-Fedtlsauth-Entity-Id
 * X-Fedtlsauth-Organization (if available in the metadata)
 * X-Fedtlsauth-Organization-Id (if available in the metadata)
 * X-Forwarded-For (ip of the client)

You can also configure an API key which the reverse proxy will
add as a header when making requests to your backend.

### Building
After installing the Go toolchain, go to the directory `cmd/bowness` and
run `go build`. This should give you an executable (`bowness`).

### Configuring and running
Bowness reads its configuration from a YAML file, which could look like this:

```
MetadataURL: https://md.swefed.se/kontosynk/kontosynk-prod-1.jws
JWKSPath: /path/to/kontosynk/jwks
CachePath: /path/to/kontosynk/metadata-cache.json
Cert: /etc/ssl/cert.pem
Key: /etc/ssl/key.pem
TargetURL: http://backend:8000
ListenAddress: :443
```

The settings are hopefully self explanatory. The TargetURL is the URL of the
backend, ListenAddress is a TCP network address which the reverse proxy should
listen to.

### Advanced settings
If you wish to enforce rate limiting, you can add the following to your configuration:

```
EnableLimiting: true
LimitRequestsPerSecond: 10
LimitBurst: 20
```
This gives every entity id bursts of up to 20 requests without limit. After the burst, 10 
requests per second will be allowed.

You may also wish to configure timeouts to protect your servers from too much load:

```
ReadHeaderTimeout: 5
ReadTimeout: 20
WriteTimeout: 40
IdleTimeout: 60
BackendTimeout: 30
```
The first four timeouts handle the relationship between Bowness and the client,
for instance if the HTTP headers haven't been read completely after 5 seconds the 
connection is closed.

The last timeout is the number of seconds Bowness will wait for the backend to
respond to a request before giving up.

If you wish to, you can also configure how often to download new metadata
from the federation operator, although you can probably use the defaults:

```
DefaultCacheTTL: 3600
NetworkRetry: 60
BadContentRetry: 3600
```

`DefaultCacheTTL` is only used if the federation metadata doesn't specify a
cache TTL. Otherwise we will download as often as the metadata suggests.

`NetworkRetry` determines how often we re-try a download if the download itself
fails (typically due to network error).

`BadContentRetry` determines how often we re-try when there's a problem
verifying or parsing the metadata.

If you want to use an API key when making requests to the backend:

```
APIKeyHeader: X-API-Key
APIKeyValue: yourverysecretkeygoeshere
```

## Go middleware
If you're developing your backend in Go the authentication middleware
can be used directly by your code if you prefer. See the example
in the [examples/middleware](examples/middleware) directory.

## Docker
[`Dockerfile`](Dockerfile) is a two-stage Docker Build file that can build a
Bowness image. The image can be built like so:

```
$ cd bowness
$ sudo docker build -t bowness .
```

Once the image has been built, it can be used to create a container which runs
Bowness inside Docker. Here's an example using the `docker` CLI:

```
$ sudo docker run \
  --name=bowness \
  -p 8443:8443 \
  --rm \
  -v ".../config.yaml:/app/config.yaml:ro" \
  -v ".../jwks.trial:/app/jwks.trial:ro" \
  -v ".../metadata-cache.json:/app/metadata-cache.json" \
  -v ".../cert.pem:/app/cert.pem:ro" \
  -v ".../key.pem:/app/key.pem:ro" \
  bowness
```

Bowness assumes `config.yaml` is located in `/app` inside the container.
