# Containerized SOCKS5 Proxy Server
## How do I use it?
### Getting the image
You can either pull it from GitHub Container Registry or build it yourself.

To pull it from GitHub Container Registry, run
```
docker pull ghcr.io/wfg/socks5-server
```

To build it yourself, run
```
docker build -t ghcr.io/wfg/socks5-server https://github.com/wfg/docker-socks5-server.git#:build
```

### Creating and running a container
By default, the image listens on 0.0.0.0:1080 with no authentication.
This is configurable today if you pass in the appropriate flags.
More documentation is coming soon (hopefully).

#### `docker run`
```
docker run --detach \
  --name=socks5-server \
  ghcr.io/wfg/socks5-server
```

#### `docker-compose`
```yaml
services:
  socks5-server:
    image: ghcr.io/wfg/socks5-server
    container_name: socks5-server
    restart: unless-stopped
```
