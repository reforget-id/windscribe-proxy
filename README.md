windscribe-proxy
================

Standalone Windscribe proxy client. Younger brother of [opera-proxy](https://github.com/Snawoot/opera-proxy/).

Just run it and it'll start a plain HTTP proxy server forwarding traffic through Windscribe proxies of your choice.
By default the application listens on 127.0.0.1:28080.

## Features

* Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
* Uses TLS for secure communication with upstream proxies
* DNS tunneling through Windscribe servers (queries appear from server location)
* Auto-detection of Windows DNS configuration (including DoH)
* Support for custom DoH upstream resolvers
* Zero configuration
* Simple and straightforward

## Installation

#### Binaries

Pre-built binaries are available [here](https://github.com/Snawoot/windscribe-proxy/releases/latest).

#### Build from source

Alternatively, you may install windscribe-proxy from source. Run the following within the source directory:

```
make install
```

#### Docker

A docker image is available as well. Here is an example of running windscribe-proxy as a background service:

```sh
docker run -d \
    --security-opt no-new-privileges \
    -p 127.0.0.1:28080:28080 \
    --restart unless-stopped \
    --name windscribe-proxy \
    yarmak/windscribe-proxy
```

## Usage

List available locations:

```
windscribe-proxy -list-locations
```

Run proxy via location of your choice:

```
windscribe-proxy -location Germany/Frankfurt
```

Also it is possible to export proxy addresses and credentials:

```
windscribe-proxy -list-proxies
```

### DNS Tunneling

By default, windscribe-proxy routes all DNS queries through the Windscribe tunnel, making DNS requests appear to originate from the Windscribe server location rather than your local IP address. This enhances privacy and allows integration with DNS-based filtering services like NextDNS.

**Auto-detection mode** (default on Windows):
```
windscribe-proxy -location Germany/Frankfurt
```
This will automatically detect your Windows DNS configuration, including DoH endpoints, and route queries through the tunnel.

**Custom DoH upstream**:
```
windscribe-proxy -location Germany/Frankfurt -resolver https://dns.nextdns.io/abc123
```
This routes DNS queries through the specified DoH provider via the Windscribe tunnel.

**How it works**:
1. DNS queries are intercepted and sent through the Windscribe VPN tunnel
2. The Windscribe server forwards queries to the configured upstream resolver (auto-detected or specified via `-resolver`)
3. DNS responses appear to come from the Windscribe server location
4. If DoH upstream fails, automatically falls back to TCP DNS (Google DNS, Cloudflare DNS, Quad9)

## List of arguments

| Argument | Type | Description |
| -------- | ---- | ----------- |
| 2fa | String | 2FA code for login |
| auth-secret | String | client auth secret (default `952b4412f002315aa50751032fcaab03`) |
| bind-address | String | HTTP proxy listen address (default `127.0.0.1:28080`) |
| cafile | String | use custom CA certificate bundle file |
| fake-sni | String | fake SNI to use to contact windscribe servers (default "com") |
| force-cold-init | - | force cold init |
| init-retries | Number | number of attempts for initialization steps, zero for unlimited retry |
| init-retry-interval | Duration | delay between initialization retries (default 5s) |
| list-locations | - | list available locations and exit |
| list-proxies | - | output proxy list and exit |
| location | String | desired proxy location. Default: best location |
| password | String | password for login |
| proxy | String | sets base proxy to use for all dial-outs. Format: `<http\|https\|socks5\|socks5h>://[login:password@]host[:port]` Examples: `http://user:password@192.168.1.1:3128`, `socks5://10.0.0.1:1080` |
| resolver | String | DoH upstream resolver to use via Windscribe tunnel. If not specified, auto-detects Windows DNS configuration. DNS queries will be sent from Windscribe server location. Examples: `https://dns.nextdns.io/abc123`, `https://1.1.1.1/dns-query` |
| state-file | String | file name used to persist Windscribe API client state. Default: `wndstate.json` |
| timeout | Duration | timeout for network operations. Default: `10s` |
| username | String | username for login |
| verbosity | Number | logging verbosity (10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical). Default: `20` |
| version | - | show program version and exit |

## See also

* [Project wiki](https://github.com/Snawoot/windscribe-proxy/wiki)
* [Community in Telegram](https://t.me/alternative_proxy)
