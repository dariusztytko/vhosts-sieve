# VHosts Sieve
Searching for virtual hosts among non-resolvable domains.

## Installation
```
git clone https://github.com/dariusztytko/vhosts-sieve.git
pip3 install -r vhosts-sieve/requirements.txt
```

## Usage
Get a list of subdomains (e.g. using [Amass](https://github.com/OWASP/Amass))
```
$ amass enum -v -passive -o domains.txt -d example.com -d example-related.com
```
Use vhosts-sieve.py to find virtual hosts
```
$ python3 vhosts-sieve.py -d domains.txt -o vhosts.txt
Max domains to resolve: -1
Max IPs to scan: -1
Max vhost candidates to check: -1
Ports to scan: [80, 443, 8000, 8008, 8080, 8443]
Threads number: 16
Timeout HTTP: 5.0s
Timeout TCP: 3.0s
Verbose: False
User agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0

Resolving 12 domains...

Scanning 1 IPs...

Finding vhosts (active IPs: 1, vhost candidates: 7)...

Saved results (4 vhosts)
```
Output file contains discovered virtual hosts in the following format
```
165.22.264.81 80 http False zxcv.example.com 301
165.22.264.81 443 https False zxcv.example.com 200 dev.example.com 200 admin.exmaple.com 401
```
Each line contains the following information:
* IP address
* Port number
* Detected protocol (HTTP or HTTPS)
* "Stopped" flag (please see [How it works](#how-it-works))
* List of discovered virtual hosts (with the response status code)

## How it works
To discover virtual hosts, the following steps are performed:
1. Domains from the input file are resolved to IP addresses (IPv4)
1. Depending on the resolving result, domains are divided into two groups:
    * Resolved domains
    * Non-resolved domains (**virtual host candidates**)
1. IP addresses of the resolved domains are scanned for the web ports (default: 80, 443, 8000, 8080, 8443)
1. Virtual host candidates are validated on each open port

### Virtual host candidates validation
Virtual host candidates validation is performed as follow:
1. Request with the random (invalid) virtual host (Host header) is sent
1. Response is saved as a reference
1. Responses for virtual host candidates are compared to the reference response
    * If the response is "similar", virtual host candidate is skipped
    * Otherwise (response is not "similar"), virtual host candidate is marked as a valid virtual host
1. To increase chance of success, the following extra headers are sent:
    * X-Forwarded-For: 127.0.0.1
    * X-Originating-IP: [127.0.0.1]
    * X-Remote-IP: 127.0.0.1
    * X-Remote-Addr: 127.0.0.1
1. Additionally, if too many valid virtual hosts are discovered (e.g. any subdomain is valid), validation is stopped and the result is marked as "Stopped"

Please notice that response status code is not taken into consideration. The main assumption is that everything other than reference response is worth to analyse in details. Even 4xx and 5xx responses.

### SNI
For the HTTPS protocol, it may be useful to send virtual host candidate name via Host header and SNI (TLS extension).
Use *--enable-sni* option to enable SNI support.
It is recommended to make a scan twice (with SNI enabled and without it) to get more relevant results.

## Optimization
For the large networks with thousands subdomains, it may take many hours to check all virtual host candidates. The following options can be used to speed up the process:
* Default scanned ports 80, 443, 8000, 8080, 8443 can be limited, e.g. to 443 only (-p, --ports-to-scan)
* Number of the threads can be increased (-t, --threads-number)
* Number of the domains to resolve can be limited (--max-domains)
* Number of the IP addresses to scan can be limited (--max-ips)
* Number of the virtual host candidates to check can be limited (--max-vhost-candidates)
* Timeouts can be reduced (--timeout-tcp, --timeout-http)

Additionally, it is recommended to use -v (verbosity) option to see the results continuously.

## Changes
Please see the [CHANGELOG](CHANGELOG)
