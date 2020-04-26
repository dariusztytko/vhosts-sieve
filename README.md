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
Use vhost-sieve.py to find vhosts
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
Output file contains discovered vhosts in the following format
```
165.22.264.81 80 http False zxcv.example.com 301
165.22.264.81 443 https False zxcv.example.com 200 dev.example.com 200 admin.exmaple.com 401
```
Each line contains the following information:
* IP address
* Port number
* Detected protocol (HTTP or HTTPS)
* Stopped flag (please see [How it works](#how-it-works))
* List of discovered vhosts (with response status code)

## How it works
The following steps are performed to discover vhosts:
1. Domains from the input file are resolved to IP addresses (IPv4)
1. Depending on the resolving result, domains are divided into two groups:
    * Resolved domains
    * Non-resolved domains (**vhost candidates**)
1. IP addresses of the resolved domains are scanned for the common web ports (default: 80, 443, 8000, 8080, 8443)
1. Vhost candidates are validated on each open port

### Vhost candidates validation
Vhost candidates validation is performed as follow:
1. Request with the random vhost (Host header) is sent
2. Response is saved as a reference
3. Responses for vhost candidates are compared to the reference response
    * If the response is "similar", vhost candidate is skipped
    * Otherwise (response is not "similar"), vhost candidate is marked as a valid vhost
4. Additionally, if too many valid vhosts are discovered (e.g. any subdomain is valid), validation is stopped and the result is marked as "Stopped"

## Optimization
For the large networks with thousands subdomains, it may take many hours to check all vhost candidates. The following options can be used to speed up the process:
* Default scanned ports 80, 443, 8000, 8080, 8443 can be reduced, e.g. to 443 only (-p, --ports-to-scan)
* Number of the threads can be increased (-t, --threads-number)
* Number of the domains to resolve can be limited (--max-domains)
* Number of the IP addresses to scan can be limited (--max-ips)
* Number of the vhost candidates to check can be limited (--max-vhost-candidates) 
* Timeouts can be reduced (--timeout-tcp, --timeout-http)

Additionally, it is recommended to use -v (verbosity) option to see the results continuously.

## Changes
Please see the [CHANGELOG](CHANGELOG)
