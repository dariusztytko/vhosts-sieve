#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from concurrent.futures import ThreadPoolExecutor
from difflib import SequenceMatcher
from threading import Lock
from urllib.parse import urlparse

import argparse
import datetime
import dns.resolver
import ipaddress
import random
import requests.packages.urllib3
import socket
import string
import sys
import time

VERSION = '1.0'

# # # # # # # # # # #
# global options
# # # # # # # # # # #
options = {}


# # # # # # # # # # #
# helpers
# # # # # # # # # # #

def filter_not_none(iterable):
    return list(filter(lambda x: x is not None, iterable))


def get_random_items(values, length):
    if length == -1:
        length = len(values)
    return random.sample(values, length)


def get_unique_list(values):
    return list(set(values))


# # # # # # # # # # #
# core classes
# # # # # # # # # # #

class ArgsParser(object):
    _DEFAULT_MAX_DOMAINS = -1
    _DEFAULT_MAX_IPS = -1
    _DEFAULT_MAX_VHOST_CANDIDATES = -1
    _DEFAULT_PORTS = '80,443,8000,8008,8080,8443'
    _DEFAULT_THREADS_NUMBER = 16
    _DEFAULT_TIMEOUT_HTTP = 5.0
    _DEFAULT_TIMEOUT_TCP = 3.0
    _DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0'

    @staticmethod
    def parse():
        parser = argparse.ArgumentParser(
            description='Searching for virtual hosts among non-resolvable domains (version: %s)' % VERSION
        )
        parser.add_argument(
            '-v', '--verbose',
            help='show detailed messages',
            action='store_true',
        )
        parser.add_argument(
            '--max-domains',
            help='number of randomly selected domains to resolve, default: %d (all)' % ArgsParser._DEFAULT_MAX_DOMAINS,
            type=ArgsParser._check_int_gt_0,
            default=ArgsParser._DEFAULT_MAX_DOMAINS,
        )
        parser.add_argument(
            '--max-ips',
            help='number of randomly selected IPs to scan, default: %d (all)' % ArgsParser._DEFAULT_MAX_IPS,
            type=ArgsParser._check_int_gt_0,
            default=ArgsParser._DEFAULT_MAX_IPS,
        )
        parser.add_argument(
            '--max-vhost-candidates',
            help='number of randomly selected vhost candidates to check, default: %d (all)'
                 % ArgsParser._DEFAULT_MAX_VHOST_CANDIDATES,
            type=ArgsParser._check_int_gt_0,
            default=ArgsParser._DEFAULT_MAX_VHOST_CANDIDATES,
        )
        parser.add_argument(
            '-p', '--ports-to-scan',
            help='default: %s' % ArgsParser._DEFAULT_PORTS,
            type=ArgsParser._check_ports,
            default=ArgsParser._DEFAULT_PORTS,
        )
        parser.add_argument(
            '-t', '--threads-number',
            help='default: %d' % ArgsParser._DEFAULT_THREADS_NUMBER,
            type=ArgsParser._check_int_gt_0,
            default=ArgsParser._DEFAULT_THREADS_NUMBER,
        )
        parser.add_argument(
            '--timeout-tcp',
            help='TCP connections (port scanning) timeout, default: %.1fs' % ArgsParser._DEFAULT_TIMEOUT_TCP,
            type=ArgsParser._check_float_gt_0,
            default=ArgsParser._DEFAULT_TIMEOUT_TCP,
        )
        parser.add_argument(
            '--timeout-http',
            help='HTTP requests timeout, default: %.1fs' % ArgsParser._DEFAULT_TIMEOUT_HTTP,
            type=ArgsParser._check_float_gt_0,
            default=ArgsParser._DEFAULT_TIMEOUT_HTTP,
        )
        parser.add_argument(
            '-u', '--user-agent',
            help='default: %s' % ArgsParser._DEFAULT_USER_AGENT,
            default=ArgsParser._DEFAULT_USER_AGENT,
        )
        parser.add_argument(
            '-d', '--domains-file',
            help='read domains from file',
            type=argparse.FileType('r'),
            required=True,
        )
        parser.add_argument(
            '-o', '--output-file',
            help='save results to file',
            type=argparse.FileType('w'),
            required=True,
        )
        args = parser.parse_args(sys.argv[1:])
        return {
            'max_domains': args.max_domains,
            'max_ips': args.max_ips,
            'max_vhost_candidates': args.max_vhost_candidates,
            'domains_file': args.domains_file,
            'output_file': args.output_file,
            'ports': args.ports_to_scan,
            'threads_number': args.threads_number,
            'timeout_http': args.timeout_http,
            'timeout_tcp': args.timeout_tcp,
            'verbose': args.verbose,
            'user_agent': args.user_agent,
        }

    @staticmethod
    def _check_float_gt_0(value):
        try:
            float_value = float(value)
            if float_value <= 0:
                raise argparse.ArgumentTypeError('must be greater than zero')
            return float_value
        except ValueError:
            raise argparse.ArgumentTypeError('must be float')

    @staticmethod
    def _check_ports(value):
        try:
            ports = []
            for port in [int(port) for port in value.split(',')]:
                if port < 0 or port > 65535:
                    raise argparse.ArgumentTypeError('invalid port: %d' % port)
                ports.append(port)
            return sorted(get_unique_list(ports))
        except ValueError:
            raise argparse.ArgumentTypeError('invalid ports')

    @staticmethod
    def _check_int_gt_0(value):
        try:
            int_value = int(value)
            if int_value <= 0:
                raise argparse.ArgumentTypeError('must be greater than zero')
            return int_value
        except ValueError:
            raise argparse.ArgumentTypeError('must be integer')


class DomainsResolver(object):
    @staticmethod
    def get_args_list():
        domains = []
        for line in options['domains_file']:
            domain = line.strip()
            if domain:
                domains.append(domain)
        options['domains_file'].close()
        domains = get_random_items(get_unique_list(domains), options['max_domains'])
        return [(domain, ) for domain in domains]

    @staticmethod
    def run(args):
        return DomainsResolver(*args).get_result()

    @staticmethod
    def show_start_info(args_list):
        Logger.info('Resolving %d domains...' % len(args_list))

    @staticmethod
    def validate_results(resolved_domains):
        is_public_ip = False
        is_non_public_domain = False
        for resolved_domain in resolved_domains:
            if resolved_domain['ips']:
                is_public_ip = True
            else:
                is_non_public_domain = True
            if is_public_ip and is_non_public_domain:
                return True
        if not is_public_ip:
            Logger.error('No public IPs found')
        if not is_non_public_domain:
            Logger.error('No non-public domains found')
        return False

    def __init__(self, domain):
        self._domain = domain

    def get_result(self):
        ips = []
        try:
            for rr in dns.resolver.query(self._domain, 'A'):
                ip = str(rr)
                if not ipaddress.ip_address(ip).is_private:
                    ips.append(ip)
        except dns.exception.DNSException:
            pass
        ProgressTracker.instance().done()
        result = {
            'domain': self._domain,
            'ips': ips,
        }
        Logger.verbose(result)
        return result


class IpsScanner(object):
    @staticmethod
    def get_args_list(resolved_domains):
        ips = []
        for resolved_domain in resolved_domains:
            ips += resolved_domain['ips']
        ips = get_random_items(get_unique_list(ips), options['max_ips'])
        return [(ip, ) for ip in ips]

    @staticmethod
    def run(args):
        return IpsScanner(*args).get_result()

    @staticmethod
    def show_start_info(args_list):
        Logger.info('Scanning %d IPs...' % len(args_list))

    @staticmethod
    def validate_results(scanned_ips):
        if len(scanned_ips) > 0:
            return True
        Logger.error('No services found')
        return False

    def __init__(self, ip):
        self._ip = ip
        self._headers = {
            'User-Agent': options['user_agent'],
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close',
        }

    def get_result(self):
        services = []
        for port in options['ports']:
            scan_result = self._scan_port(port)
            if scan_result:
                services.append(scan_result)
        ProgressTracker.instance().done()
        if services:
            result = {
                'ip': self._ip,
                'services': services,
            }
            Logger.verbose(result)
            return result

    def _detect_scheme(self, port):
        schemes = ['http', 'https']
        if port in [443, 8443]:
            schemes = ['https', 'http']
        for scheme in schemes:
            try:
                url = '%s://%s:%d' % (scheme, self._ip, port)
                requests.get(
                    url,
                    headers=self._headers,
                    allow_redirects=False,
                    verify=False,
                    timeout=options['timeout_http']
                )
                return scheme
            except requests.exceptions.RequestException:
                pass

    def _scan_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(options['timeout_tcp'])
            s.connect((self._ip, port))
            scheme = self._detect_scheme(port)
            if scheme:
                return {
                    'port': port,
                    'scheme': scheme,
                }
        except socket.error:
            pass
        finally:
            s.close()


class Logger(object):
    @staticmethod
    def error(message):
        Logger._print_on_stderr(message)

    @staticmethod
    def info(message):
        print(message)

    @staticmethod
    def verbose(message):
        if options['verbose']:
            print(message)

    @staticmethod
    def _print_on_stderr(message):
        print(message, file=sys.stderr)


class Pool(object):
    @staticmethod
    def map(job_class, init_args):
        args_list = job_class.get_args_list(*init_args)
        ProgressTracker.instance().reset(len(args_list))
        Logger.info('')
        job_class.show_start_info(args_list)
        with ThreadPoolExecutor(options['threads_number']) as executor:
            results = filter_not_none(executor.map(job_class.run, args_list))
            if job_class.validate_results(results):
                return results


class ProgressTracker(object):
    _LOG_INFO_INTERVAL = 30

    _instance = None

    @staticmethod
    def instance():
        if not ProgressTracker._instance:
            ProgressTracker._instance = ProgressTracker()
        return ProgressTracker._instance

    def __init__(self):
        self._done_counter = 0
        self._last_log_info_timestamp = None
        self._lock = Lock()
        self._start_timestamp = None
        self._total = 0

    def done(self):
        with self._lock:
            now = int(time.time())
            if self._done_counter == 0:
                self._last_log_info_timestamp = now
                self._start_timestamp = now
            self._done_counter += 1
            if now - self._last_log_info_timestamp >= self._LOG_INFO_INTERVAL:
                Logger.info('Done %d of %d (Left time: %s)' % (
                    self._done_counter, self._total, self._get_left_time(now)
                ))
                self._last_log_info_timestamp = now

    def reset(self, total):
        self._done_counter = 0
        self._total = total

    def _get_left_time(self, now):
        elapsed_seconds = now - self._start_timestamp
        left_seconds = int(((self._total * elapsed_seconds) / self._done_counter) - elapsed_seconds)
        return str(datetime.timedelta(seconds=left_seconds))


class Results(object):
    @staticmethod
    def save(vhosts):
        vhosts_count = 0
        for ip_data in vhosts:
            ip = ip_data['ip']
            for service_data in ip_data['vhosts']:
                service = service_data[0]
                stopped = service_data[1]
                service_vhosts = service_data[2]
                options['output_file'].write('%s %d %s %s %s\n' % (
                    ip,
                    service['port'],
                    service['scheme'],
                    stopped,
                    ' '.join(service_vhosts),
                ))
                vhosts_count += len(service_vhosts)
        options['output_file'].close()
        Logger.info('')
        Logger.info('Saved results (%d vhosts)' % vhosts_count)


class VhostsFinder(object):
    _ERROR_SERIES_LENGTH_LIMIT = 8
    _VALID_VHOSTS_SERIES_LENGTH_LIMIT = 8

    class HttpClient(object):
        class Error(Exception):
            pass

        def __init__(self, ip, service):
            self._ip = ip
            self._service = service
            self._url = '%s://%s:%d' % (self._service['scheme'], self._ip, self._service['port'])
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': options['user_agent'],
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'X-Forwarded-For': '127.0.0.1',
                'X-Originating-IP': '[127.0.0.1]',
                'X-Remote-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1',
            })

        def get_response(self, vhost):
            try:
                response = self._session.get(
                    self._url,
                    headers={
                        'Host': vhost,
                    },
                    allow_redirects=False,
                    verify=False,
                    timeout=options['timeout_http']
                )
                return VhostsFinder.HttpResponse(response)
            except requests.exceptions.RequestException:
                raise VhostsFinder.HttpClient.Error

    class HttpResponse(object):
        def __init__(self, response):
            self._status_code = response.status_code
            self._location = ''
            self._body = ''
            if 'location' in response.headers:
                self._location = self._parse_location_header(response.headers['location'])
            else:
                # for performance reasons, compare only the first 512 bytes
                self._body = response.text[:512]

        def get_body(self):
            return self._body

        def get_location(self):
            return self._location

        def get_status_code(self):
            return self._status_code

        def is_similar(self, response):
            if self._status_code != response.get_status_code():
                return False
            if self._location != response.get_location():
                return False
            return SequenceMatcher(None, self._body, response.get_body()).ratio() >= 0.8

        @staticmethod
        def _parse_location_header(header):
            try:
                url = urlparse(header)
                return url.scheme + url.netloc + url.path
            except ValueError:
                return ''

    @staticmethod
    def get_args_list(resolved_domains, scanned_ips):
        args_list = []
        vhost_candidates = VhostsFinder._get_vhost_candidates(resolved_domains)
        for scanned_ip in scanned_ips:
            args_list.append((scanned_ip['ip'], scanned_ip['services'], vhost_candidates))
        return args_list

    @staticmethod
    def run(args):
        return VhostsFinder(*args).get_result()

    @staticmethod
    def show_start_info(args_list):
        Logger.info('Finding vhosts (active IPs: %d, vhost candidates: %d)...' % (
            len(args_list),
            len(args_list[0][2])
        ))

    @staticmethod
    def validate_results(_):
        return True

    @staticmethod
    def _get_vhost_candidates(resolved_domains):
        vhosts_candidates = []
        for resolved_domain in resolved_domains:
            if not resolved_domain['ips']:
                vhosts_candidates.append(resolved_domain['domain'])
        return get_random_items(vhosts_candidates, options['max_vhost_candidates'])

    def __init__(self, ip, services, vhost_candidates):
        self._ip = ip
        self._services = services
        self._vhost_candidates = vhost_candidates

    def get_result(self):
        vhosts = []
        for service in self._services:
            service_vhosts, stopped = self._find_service_vhosts(service)
            if service_vhosts:
                vhosts.append((service, stopped, service_vhosts))
        ProgressTracker.instance().done()
        if vhosts:
            result = {
                'ip': self._ip,
                'vhosts': vhosts,
            }
            Logger.verbose(result)
            return result

    def _find_service_vhosts(self, service):
        try:
            http_client = VhostsFinder.HttpClient(self._ip, service)
            reference_response = http_client.get_response(self._get_random_vhost())

            if not http_client.get_response(self._get_random_vhost()).is_similar(reference_response):
                # Responses for random (not existing) vhosts have to be similar
                return [], True

            error_series_length = 0
            stopped = False
            valid_vhosts_series_length = 0
            vhosts = []
            for vhost_candidate in get_random_items(self._vhost_candidates, -1):
                vhost, error = self._check_vhost_candidate(vhost_candidate, http_client, reference_response)
                if error:
                    error_series_length += 1
                    if error_series_length > self._ERROR_SERIES_LENGTH_LIMIT:
                        Logger.verbose('Stopped because too many errors (ip: %s, service: %s)' % (self._ip, service))
                        stopped = True
                        break
                else:
                    error_series_length = 0
                if vhost:
                    valid_vhosts_series_length += 1
                    if valid_vhosts_series_length > self._VALID_VHOSTS_SERIES_LENGTH_LIMIT:
                        Logger.verbose('Stopped because too many valid vhosts (ip: %s, service: %s)' % (
                            self._ip, service
                        ))
                        stopped = True
                        break
                    vhosts.append(vhost)
                else:
                    valid_vhosts_series_length = 0
            return vhosts, stopped
        except VhostsFinder.HttpClient.Error:
            return [], True

    @staticmethod
    def _check_vhost_candidate(vhost_candidate, http_client, reference_response):
        try:
            response = http_client.get_response(vhost_candidate)
            if response.is_similar(reference_response):
                return None, False
            return '%s %d' % (vhost_candidate, response.get_status_code()), False
        except VhostsFinder.HttpClient.Error:
            return None, True

    @staticmethod
    def _get_random_vhost(length=8):
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for _ in range(length)) + '.com'


# # # # # # # # # # #
# main
# # # # # # # # # # #

def main():
    global options

    options = ArgsParser.parse()
    requests.packages.urllib3.disable_warnings()

    Logger.info('Max domains to resolve: %d' % options['max_domains'])
    Logger.info('Max IPs to scan: %d' % options['max_ips'])
    Logger.info('Max vhost candidates to check: %d' % options['max_vhost_candidates'])
    Logger.info('Ports to scan: %s' % options['ports'])
    Logger.info('Threads number: %d' % options['threads_number'])
    Logger.info('Timeout HTTP: %.1fs' % options['timeout_http'])
    Logger.info('Timeout TCP: %.1fs' % options['timeout_tcp'])
    Logger.info('Verbose: %s' % options['verbose'])
    Logger.info('User agent: %s' % options['user_agent'])

    resolved_domains = Pool.map(DomainsResolver, ())
    if resolved_domains:
        scanned_ips = Pool.map(IpsScanner, (resolved_domains, ))
        if scanned_ips:
            vhosts = Pool.map(VhostsFinder, (resolved_domains, scanned_ips, ))
            if vhosts:
                Results.save(vhosts)


if __name__ == '__main__':
    main()
