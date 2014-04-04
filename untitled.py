import traceback
import struct
import ctypes

import gevent
import gevent.queue
import gevent.event
from gevent import socket
from dnslib import (
    OPCODE, QTYPE, RCODE, RR, AAAA,
    DNSRecord, DNSQuestion, DNSHeader,
)

if_nametoindex = ctypes.CDLL("libc.so.6").if_nametoindex


class DNSException(Exception):
    def __init__(self, rcode, message=None):
        super(DNSException, self).__init__(message)
        self.rcode = rcode


class ZeroConfResolutionRequest(gevent.event.AsyncResult):
    DEFAULT_TIMEOUT = 5.0
    DEFAULT_QUICK_COUNT = 3

    def __init__(
        self,
        rname,
        timeout=DEFAULT_TIMEOUT,
        quick_count=DEFAULT_QUICK_COUNT
    ):
        """
        timeout - maximum length of time to wait, in seconds

        quick_count - the number of responses to get before returning
            immediately
        """
        super(ZeroConfResolutionRequest, self).__init__()
        self.rname = rname
        self.timeout = timeout
        self.quick_count = quick_count
        self.responses = []

    def add_response(self, response):
        self.responses.append(response)
        if self.quick_count <= len(self.responses):
            self.set(self.responses)

    def try_resolve(self):
        have_responses = bool(self.responses)
        if have_responses:
            self.set(self.responses)
        return have_responses

    def try_get(self, *args, **kwargs):
        try:
            return super(ZeroConfResolutionRequest, self).get(*args, **kwargs)
        except gevent.Timeout:
            self.set(self.responses)
        return super(ZeroConfResolutionRequest, self).get(*args, **kwargs)

    def begin_request(self):
        pass

    def get_request(self):
        return DNSRecord(
            DNSHeader(rd=1),
            q=DNSQuestion(self.rname, QTYPE.AAAA))


class BaseDnsServer(object):
    def _greenlet_runnable(self):
        while True:
            (buf, address) = self.sock.recvfrom(10240)
            try:
                record = DNSRecord.parse(buf)
            except struct.error:
                pass  # log maybe later
            else:
                self.handle(record, address)

    def put(self, dns_record, address):
        buf = dns_record.pack()
        if len(buf) != self.sock.sendto(buf, 0, address):
            raise Exception('Datagram truncated')


class ZeroConfUpstream(object):
    def __init__(self, authoritative_for, zeroconf_listener):
        self._auth_for = authoritative_for
        self._zc = zeroconf_listener

    def _is_authoritative_for(self, dns_record):
        # FIXME: robustness
        return str(dns_record.questions[0].qname).endswith(self._auth_for)

    def _mangle_name(self, name):
        # FIXME: robustness
        rv = str(name)[:str(name).find(self._auth_for)] + 'local'
        print "rv = %r" % (rv, )
        return rv

    def _response_adapt_record(self, dns_record, rr):
        # import pdb; pdb.set_trace()
        return RR(
            dns_record.questions[0].qname,
            ttl=rr.ttl, rtype=28,
            rdata=AAAA(rr.rdata.data))

    def resolve(self, dns_record):
        if not self._is_authoritative_for(dns_record):
            raise DNSException(RCODE.NOTAUTH)

        if dns_record.questions[0].qtype != QTYPE.AAAA:
            response = dns_record.reply()
            response.rr = list()
            return response
        response = dns_record.reply()
        try:
            zc_response = self._zc.make_request(
                ZeroConfResolutionRequest(
                    self._mangle_name(dns_record.questions[0].qname),
                    quick_count=1
                )
            ).try_get(timeout=2.0)
        except Exception:
            traceback.print_exc()
            raise
        else:
            pass
        response.rr = list()
        if not zc_response:
            response.header.set_rcode(RCODE['Name Error'])
        for response_rec in zc_response:
            for rr in response_rec.rr:
                if rr.rtype == 28 and rr.rdata:
                    response.add_answer(
                        self._response_adapt_record(dns_record, rr))
        return response


class AuthoritativeDnsServer(BaseDnsServer):
    def __init__(self, upstream, address=None):
        if address is None:
            address = ('::', 53)
        self.upstream = upstream
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.bind(address)
        self._greenlet = gevent.Greenlet.spawn(self._greenlet_runnable)

    def _server_failure(self, dns_record):
        response = dns_record.reply()
        response.rr = []
        response.header.set_rcode(RCODE['Server failure'])
        return response

    def _handle_dns_exception(self, dns_record, exc):
        response = dns_record.reply()
        response.rr = []
        response.header.set_rcode(exc.rcode)
        return response

    def _handle_runnable(self, dns_record, address):
        assert OPCODE.QUERY == dns_record.header.opcode
        try:
            zc_response = self.upstream.resolve(dns_record)
        except gevent.Timeout:
            self.sock.sendto(self._server_failure(
                dns_record).pack(), 0, address)
        except DNSException as e:
            self.sock.sendto(self._handle_dns_exception(
                dns_record, e).pack(), 0, address)
        else:
            self.sock.sendto(zc_response.pack(), 0, address)

    def handle(self, dns_record, address):
        gevent.Greenlet(self._handle_runnable, dns_record, address).start()


class ZeroConfListener(BaseDnsServer):
    def __init__(self, interface=None):
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IP_MULTICAST_TTL,
            struct.pack('i', 30))
        if interface is not None:
            self.sock.setsockopt(
                socket.IPPROTO_IPV6,
                socket.IPV6_MULTICAST_IF,
                if_nametoindex(interface))
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, (
            socket.inet_pton(socket.AF_INET6, 'ff02::fb') +
            socket.inet_pton(socket.AF_INET6, '::')))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('::', 5353))
        self.listeners = []
        self._greenlet = gevent.Greenlet.spawn(self._greenlet_runnable)

    def put(self, dns_record):
        super(ZeroConfListener, self).put(dns_record, ('ff02::fb', 5353))

    def is_interested(self, listener, dns_record):
        for rr in dns_record.rr:
            if listener.rname == str(rr.rname):
                return True
        return False

    def handle(self, dns_record, address):
        for listener in self.listeners:
            if self.is_interested(listener, dns_record):
                listener.add_response(dns_record)

    def make_request(self, resolution_request):
        assert isinstance(resolution_request, ZeroConfResolutionRequest)

        def listener_remover():
            try:
                resolution_request.get(timeout=resolution_request.timeout)
            except gevent.Timeout:
                pass
            self.listeners.remove(resolution_request)
            if not resolution_request.ready():
                if not resolution_request.try_resolve():
                    resolution_request.set_exception(gevent.Timeout())

        self.listeners.append(resolution_request)
        gevent.Greenlet(listener_remover).start()
        resolution_request.begin_request()
        self.put(resolution_request.get_request())
        return resolution_request
