import struct
import ctypes

import gevent
import gevent.queue
import gevent.event
from gevent import socket
from dnslib import QTYPE, RCODE, DNSRecord, DNSQuestion, DNSHeader


if_nametoindex = ctypes.CDLL("libc.so.6").if_nametoindex

"""
<DNS Header: id=0x128e type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
<DNS Question: 'jenkins.local' qtype=AAAA qclass=IN>

<DNS Header: id=0xc837 type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
<DNS Question: 'jenkins.local' qtype=AAAA qclass=IN>
"""
"""
import untitled
listener = untitled.ZeroConfListener(interface='wlan0')
req = untitled.ZeroConfResolutionRequest('vita.local')
xx = listener.make_request(req).get()
"""
"""
import gevent
import untitled
adns = untitled.AuthoritativeDnsServer(None)
gevent.sleep(400)
"""


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
        print "try_resolve => %r" % (have_responses, )
        return have_responses

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


class AuthoritativeDnsServer(BaseDnsServer):
    def __init__(self, upstream, address=None):
        if address is None:
            address = ('::', 53)
        self.upstream = upstream
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.bind(address)
        self._greenlet = gevent.Greenlet.spawn(self._greenlet_runnable)

    def handle(self, dns_record, address):
        for question in dns_record.questions:
            if question.qname == ('a', 'a'):
                print ";ol"
        response = dns_record.reply()
        response.rr = []
        response.header.set_rcode(RCODE['Name Error'])
        print "response buf: %r" % (response.pack(), )
        self.sock.sendto(response.pack(), 0, address)


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

    def _greenlet_runnable(self):
        while True:
            buf = self.sock.recv(10240)
            print "ZeroConfListener.RX"
            try:
                self.handle(DNSRecord.parse(buf))
            except struct.error as e:
                print "ZeroConfListener.RX.Failed: %r" % (e, )

    def put(self, dns_record):
        print "ZeroConfListener.TX"
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
                    resolution_request.set_exception(Exception())

        self.listeners.append(resolution_request)
        gevent.Greenlet(listener_remover).start()
        resolution_request.begin_request()
        self.put(resolution_request.get_request())
        return resolution_request
