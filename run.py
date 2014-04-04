import gevent
import untitled

listener = untitled.ZeroConfListener(interface='br0')

upstream = untitled.ZeroConfUpstream('office.corp.yasashiisyndicate.org', listener)
adns = untitled.AuthoritativeDnsServer(upstream)

gevent.sleep(400)
