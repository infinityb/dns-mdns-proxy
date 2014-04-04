import gevent
import untitled

listener = untitled.ZeroConfListener(interface='usb0')

upstream = untitled.ZeroConfUpstream('corp.yasashiisyndicate.org', listener)
adns = untitled.AuthoritativeDnsServer(upstream)

gevent.sleep(400)
