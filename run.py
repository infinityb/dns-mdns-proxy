import os
import sys
import pwd
import grp
import gevent
import untitled


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() != 0:
        return

    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid
    os.setgroups([])
    os.setgid(running_gid)
    os.setuid(running_uid)
    os.umask(077)


listener = untitled.ZeroConfListener(interface='br0')
upstream = untitled.ZeroConfUpstream(sys.argv[1], listener)
adns = untitled.AuthoritativeDnsServer(upstream)


drop_privileges()

while True:
    gevent.sleep(400)
