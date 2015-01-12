#!/usr/bin/python2 -tt
# ex:ts=4:sw=4:sts=4:et
# -*- tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*-
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# AUTHORS
# Maciek Borzecki <maciek.borzecki (at] gmail.com>
#

import socket
import logging
import json
import subprocess
import os

DISCOVERY_PORT = 1714

def main():
    # listen for packet on UDP socket
    us = socket.socket(type=socket.SOCK_DGRAM)
    us.bind(('0.0.0.0', DISCOVERY_PORT))
    while True:
        logging.debug('recv...')
        data, sender = us.recvfrom(1024)
        logging.debug('got packet from %s:%d', sender[0], sender[1])
        logging.debug('data packet: %r', data)

        pkt = json.loads(data)
        logging.debug('parsed: %r', pkt)
        if pkt['type'] == 'kdeconnect.identity':
            logging.debug('identity packet')

        tcp_port = pkt['body']['tcpPort']
        logging.debug('target: tcp://%s:%d', sender[0], tcp_port)
        # start connector
        os.execv(os.path.join(os.path.dirname(__file__), 'connector.py'),
                 ['-d', '%s:%d' % (sender[0], tcp_port)])

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
