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

import sys
import socket
import logging
import json
import time
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

KEY_FILE_NAME = 'private.pem'
NOTIFICATION = 'kdeconnect.notification'
BATTERY = 'kdeconnect.battery'
ENCRYPTED = 'kdeconnect.encrypted'
PING = 'kdeconnect.ping'

def identify_data(incoming, outgoing):
    assert type(incoming) == list
    assert type(outgoing) == list

    d = {
        'deviceId': '123',
        'deviceName': os.getenv('USER') + '@' + socket.gethostname(),
        'deviceType': 'desktop',
        'protocolVersion': 5,
        'SupportedIncomingInterfaces': ','.join(incoming),
        'SupportedOutgoingInterfaces': ','.join(outgoing)
    }
    return d

def netpkt(tp, data):
    d = {
        'id': int(time.time() * 1000),
        'type': tp,
        'body': data
    }
    return json.dumps(d)

def send_identity(ts):
    """
    :ts: socket
    """
    pkt = netpkt('kdeconnect.identity',
                 identify_data([NOTIFICATION, BATTERY, PING],
                               [NOTIFICATION, BATTERY, PING]))
    logging.debug('identity: %s', pkt)
    ts.send(pkt)
    ts.send('\n')

def send_pair(ts, key):
    """
    :param socket.socket ts: socket
    :param: PEM encoded public key
    """
    # logging.debug('public key: %s', key)

    pkt = netpkt('kdeconnect.pair',
                 {'pair': True, 'publicKey': key})
    logging.debug('pair request: %s', pkt)
    ts.send(pkt)
    ts.send('\n')

def handle_packets(pkts, cipher):
    """
    :param list pkts: list of packets
    """
    for pkt in pkts:
        p = json.loads(pkt)
        if p['type'] == ENCRYPTED:
            logging.debug('encrypted packet')

            data = ''
            for data_chunk in p['body']['data']:
                logging.debug('encrypted data: %s', data_chunk)
                dec = cipher.decrypt(base64.b64decode(data_chunk), None)
                # dec = cipher.decrypt(data_chunk, None)
                if not dec:
                    logging.error('failed to decrypt packet data, perhaps need to pair again?')
                else:
                    logging.debug('decrypted: %r', dec)
                    data += dec

            if data:
                logging.debug('decrypted data: %r', data)
            else:
                logging.debug('no data available')
        else:
            logging.info('other type: %s', p['type'])


def get_key():
    """
    Load private key from file or generate a new one
    :return: RSA key object
    :rtype: RSA
    """
    if os.path.exists('private.pem'):
        with open(KEY_FILE_NAME, 'r') as inf:
            key = RSA.importKey(inf.read())
    else:
        key = RSA.generate(2048)
        with open(KEY_FILE_NAME, 'w') as outf:
            outf.write(key.exportKey('PEM'))
    return key

def main(host, port):
    key = get_key()
    cipher = PKCS1_v1_5.new(key)

    # use TCP socket to complete handshake
    ts = socket.socket()
    logging.debug('connect to %s:%d', host, port)
    ts.connect((host, port))
    logging.debug('connected..')

    send_identity(ts)
    send_pair(ts, key.publickey().exportKey())

    pkts = []
    pending_pkt = ''
    while True:
        logging.debug('wait for data...')
        logging.debug('pending pkt: %s', pending_pkt)
        data = ts.recv(1024)
        # logging.debug('data: %s len: %d', data, len(data))
        pending_pkt += data
        pos = pending_pkt.find('\n\n')
        if pos == -1:
            logging.debug('expecting more data')
        else:
            # logging.debug('pos %r', pos)
            while len(pending_pkt) > 0 and pos != -1:
                pkt = pending_pkt[0:pos]
                logging.debug('got pkt: \'%s\'', pkt)
                if len(pkt) > 0:
                    pkts.append(pkt)
                pending_pkt = pending_pkt[pos + 2:]
                # logging.debug('rest: \'%s\'', pending_pkt)
                pos = pending_pkt.find('\n')
                # logging.debug('pos %r', pos)

            logging.debug('found %d complete packets', len(pkts))
            handle_packets(pkts, cipher)
            pkts = []


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        logging.error('missing host, port')
        raise SystemExit(1)

    host, port = sys.argv[1].split(':')
    main(host, int(port))
