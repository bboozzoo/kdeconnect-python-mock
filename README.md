# kdeconnect-python-mock

Mock implementation of kdeconnect daemon in Python. Use at your own
risk.

## Dependencies

- pycrypto

## Operation

There are 2 main scripts:

- `locator.py` - responsible for initial discovery
- `connector.py` - unicast with a device, performs pairing etc.

Kdeconnect Android client will send a UDP packet to port 1714 to all
hosts within the network. The packet contains a `tcpPort` field, while
the source IP address is obtained from IP packet, further known as
mobile. The desktop daemon connects to the mobile on given TCP port
and starts exchanging packets.

The 3 basic types of packets are (denoted as `kdeconnect.<name>` in
JSON):

- identity - basic device identification, type, name etc.
- pair - pairing request
- encrypted - data

The core daemon does not handle any data, things like notifications,
battery status are all handled by respective plugins in original
kdeconnect code.

All packet data is sent encrypted using asymmetric RSA keys. The
desktop initiates a `pair` request sending it's public key. *Note*,
apparently there is a problem in mobile app, that a pair request with
a new public key, coming from an already paired daemon will have no
effect, i.e. the old public key remains in use at the mobile device
side, thus the received packet data cannot be decrypted. The decrypted
packet data is again JSON payload with `type` and so on.


