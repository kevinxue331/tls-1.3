"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets
from typing import Any

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *
from tlsimpl.util import pack_varlen


def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the Ed25519 public key used for key exchange.

    Specified in RFC8446 section 4.1.2.
    """
    # Generate a random 32-byte client random value
    client_random = secrets.token_bytes(32)

    packet = []
    extension =[]
    # TODO: construct the packet data
    
    packet.append(b'\x03\x03')
    packet.append(client_random)
    #packet.append(b'\x20')
    packet.append(b'\x01\x00')
    packet.append(b'\x00\x02')
    packet.append(b'\x13\x02')
    
    packet.append(b'\x01\x00')
    extension.append(b'\x00\x2b\x00\x03\x02\x03\x04') #supported versions
    extension.append(b'\x00\x0d\x00\x04\x00\x02\x08\x04') #sig algos
 
    
    
    key_exchange_pubkey=pack_varlen(key_exchange_pubkey)
    key_exchange_pubkey=(b'\x00\x1d')+key_exchange_pubkey
    key_exchange_pubkey=pack_varlen(key_exchange_pubkey)
    key_exchange_pubkey=pack_varlen(key_exchange_pubkey)
    key_exchange_pubkey=(b'\x00\x33')+key_exchange_pubkey

    
    
    
    extension.append(key_exchange_pubkey)
    
    extension.append(b'\x00\x0a\x00\x04\x00\x02\x00\x1d') #psk key exchange modes
    extension = b''.join(extension)
    
    length = len(extension)
    lengthb = length.to_bytes(2,"big")
    packet.append(lengthb)
    packet=packet+[extension]
    
    packet=b''.join(packet)
    
    length = len(packet)
    lengthb = length.to_bytes(3,"big")
    packet = lengthb+packet
    a=b'\x01'
    packet = a+packet
#print(packet)
    
    length = len(packet)
    lengthb = length.to_bytes(2,"big")
    packet=lengthb+packet
    packet=b'\x01'+packet
    packet=b'\x03'+packet
    packet=b'\x16'+packet
    
    #print(packet)
    sock.inner.sendall(packet)



def recv_server_hello(sock: client.TLSSocket) -> Any:
    # TODO: parse the server hello data
    pass


def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_ed25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    server_info = recv_server_hello(sock)
