import struct
import socket

def desempacota_ethernet(frame):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', frame[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), frame[14:]

# Função para formatar o endereço MAC
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()