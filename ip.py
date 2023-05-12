import socket
import struct

# Função para desempacotar o cabeçalho IP
def desempacota_ip(frame):
    version_header_length = frame[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', frame[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), frame[header_length:]

# Função para formatar o endereço IP
def ipv4(addr):
    return '.'.join(map(str, addr))