import socket
import struct

# Função para desempacotar o cabeçalho UDP
def desempacota_udp(segment):
    src_port, dest_port, size = struct.unpack('! H H 2x H', segment[:8])
    return src_port, dest_port, size, segment[8:]