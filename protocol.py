import socket
import struct

# Função para identificar o protocolo
def identifica_protocolo_ethernet(proto):
    if proto == 8:
        return 'IPv4'
    elif proto == 1544:
        return 'ARP'
    elif proto == 34525:
        return 'IPv6'
    else:
        return 'Outro'

# Função para identificar o protocolo da camada de transporte
def identifica_protocolo_transporte(proto):
    if proto == 6:
        return 'TCP'
    elif proto == 17:
        return 'UDP'
    else:
        return 'Outro'