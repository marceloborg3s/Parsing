from ethernet import desempacota_ethernet, get_mac_addr
from ip import desempacota_ip, ipv4
from tcp import desempacota_tcp
from udp import desempacota_udp
from protocol import identifica_protocolo_ethernet, identifica_protocolo_transporte

# Função principal que recebe os pacotes e faz o parsing
def captura_pacotes(hexadecimal):
    frame = bytes.fromhex(hexadecimal)
    dest_mac, src_mac, eth_proto, raw_data = desempacota_ethernet(frame)
    version, header_length, ttl, proto, src, target, data = desempacota_ip(raw_data)

    # identificar o protocolo Ethernet e IP
    proto_ethernet = identifica_protocolo_ethernet(eth_proto)
    proto_transporte = identifica_protocolo_transporte(proto)
    
    # extrair informações do pacote de acordo com o protocolo de transporte
    if proto_transporte == 'TCP':
        src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = desempacota_tcp(data)
    elif proto_transporte == 'UDP':
        src_port, dest_port, size, data = desempacota_udp(data)
    else:
        print('Protocolo de transporte não suportado:', proto_transporte)
        return

    # mostrar as informações extraídas
    print('\n----- Ethernet Frame -----')
    print(f'Destino: {dest_mac}, Origem: {src_mac}, Protocolo: {proto_ethernet}')

    print('\n------ Pacote IP ------')
    print(f'Versão: {version}, Tamanho do cabeçalho: {header_length}, TTL: {ttl}')
    print(f'Protocolo: {proto}, Origem: {src}, Destino: {target}')

    print(f'\n------ Pacote {proto_transporte} ------')
    print(f'Porta de origem: {src_port}, Porta de destino: {dest_port}')
    if proto_transporte == 'TCP':
        print(f'Flags: URG={flag_urg}, ACK={flag_ack}, PSH={flag_psh}, RST={flag_rst}, SYN={flag_syn}, FIN={flag_fin}')
    print('Dados:')
    print('\nDados:')
    data_size = len(data)
    print(f'Tamanho: {data_size} bytes')
    for i in range(0, data_size, 16):
        chunk = data[i:i+16]
        print(f'{i:04x}  {" ".join(f"{b:02x}" for b in chunk):<48}  {" ".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)}')
      
armazen ="d4ab8245c40c000c297643e108004500003c1c4640004006b6e7c0a80001c0a800501f9000357d1643fb000000005012100082e10000020405b40402"
captura_pacotes(armazen)