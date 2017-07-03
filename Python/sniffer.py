import socket
import struct


def quadro_ethernet(dados):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', dados[:14])
    return get_mac(dest_mac), get_mac(src_mac), hex(proto), dados[14:]


def get_mac(mac_bytes):
    str_bytes = map('{:02x}'.format, mac_bytes)
    mac_formatado = ':'.join(str_bytes).upper()
    return mac_formatado


def pacote_ipv4(payload):
    versao_comprimento = payload[0]
    versao = versao_comprimento >> 4
    comprimento = (versao_comprimento & 15) * 4
    ttl, protocolo, ip_origem, ip_destino = struct.unpack('!8xBB2x4s4s', payload[:20])
    return versao, comprimento, ttl, protocolo, get_ipv4(ip_origem), get_ipv4(ip_destino), payload[comprimento:]


def get_ipv4(end_ip):
    str_ip = map(str, end_ip)
    ip_formatado = '.'.join(str_ip)
    return ip_formatado


def pacote_arp(payload):
    tipo_hw, tipo_proto, comp_hw, comp_proto, opcode, mac_origem, ip_origem, mac_destino, \
     ip_destino = struct.unpack('!HHBBH6s4s6s4s', payload[:28])
    return tipo_hw, tipo_proto, comp_hw, comp_proto, opcode, get_mac(mac_origem), get_ipv4(ip_origem), \
        get_mac(mac_destino), get_ipv4(ip_destino), payload[28:]


def segmento_tcp(payload):
    porta_origem, porta_destino, sequencia, ack, offset_reserved_flags = struct.unpack('!HHLLH', payload[:14])
    offset = (offset_reserved_flags >> 12) * 4
    urg_flag = (offset_reserved_flags & 32) >> 5
    ack_flag = (offset_reserved_flags & 16) >> 4
    psh_flag = (offset_reserved_flags & 8) >> 3
    rst_flag = (offset_reserved_flags & 4) >> 2
    syn_flag = (offset_reserved_flags & 2) >> 1
    fin_flag = offset_reserved_flags & 1
    return porta_origem, porta_destino, sequencia, ack, offset, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, \
        fin_flag, payload[offset:]


def datagrama_udp(payload):
    porta_origem, porta_destino, tamanho = struct.unpack('!HH2xH', payload[:8])
    return porta_origem, porta_destino, tamanho, payload[8:]


def pacote_icmp(payload):
    tipo_icmp, codigo, checksum = struct.unpack('!BBH', payload[:4])
    return tipo_icmp, codigo, checksum, payload[4:]


def dissecar_ip(payload):
    versao, comprimento, ttl, protocolo_ip, ip_origem, ip_destino, payload_ip = pacote_ipv4(payload)
    print('\nPacote IP')
    print('\n\tVersao: ' + str(versao))
    print('\n\tTTL: ' + str(ttl))
    print('\n\tProtocolo: ' + str(protocolo_ip))
    print('\n\tIP de Origem: ' + str(ip_origem))
    print('\n\tIP de Destino: ' + str(ip_destino))
    print('\n-----------------------------------------\n')

    if protocolo_ip == 1:
        dissecar_icmp(payload_ip)
    elif protocolo_ip == 6:
        dissecar_tcp(payload_ip)
    elif protocolo_ip == 17:
        dissecar_udp(payload_ip)
    else:
        print('\nProtocolo diferente de TCP, UDP ou ICMP.\n')


def dissecar_icmp(payload_ip):
    tipo_icmp, codigo, checksum, payload_icmp = pacote_icmp(payload_ip)
    print('\nPacote ICMP')
    print('\n\tTipo: ' + str(tipo_icmp))
    print('\n\tCodigo: ' + str(codigo))
    print('\n\tChecksum: ' + str(checksum))
    print('\n\tPayload: ' + str(payload_icmp))


def dissecar_tcp(payload_ip):
    porta_origem, porta_destino, sequencia, ack, offset, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, \
     payload_tcp = segmento_tcp(payload_ip)
    print('\nSegmento TCP')
    print('\n\tPorta de Origem: ' + str(porta_origem))
    print('\n\tPorta de Destino: ' + str(porta_destino))
    print('\n\tNumero de Sequencia: ' + str(sequencia))
    print('\n\tOffset: ' + str(offset))
    print('\n\tFlags')
    print('\n\t\tURG: ' + str(urg_flag))
    print('\n\t\tACK: ' + str(ack_flag))
    print('\n\t\tPSH: ' + str(psh_flag))
    print('\n\t\tRST: ' + str(rst_flag))
    print('\n\t\tSYN: ' + str(syn_flag))
    print('\n\t\tFIN: ' + str(fin_flag))
    print('\n\tPayload: ' + str(payload_tcp))

def dissecar_udp(payload_ip):
    porta_origem, porta_destino, tamanho, payload_udp = datagrama_udp(payload_ip)
    print('\nSegmento UDP')
    print('\n\tPorta de Origem: ' + str(porta_origem))
    print('\n\tPorta de Destino: ' + str(porta_destino))
    print('\n\tTamanho: ' + str(tamanho))
    print('\n\tPayload: ' + str(payload_udp))


def dissecar_arp(payload):
    tipo_hw, tipo_proto, comp_hw, comp_proto, opcode, mac_origem, ip_origem, \
     mac_destino, ip_destino, payload_arp = pacote_arp(payload)
    print('\nPacote ARP')
    print('\n\tTipo de Hardware: ' + str(tipo_hw))
    print('\n\tTipo de Protocolo: ' + str(hex(tipo_proto)))
    print('\n\tComprimento do Endereco de Hardware: ' + str(comp_hw))
    print('\n\tComprimento do Endereco de Protocolo: ' + str(comp_proto))
    if opcode == 1:
        tipo_arp = '( Request )'
    else:
        tipo_arp = '( Reply )'
    print('\n\tOpcode: ' + str(opcode) + ' ' + tipo_arp)
    print('\n\tEndereco MAC do Remetente: ' + str(mac_origem))
    print('\n\tEndereco IP do Remetente: ' + str(ip_origem))
    print('\n\tEndereco MAC do Alvo: ' + str(mac_destino))
    print('\n\tEndereco IP do Alvo: ' + str(ip_destino))
    print('\n\tPayload: ' + str(payload_arp))


def dissecar_ethernet(dados_raw):
    mac_destino, mac_origem, protocolo_eth, payload = quadro_ethernet(dados_raw)
    print('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')
    print('\nQuadro Ethernet')
    print('\n\tMAC de Origem: ' + str(mac_origem))
    print('\n\tMAC de Destino: ' + str(mac_destino))
    print('\n\tProtocolo Ethernet: ' + str(protocolo_eth))
    print('\n-----------------------------------------\n')

    if str(protocolo_eth) == '0x800':
        dissecar_ip(payload)
    elif str(protocolo_eth) == '0x806':
        dissecar_arp(payload)
    else:
        print('\nProtocolo diferente de IP ou ARP.\n')

    print('\n\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')


def main():
    conex = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

    try:
        while True:
            dados_raw, addr = conex.recvfrom(65536)
            dissecar_ethernet(dados_raw)
    except KeyboardInterrupt:
        print('\n\nSniffer interrompido pelo usuario.\n\n')


main()
