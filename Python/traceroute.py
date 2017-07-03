#
#           TraceRoute
#
# -----------------------------------------------------------------------------------------------------------
# 2EE da disciplina de Redes 2 - POLI-UPE
# Professor: Edison de Queiroz Albuquerque
# Autor: Rubens Euclides Carneiro
# Data: 20/11/2016
# -----------------------------------------------------------------------------------------------------------
# Descricao:
# Este programa exibe a rota (roteadores) que pacotes de rede percorrem entre seu computador e um host destino.
# Os protocolos disponiveis para serem usados no TraceRoute sao o UDP, ICMP e TCP; Podendo ser expecificados
# o numero da porta de destino utilizada pelos protocolos, quantidade maxima de hops e TTL inicial.
# O programa foi desenvolvido para OS X, mas pode ser utilizado em Linux sem o modo TCP.
# Deve ser executado com 'sudo' pois sockets raw exigem privilegios root.

# -----------------------------------------------------------------------------------------------------------

# Bibliotecas externas
# -----------------------------------------------------------------------------------------------------------
import socket
import struct
from random import randint
import time
import json
import urllib.request
import argparse
import signal


# Parser da linha de comando
# -----------------------------------------------------------------------------------------------------------
parser = argparse.ArgumentParser()
parser.add_argument("dest", help="Endereco alvo do TraceRoute")
parser.add_argument("--proto", help="Protocolo do TraceRoute. (UDP, ICMP, TCP)")
parser.add_argument("--porta", help="Porta alvo do traceroute", type=int)
parser.add_argument("--hops", help="Quantidade maxima de hops", type=int)
parser.add_argument("--ttl", help="Valor inicial do ttl", type=int)
args = parser.parse_args()


# Variaveis Globais
# -----------------------------------------------------------------------------------------------------------
dest_name = args.dest  # Dominio ou endereco IP

if args.porta:  # Porta de Destino utilizada pelos protocolos UDP e TCP
    port = args.porta
else:
    port = 54454

if args.hops:  # Quantidade maxima de hops
    hops = args.hops
else:
    hops = 30

if args.proto:  # Protocolo a ser utilizado pelo traceroute
    proto = str.upper(args.proto)
else:
    proto = "UDP"

if args.ttl:  # TTL inicial do traceroute
    ttl_inicial = args.ttl
else:
    ttl_inicial = 1


# Metodos
# -----------------------------------------------------------------------------------------------------------

# Gerador de sinal de timeout
def timeout_handler(signal, frame):
    raise Exception('Resposta demorou demais. Timeout.')

signal.signal(signal.SIGALRM, timeout_handler)


# Traceroute utilizando o protocolo UDP (Port Unreachable)
def udp():
    ttl, tempo, timeout, iteracao, enviados, recebidos, dest_addr = inicializa()

    try:
        while True:
            ttl, timeout, iteracao = limite_timeouts(timeout, iteracao, ttl)

            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            send_socket.sendto("".encode(), (dest_addr, port))

            enviados += 1
            inicio = time.time()
            curr_addr = None
            curr_name = None

            try:
                signal.alarm(5)
                try:
                    _, curr_addr = recv_socket.recvfrom(512)
                    curr_addr = curr_addr[0]
                    recebidos += 1
                    try:
                        curr_name = socket.gethostbyaddr(curr_addr)[0]
                    except socket.error:
                        curr_name = curr_addr

                except Exception:
                    timeout += 1
                    if timeout == 3:
                        curr_host = "* * *"
                        print("%d\t%s" % (ttl, curr_host))
                    continue
                finally:
                    send_socket.close()
                    recv_socket.close()

            except socket.error:
                pass
            finally:
                fim = time.time()
                send_socket.close()
                recv_socket.close()

            timeout = 0
            iteracao = 0

            print_info(curr_addr, curr_name, ttl, inicio, fim)

            ttl += 1

            if finaliza(curr_addr, dest_addr, ttl, tempo, enviados, recebidos):
                break
    except KeyboardInterrupt:
        interrompe(ttl, tempo, enviados, recebidos)


# Traceroute utilizando o protocolo TCP (Flag SYN)
def tcp():
    ttl, tempo, timeout, iteracao, enviados, recebidos, dest_addr = inicializa()

    try:
        while True:
            ttl, timeout, iteracao = limite_timeouts(timeout, iteracao, ttl)

            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

            send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            pacotetcp = pacote_tcp(dest_addr)
            send_socket.sendto(pacotetcp, (dest_addr, port))

            inicio = time.time()
            enviados += 1
            curr_addr = None
            curr_name = None

            try:
                try:
                    signal.alarm(5)
                    _, curr_addr = recv_socket.recvfrom(65535)
                    curr_addr = curr_addr[0]
                    recebidos += 1
                    timeout = 0

                    try:
                        curr_name = socket.gethostbyaddr(curr_addr)[0]
                    except socket.error:
                        curr_name = curr_addr

                except Exception:
                    timeout += 1

                    if timeout >= 2:
                        try:
                            signal.alarm(5)
                            dados, _ = recv_socket_tcp.recvfrom(65535)

                            if disseca_ipv4(dados)[4] == dest_addr and disseca_ipv4(dados)[3] == 6:
                                curr_addr = dest_addr
                                recebidos += 1
                                timeout = 0

                                try:
                                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                                except socket.error:
                                    curr_name = curr_addr

                        except Exception:
                            if timeout == 3:
                                curr_host = "* * *"
                                print("%d\t%s" % (ttl, curr_host))
                            continue
                    else:
                        continue

            except socket.error:
                pass
            finally:
                send_socket.close()
                recv_socket.close()
                recv_socket_tcp.close()

            fim = time.time()
            timeout = 0
            iteracao = 0

            print_info(curr_addr, curr_name, ttl, inicio, fim)

            ttl += 1

            if finaliza(curr_addr, dest_addr, ttl, tempo, enviados, recebidos):
                break
    except KeyboardInterrupt:
        interrompe(ttl, tempo, enviados, recebidos)
    except Exception:
        pass


# Traceroute utilizando o protocolo ICMP (Echo Requests)
def icmp():
    ttl, tempo, timeout, iteracao, enviados, recebidos, dest_addr = inicializa()
    pacoteicmp = pacote_icmp()

    try:
        while True:
            ttl, timeout, iteracao = limite_timeouts(timeout, iteracao, ttl)

            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            send_socket.sendto(pacoteicmp, (dest_addr, port))
            enviados += 1

            inicio = time.time()
            curr_addr = None
            curr_name = None
            try:
                signal.alarm(5)
                try:
                    _, curr_addr = recv_socket.recvfrom(512)
                    curr_addr = curr_addr[0]
                    recebidos += 1
                    try:
                        curr_name = socket.gethostbyaddr(curr_addr)[0]
                    except socket.error:
                        curr_name = curr_addr

                except Exception:
                    timeout += 1
                    if timeout == 3:
                        curr_host = "* * *"
                        print("%d\t%s" % (ttl, curr_host))
                    continue
                finally:
                    send_socket.close()
                    recv_socket.close()

            except socket.error:
                pass
            finally:
                fim = time.time()
                send_socket.close()
                recv_socket.close()

            timeout = 0
            iteracao = 0

            print_info(curr_addr, curr_name, ttl, inicio, fim)

            ttl += 1

            if finaliza(curr_addr, dest_addr, ttl, tempo, enviados, recebidos):
                break
    except KeyboardInterrupt:
        interrompe(ttl, tempo, enviados, recebidos)


# Disseca quadro Ethernet
def quadro_ethernet(dados):
    dest_mac, src_mac, protoc = struct.unpack('!6s6sH', dados[:14])
    return get_mac(dest_mac), get_mac(src_mac), hex(protoc), dados[14:]


# Formata endereco MAC
def get_mac(mac_bytes):
    str_bytes = map('{:02x}'.format, mac_bytes)
    mac_formatado = ':'.join(str_bytes).upper()
    return mac_formatado


# Disseca pacote IPv4
def disseca_ipv4(payload):
    versao_comprimento = payload[0]
    versao = versao_comprimento >> 4
    comprimento = (versao_comprimento & 15) * 4
    ttl, protocolo, ip_origem, ip_destino = struct.unpack('!8xBB2x4s4s', payload[:20])
    return versao, comprimento, ttl, protocolo, get_ipv4(ip_origem), get_ipv4(ip_destino), payload[comprimento:]


# Disseca segmento ICMP
def disseca_icmp(payload):
    tipo_icmp, codigo, check = struct.unpack('!BBH', payload[:4])
    return tipo_icmp, codigo, check


# Formata endereco IPv4
def get_ipv4(end_ip):
    str_ip = map(str, end_ip)
    ip_formatado = '.'.join(str_ip)
    return ip_formatado


# Disseca segmento TCP
def disseca_tcp(payload):
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


# Monta um segmento TCP com a flag SYN setada
def pacote_tcp(ipdest):
    # Cabecalho TCP
    porta_origem = randint(57000, 58000)
    porta_destino = port
    seq = 1
    ack = 0
    offset_reservado = 176  # 1011 0000
    flags = 0x02  # 0000 0010
    janela = 65535
    check = 0
    urgent = 0

    # Opcoes
    eol = 0x00
    nop = 0x01
    max_seg = struct.pack("!BBH", 0x02, 0x04, 0x05b4)
    scale = struct.pack("!BBB", 0x03, 0x03, 0x05)
    sack = struct.pack("!BB", 0x04, 0x02)
    tsval = randint(900000000, 999999999)
    timestamp = struct.pack("!BBLL", 0x08, 0x0a, tsval, 0)

    opcoes = struct.pack("!4sB3sBB10s2sB", max_seg, nop, scale, nop, nop, timestamp, sack, eol)

    pacote = struct.pack("!HHLLBBHHH24s", porta_origem, porta_destino, seq, ack, offset_reservado,
                         flags, janela, check, urgent, opcoes)

    # Pseudo-cabecalho TCP
    ip_origem = get_ip_address()
    ip_origem = ip_origem.split(".")
    ip_origem0 = hex((int(ip_origem[0])))
    ip_origem1 = hex((int(ip_origem[1])))
    ip_origem2 = hex((int(ip_origem[2])))
    ip_origem3 = hex((int(ip_origem[3])))

    ip_destino = ipdest.split(".")
    ip_destino0 = hex((int(ip_destino[0])))
    ip_destino1 = hex((int(ip_destino[1])))
    ip_destino2 = hex((int(ip_destino[2])))
    ip_destino3 = hex((int(ip_destino[3])))

    reservado = 0
    protocolo = socket.IPPROTO_TCP  # 6 TCP
    tam_seg = 44

    pseudocabecalho = struct.pack("!BBBBBBBBBBH", int(ip_origem0, 16), int(ip_origem1, 16), int(ip_origem2, 16),
                                  int(ip_origem3, 16), int(ip_destino0, 16), int(ip_destino1, 16), int(ip_destino2, 16),
                                  int(ip_destino3, 16), reservado, protocolo, tam_seg)
    pseudopacote = pseudocabecalho + pacote
    check = checksum(pseudopacote)

    pacote = struct.pack("!HHLLBBHHH24s", porta_origem, porta_destino, seq, ack, offset_reservado,
                         flags, janela, check, urgent, opcoes)
    return pacote


# Retorna o endereco IP da maquina
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


# Monta um segmento ICMP do tipo Echo Request
def pacote_icmp():
    tipo = 8
    codigo = 0
    check = 0
    resto = "".encode()

    pacote = struct.pack("!BBH4s", tipo, codigo, check, resto)
    check = checksum(pacote)

    pacote = struct.pack("!BBH4s", tipo, codigo, check, resto)
    return pacote


# Calcula o checksum dos segmentos ICMP e TCP
def checksum(checksum_packet):
    byte_count = len(checksum_packet)

    if byte_count % 2:
        odd_byte = ord(checksum_packet[-1])
        checksum_packet = checksum_packet[:-1]
    else:
        odd_byte = 0

    two_byte_chunks = struct.unpack("!%dH" % (len(checksum_packet) / 2), checksum_packet)

    total = 0
    for two_bytes in two_byte_chunks:
        total += two_bytes
    else:
        total += odd_byte

    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16

    return ~total + 0x10000 & 0xffff


# Busca o endereco fisico do Roteador ou Host
def geoip(ip):
    try:
        r = urllib.request.urlopen("http://freegeoip.net/json/%s" % ip).read()
        d = json.loads(r.decode())
        endereco = [d["country_name"], d["region_name"], d["city"]]
        retorno = ", ".join([s for s in endereco if s])
        return retorno
    except Exception:
        return "Endereco Desconhecido"


# Imprime informacoes
def print_info(curr_addr, curr_name, ttl, inicio, fim):
    if curr_addr is not None:
        if ttl == 1:
            curr_host = "%s   [ %s ] - Aqui Mesmo" % (curr_addr, curr_name)
        else:
            curr_host = "%s   [ %s ] - %s" % (curr_addr, curr_name, geoip(curr_addr))
    else:
        curr_host = "*"
    print("%d\t%dms\t\t%s" % (ttl, (fim - inicio) * 1000, curr_host))


# Imprime estatisticas
def finaliza(curr_addr, dest_addr, ttl, tempo, enviados, recebidos):
    if curr_addr == dest_addr:
        fim = time.time()
        print("\n\t\t--TraceRoute Finalizado--\n\nHops: %d\nTempo total: %dms\nPacotes enviados: %d\n"
              "Pacotes recebidos: %d\n" % ((ttl - 1), ((fim - tempo) * 1000), enviados, recebidos))
        return True
    elif ttl > hops:
        fim = time.time()
        print("\n\t\t--TraceRoute NAO Finalizado--\n\nHops: %d (Max)\nTempo total: %dms\nPacotes enviados: %d\n"
              "Pacotes recebidos: %d\n" % ((ttl - 1), ((fim - tempo) * 1000), enviados, recebidos))
        return True
    return False


# Interrompe o programa
def interrompe(ttl, tempo, enviados, recebidos):
    fim = time.time()
    print("\n\t\t--TraceRoute Interrompido--\n\nHops: %d\nTempo total: %dms\nPacotes enviados: %d\n"
          "Pacotes recebidos: %d\n" % ((ttl - 1), ((fim - tempo) * 1000), enviados, recebidos))


# Inicializa o programa
def inicializa():
    try:
        dest_addr = socket.gethostbyname(dest_name)
    except socket.gaierror:
        print('\nDestino nao encontrado.\n')
        return

    print("Realizando traceroute para o endereco: " + dest_name + " ( " + dest_addr + " )")

    ttl = ttl_inicial
    timeout = 0
    iteracao = 0
    enviados = 0
    recebidos = 0
    tempo = time.time()

    print("\nTTL\tRTT\t\tEndereco IP   [ Hostname ]  -  Geolocation\n")
    return ttl, tempo, timeout, iteracao, enviados, recebidos, dest_addr


# Limite de timeouts atingido
def limite_timeouts(timeout, iteracao, ttl):
        if (timeout == 3) and (iteracao >= 3):
            print("\nLimite de Timeouts excedido.")
            raise KeyboardInterrupt
        elif timeout == 3:
            ttl += 1
            timeout = 0
            iteracao += 1
        return ttl, timeout, iteracao


# Funcao Principal
# -----------------------------------------------------------------------------------------------------------
def main():
    print("\n\t\t-- TraceRoute --\n")
    print("Protocolo: [ %s ]   Porta: [ %d ]   Numero maximo de hops: [ %d ]\n" % (proto, port, hops))

    if proto == "UDP":
        udp()
    elif proto == "ICMP":
        icmp()
    elif proto == "TCP":
        tcp()
    else:
        print("\nProtocolos disponiveis: UDP - ICMP - TCP\n")


main()  # Inicio do programa
