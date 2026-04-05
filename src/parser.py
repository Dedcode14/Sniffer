from scapy.all import Ether, IP, TCP, UDP, ICMP


def parse_packet(paquete):
    #Recibe un paquete de Scapy y devuelve un diccionario
    #con los campos de cada capa identificada.
    
    resultado = {}

    #Capa 2 - Ethernet
    if paquete.haslayer(Ether):
        eth = paquete[Ether]
        resultado['ethernet'] = {
            'mac_origen' : eth.src,
            'mac_destino': eth.dst,
            'protocolo'  : hex(eth.type),
        }

    #Capa 3 - IPv4
    if paquete.haslayer(IP):
        ip = paquete[IP]
        resultado['ipv4'] = {
            'ip_origen'  : ip.src,
            'ip_destino' : ip.dst,
            'ttl'        : ip.ttl,
            'protocolo'  : ip.proto,
        }

    #Capa 4 - TCP
    if paquete.haslayer(TCP):
        tcp = paquete[TCP]
        resultado['tcp'] = {
            'puerto_origen' : tcp.sport,
            'puerto_destino': tcp.dport,
            'secuencia'     : tcp.seq,
            'ack'           : tcp.ack,
            'flags'         : str(tcp.flags),
        }

    #Capa 4 - UDP
    elif paquete.haslayer(UDP):
        udp = paquete[UDP]
        resultado['udp'] = {
            'puerto_origen' : udp.sport,
            'puerto_destino': udp.dport,
            'longitud'      : udp.len,
        }

    #ICMP
    elif paquete.haslayer(ICMP):
        icmp = paquete[ICMP]
        resultado['icmp'] = {
            'tipo'  : icmp.type,
            'codigo': icmp.code,
        }

    #Payload
    if paquete.haslayer('Raw'):
        raw = bytes(paquete['Raw'])
        resultado['payload'] = ' '.join(f'{b:02x}' for b in raw[:32])

    return resultado