from scapy.all import sniff
from parser import parse_packet


def _imprimir_paquete(datos):
    #Imprime en consola los campos del diccionario devuelto por parse_packet

    if 'ethernet' in datos:
        eth = datos['ethernet']
        print("=" * 50)
        print("CAPA 2 - ETHERNET")
        print("=" * 50)
        print(f"  MAC origen  : {eth['mac_origen']}")
        print(f"  MAC destino : {eth['mac_destino']}")
        print(f"  Protocolo   : {eth['protocolo']}")

    if 'ipv4' in datos:
        ip = datos['ipv4']
        print("\n" + "=" * 50)
        print("CAPA 3 - IPv4")
        print("=" * 50)
        print(f"  IP origen   : {ip['ip_origen']}")
        print(f"  IP destino  : {ip['ip_destino']}")
        print(f"  TTL         : {ip['ttl']}")
        print(f"  Protocolo   : {ip['protocolo']}")

    if 'tcp' in datos:
        tcp = datos['tcp']
        print("\n" + "=" * 50)
        print("CAPA 4 - TCP")
        print("=" * 50)
        print(f"  Puerto origen  : {tcp['puerto_origen']}")
        print(f"  Puerto destino : {tcp['puerto_destino']}")
        print(f"  Secuencia      : {tcp['secuencia']}")
        print(f"  Acuse (ACK)    : {tcp['ack']}")
        print(f"  Flags          : {tcp['flags']}")

    elif 'udp' in datos:
        udp = datos['udp']
        print("\n" + "=" * 50)
        print("CAPA 4 - UDP")
        print("=" * 50)
        print(f"  Puerto origen  : {udp['puerto_origen']}")
        print(f"  Puerto destino : {udp['puerto_destino']}")
        print(f"  Longitud       : {udp['longitud']}")

    elif 'icmp' in datos:
        icmp = datos['icmp']
        print("\n" + "=" * 50)
        print("CAPA 3.5 - ICMP")
        print("=" * 50)
        print(f"  Tipo   : {icmp['tipo']}")
        print(f"  Código : {icmp['codigo']}")

    if 'payload' in datos:
        print("\n" + "=" * 50)
        print("PAYLOAD (primeros 32 bytes en hex)")
        print("=" * 50)
        print(f"  {datos['payload']}")

    print()


def capturar_uno():
    #captura un solo paquete y lo imprime

    print("Esperando un paquete...\n")

    def callback(paquete):
        datos = parse_packet(paquete)
        _imprimir_paquete(datos)

    sniff(count=1, prn=callback)