# Importa las capas que Scapy puede identificar automáticamente en un paquete
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP

# Importa struct (disponible por si se necesita parseo manual de bytes)
import struct


# Función auxiliar que convierte bytes a formato MAC legible
def _mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


# Función principal que recibe un paquete de Scapy y devuelve un diccionario con sus campos
def parse_packet(paquete):

    # Diccionario que acumulará los campos de cada capa encontrada
    resultado = {}

    # Convierte el paquete completo a bytes para calcular longitudes
    raw = bytes(paquete)

    # Verifica si el paquete tiene capa Ethernet
    if paquete.haslayer(Ether):
        eth = paquete[Ether]  # extrae la capa Ethernet del paquete

        resultado["ethernet"] = {
            # PRE: 7 bytes de preámbulo, no disponibles desde software, los gestiona el NIC
            "PRE": "AA AA AA AA AA AA AA (gestionado por NIC)",
            # SFD: byte delimitador de inicio de trama, tampoco disponible desde software
            "SFD": "AB (gestionado por NIC)",
            # DAD: dirección MAC de destino
            "DAD": eth.dst,
            # SAD: dirección MAC de origen
            "SAD": eth.src,
            # LNG: EtherType en hexadecimal (0x0800 = IPv4, 0x0806 = ARP, etc.)
            "LNG": hex(eth.type),
            # DATA: tamaño del campo de datos, se calcula restando 14 bytes de encabezado y 4 de FCS
            "DATA": f"{len(raw) - 18} bytes",
            # FCS: checksum de la trama, calculado y verificado por el NIC, no disponible desde software
            "FCS": "calculado por NIC",
            # longitud: tamaño total del paquete capturado en bytes
            "longitud": f"{len(raw)} bytes",
        }

    # Si el paquete es IPv6 lo descarta devolviendo un diccionario vacío
    # El sniffer solo trabaja con IPv4
    if paquete.haslayer("IPv6"):
        return {}

    # Verifica si el paquete es ARP
    if paquete.haslayer(ARP):
        arp = paquete[ARP]  # extrae la capa ARP

        resultado["arp"] = {
            # op == 1 es Request, op == 2 es Reply
            "operacion": "Request" if arp.op == 1 else "Reply",
            # MAC del dispositivo que envía el ARP
            "mac_origen": arp.hwsrc,
            # IP del dispositivo que envía el ARP
            "ip_origen": arp.psrc,
            # MAC del dispositivo destino
            "mac_destino": arp.hwdst,
            # IP del dispositivo que se está buscando
            "ip_destino": arp.pdst,
        }

        # Marca el tipo de protocolo como ARP
        resultado["tipo_protocolo"] = "ARP"

        # Retorna aquí porque ARP no tiene capa de transporte
        return resultado

    # Verifica si el paquete tiene capa IPv4
    if paquete.haslayer(IP):
        ip = paquete[IP]  # extrae la capa IP
        raw_ip = bytes(ip)  # convierte la capa IP a bytes para acceder a las opciones

        ihl_words = ip.ihl  # IHL en palabras de 32 bits (valor entre 5 y 15)
        hlen_bytes = ihl_words * 4  # convierte a bytes multiplicando por 4

        # Construye el string de flags: DF (Don't Fragment) y MF (More Fragments)
        flags_str = (
            f"DF={'1' if ip.flags.DF else '0'}  MF={'1' if ip.flags.MF else '0'}"
        )

        # Checksum del encabezado IP en hexadecimal
        checksum = hex(ip.chksum)

        # Las opciones solo existen si el encabezado es mayor a 20 bytes (IHL > 5)
        options = None
        if hlen_bytes > 20:
            raw_opts = raw_ip[20:hlen_bytes]  # extrae los bytes de opciones
            options = " ".join(
                f"{b:02x}" for b in raw_opts
            )  # los convierte a hex legible

        resultado["ipv4"] = {
            # Versión del protocolo IP (siempre 4 aquí)
            "VER": ip.version,
            # Longitud del encabezado en palabras y en bytes
            "HLEN": f"{ihl_words} ({hlen_bytes} bytes)",
            # Differentiated Services
            "DS": ip.tos,
            # Longitud total del datagrama en bytes (encabezado + datos)
            "TLEN": ip.len,
            # Identificador único del datagrama, usado para reensamblar fragmentos
            "Identification": hex(ip.id),
            # Flags de fragmentación
            "Flags": flags_str,
            # Desplazamiento del fragmento respecto al datagrama original
            "Fragmentation Offset": ip.frag,
            # Tiempo de vida
            "TTL": ip.ttl,
            # Número de protocolo de la capa siguiente (6=TCP, 17=UDP, 1=ICMP)
            "Protocol": ip.proto,
            # Checksum del encabezado IP para detección de errores
            "Checksum": checksum,
            # Dirección IP de origen
            "Source IP Address": ip.src,
            # Dirección IP de destino
            "Destination IP Address": ip.dst,
            # Opciones del encabezado en hex, o "No" si no hay opciones
            "Options": options if options else "No",
        }

    # Verifica si el protocolo de transporte es TCP
    if paquete.haslayer(TCP):
        tcp = paquete[TCP]  # extrae la capa TCP

        resultado["tcp"] = {
            # Puerto de origen (proceso que envía)
            "puerto_origen": tcp.sport,
            # Puerto de destino (proceso que recibe)
            "puerto_destino": tcp.dport,
            # Número de secuencia para ordenar segmentos
            "secuencia": tcp.seq,
            # Número de acuse de recibo
            "ack": tcp.ack,
            # Flags TCP activos (SYN, ACK, FIN, RST, PSH, URG)
            "flags": str(tcp.flags),
        }

        # Detecta el protocolo de aplicación según el puerto
        if tcp.dport == 80 or tcp.sport == 80:
            resultado["tipo_protocolo"] = "HTTP"  # puerto 80 es HTTP
        elif tcp.dport == 443 or tcp.sport == 443:
            resultado["tipo_protocolo"] = "TLS"  # puerto 443 es HTTPS/TLS
        else:
            resultado["tipo_protocolo"] = "TCP"  # cualquier otro puerto TCP genérico

    # Si no es TCP, verifica si es UDP
    elif paquete.haslayer(UDP):
        udp = paquete[UDP]  # extrae la capa UDP

        resultado["udp"] = {
            # Puerto de origen
            "puerto_origen": udp.sport,
            # Puerto de destino
            "puerto_destino": udp.dport,
            # Longitud total del segmento UDP en bytes (encabezado + datos)
            "longitud": udp.len,
        }

        # Detecta DNS según el puerto estándar 53
        if udp.dport == 53 or udp.sport == 53:
            resultado["tipo_protocolo"] = "DNS"  # puerto 53 es DNS
        else:
            resultado["tipo_protocolo"] = "UDP"  # cualquier otro puerto UDP genérico

    # Si no es UDP, verifica si es ICMP
    elif paquete.haslayer(ICMP):
        icmp = paquete[ICMP]  # extrae la capa ICMP

        resultado["icmp"] = {
            # Tipo de mensaje ICMP
            "tipo": icmp.type,
            # Código que complementa el tipo para dar más detalle del mensaje
            "codigo": icmp.code,
        }

        # Marca el tipo de protocolo como ICMP
        resultado["tipo_protocolo"] = "ICMP"

    else:
        # Ningún protocolo de transporte reconocido
        resultado["tipo_protocolo"] = "DESCONOCIDO"

    # Verifica si el paquete tiene datos en la capa Raw (payload sin parsear)
    if paquete.haslayer("Raw"):
        raw_data = bytes(paquete["Raw"])  # convierte el payload a bytes
        # Guarda los primeros 32 bytes del payload en formato hexadecimal
        resultado["payload"] = " ".join(f"{b:02x}" for b in raw_data[:32])

    # Devuelve el diccionario con todos los campos encontrados
    return resultado
