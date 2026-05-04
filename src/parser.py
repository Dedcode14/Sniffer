from scapy.all import Ether, IP, TCP, UDP, ICMP
import struct


def _mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def parse_packet(paquete):
    resultado = {}

    raw = bytes(paquete)

    # --- Frame Ethernet ---
    # Nota: PRE, SFD y FCS no los entrega el driver de red, los maneja el NIC.
    if paquete.haslayer(Ether):
        eth = paquete[Ether]
        raw_eth = bytes(paquete)

        resultado["ethernet"] = {
            "PRE": "AA AA AA AA AA AA AA (gestionado por NIC)",
            "SFD": "AB (gestionado por NIC)",
            "DAD": eth.dst,  # Destination Address
            "SAD": eth.src,  # Source Address
            "LNG": hex(eth.type),  # EtherType / Length
            "FCS": "calculado por NIC",
        }

    # descarta IPv6
    if paquete.haslayer("IPv6"):
        return {}

    # --- Datagrama IPv4 ---
    if paquete.haslayer(IP):
        ip = paquete[IP]
        raw_ip = bytes(ip)

        # HLEN
        ihl_words = ip.ihl  # valor en palabras de 32 bits
        hlen_bytes = ihl_words * 4

        # Flags
        flags_val = ip.flags
        flags_str = (
            f"DF={'1' if ip.flags.DF else '0'}  " f"MF={'1' if ip.flags.MF else '0'}"
        )

        # Checksum
        checksum = hex(ip.chksum)

        # Options
        options = None
        if hlen_bytes > 20:
            raw_opts = raw_ip[20:hlen_bytes]
            options = " ".join(f"{b:02x}" for b in raw_opts)

        resultado["ipv4"] = {
            "VER": ip.version,
            "HLEN": f"{ihl_words} ({hlen_bytes} bytes)",
            "DS": ip.tos,  # Differentiated Services
            "TLEN": ip.len,  # Total Length
            "Identification": hex(ip.id),
            "Flags": flags_str,
            "Fragmentation Offset": ip.frag,
            "TTL": ip.ttl,
            "Protocol": ip.proto,
            "Checksum": checksum,
            "Source IP Address": ip.src,
            "Destination IP Address": ip.dst,
            "Options": options if options else "No",
        }

    # TCP
    if paquete.haslayer(TCP):
        tcp = paquete[TCP]
        resultado["tcp"] = {
            "puerto_origen": tcp.sport,
            "puerto_destino": tcp.dport,
            "secuencia": tcp.seq,
            "ack": tcp.ack,
            "flags": str(tcp.flags),
        }

    # UDP
    elif paquete.haslayer(UDP):
        udp = paquete[UDP]
        resultado["udp"] = {
            "puerto_origen": udp.sport,
            "puerto_destino": udp.dport,
            "longitud": udp.len,
        }

    # ICMP
    elif paquete.haslayer(ICMP):
        icmp = paquete[ICMP]
        resultado["icmp"] = {
            "tipo": icmp.type,
            "codigo": icmp.code,
        }

    # Payload
    if paquete.haslayer("Raw"):
        raw_data = bytes(paquete["Raw"])
        resultado["payload"] = " ".join(f"{b:02x}" for b in raw_data[:32])

    return resultado
