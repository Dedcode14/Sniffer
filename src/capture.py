# Importa la función sniff de Scapy para capturar paquetes de red
from scapy.all import sniff

# Importa la función que disecciona cada paquete por capas
from parser import parse_packet


# Imprime en consola los campos del paquete organizados por capa
def _imprimir_paquete(datos):

    # Verifica si existen datos de la capa Ethernet
    if "ethernet" in datos:
        eth = datos["ethernet"]
        print("=" * 50)
        print("CAPA 2 - ETHERNET")
        print("=" * 50)
        print(f"  PRE  (Preamble)          : {eth['PRE']}")
        print(f"  SFD  (Start Frame Delim) : {eth['SFD']}")
        print(f"  DAD  (Dest. Address)     : {eth['DAD']}")
        print(f"  SAD  (Source Address)    : {eth['SAD']}")
        print(f"  LNG  (EtherType/Length)  : {eth['LNG']}")
        print(f"  DATA                     : {eth['DATA']}")
        print(f"  FCS  (Frame Check Seq.)  : {eth['FCS']}")
        print(f"  Longitud total           : {eth['longitud']}")

    # Verifica si existen datos de la capa IPv4
    if "ipv4" in datos:
        ip = datos["ipv4"]
        print("\n" + "=" * 50)
        print("CAPA 3 - IPv4")
        print("=" * 50)
        print(f"  VER                      : {ip['VER']}")
        print(f"  HLEN                     : {ip['HLEN']}")
        print(f"  DS   (Diff. Services)    : {ip['DS']}")
        print(f"  TLEN (Total Length)      : {ip['TLEN']}")
        print(f"  Identification           : {ip['Identification']}")
        print(f"  Flags                    : {ip['Flags']}")
        print(f"  Fragmentation Offset     : {ip['Fragmentation Offset']}")
        print(f"  TTL                      : {ip['TTL']}")
        print(f"  Protocol                 : {ip['Protocol']}")
        print(f"  Checksum                 : {ip['Checksum']}")
        print(f"  Source IP Address        : {ip['Source IP Address']}")
        print(f"  Destination IP Address   : {ip['Destination IP Address']}")
        print(f"  Options                  : {ip['Options']}")

    # Verifica si existen datos ARP
    if "arp" in datos:
        arp = datos["arp"]
        print("\n" + "=" * 50)
        print("CAPA 3 - ARP")
        print("=" * 50)
        print(f"  Operación    : {arp['operacion']}")
        print(f"  MAC Origen   : {arp['mac_origen']}")
        print(f"  IP Origen    : {arp['ip_origen']}")
        print(f"  MAC Destino  : {arp['mac_destino']}")
        print(f"  IP Destino   : {arp['ip_destino']}")

    # Verifica si el protocolo de transporte es TCP
    if "tcp" in datos:
        tcp = datos["tcp"]
        print("\n" + "=" * 50)
        print("CAPA 4 - TCP")
        print("=" * 50)
        print(f"  Puerto origen  : {tcp['puerto_origen']}")
        print(f"  Puerto destino : {tcp['puerto_destino']}")
        print(f"  Secuencia      : {tcp['secuencia']}")
        print(f"  Acuse (ACK)    : {tcp['ack']}")
        print(f"  Flags          : {tcp['flags']}")

    # Si no es TCP, verifica si es UDP
    elif "udp" in datos:
        udp = datos["udp"]
        print("\n" + "=" * 50)
        print("CAPA 4 - UDP")
        print("=" * 50)
        print(f"  Puerto origen  : {udp['puerto_origen']}")
        print(f"  Puerto destino : {udp['puerto_destino']}")
        print(f"  Longitud       : {udp['longitud']}")

    # Si no es UDP, verifica si es ICMP
    elif "icmp" in datos:
        icmp = datos["icmp"]
        print("\n" + "=" * 50)
        print("CAPA 3.5 - ICMP")
        print("=" * 50)
        print(f"  Tipo   : {icmp['tipo']}")
        print(f"  Código : {icmp['codigo']}")

    # Verifica si existe payload y lo muestra en hexadecimal
    if "payload" in datos:
        print("\n" + "=" * 50)
        print("PAYLOAD (primeros 32 bytes en hex)")
        print("=" * 50)
        print(f"  {datos['payload']}")

    # Salto de línea al final del paquete
    print()


# Captura exactamente un paquete y muestra su detalle en consola
def capturar_uno():
    print("Esperando un paquete...\n")

    # Función interna que se ejecuta cuando llega el paquete
    def callback(paquete):
        datos = parse_packet(paquete)  # disecciona el paquete
        if not datos:  # descarta paquetes no soportados como IPv6
            return
        _imprimir_paquete(datos)  # imprime los campos en consola

    # count=1 captura solo un paquete y llama a callback al recibirlo
    sniff(count=1, prn=callback)


# Lista global que almacena todos los paquetes capturados en modo continuo
paquetes_capturados = []


# Función interna que se ejecuta por cada paquete durante la captura continua
def _callback_continuo(paquete):
    datos = parse_packet(paquete)  # disecciona el paquete
    if not datos:  # descarta paquetes no soportados como IPv6
        return
    paquetes_capturados.append(datos)  # agrega el paquete a la lista global
    num = len(paquetes_capturados)  # número de paquetes capturados hasta ahora

    # Obtiene el protocolo detectado por parser, o muestra ??? si no se reconoce
    proto = datos.get("tipo_protocolo", "???")

    # Obtiene las IPs de origen y destino del datagrama IPv4 si existe
    ip = datos.get("ipv4", {})
    src = ip.get("Source IP Address", "?")
    dst = ip.get("Destination IP Address", "?")

    # Para ARP usa las IPs del propio ARP ya que no tiene capa IPv4
    if "arp" in datos:
        src = datos["arp"]["ip_origen"]
        dst = datos["arp"]["ip_destino"]

    # Imprime una línea de resumen por paquete
    print(f"  [{num:>3}]  {proto:<12}  {src:<16}  ->  {dst}")


# Inicia la captura continua de paquetes hasta que el usuario presione Ctrl+C
def capturar_continuo():
    global paquetes_capturados
    paquetes_capturados = []  # reinicia la lista al iniciar una nueva captura

    print("Captura continua iniciada. Presiona Ctrl+C para detener.\n")
    print(f"  {'#':>3}   {'Protocolo':<12}  {'IP Origen':<16}       IP Destino")
    print("  " + "-" * 55)

    try:
        # Captura paquetes sin límite y llama a _callback_continuo por cada uno
        sniff(prn=_callback_continuo, store=False)
    except KeyboardInterrupt:
        # El usuario presionó Ctrl+C, muestra el total capturado
        print(f"\nCaptura detenida. Paquetes capturados: {len(paquetes_capturados)}")

    # Después de detener ofrece al usuario seleccionar un paquete para análisis
    seleccionar_paquete()


# Permite al usuario elegir un paquete de la lista y ver su detalle completo
def seleccionar_paquete():
    # Si no hay paquetes capturados termina la función
    if not paquetes_capturados:
        print("No hay paquetes capturados.")
        return

    while True:
        try:
            # Solicita al usuario el número del paquete que desea analizar
            entrada = input(
                f"\nIngresa el número del paquete a analizar "
                f"(1-{len(paquetes_capturados)}), o 0 para salir: "
            )
            num = int(entrada)  # convierte la entrada a entero

            if num == 0:  # el usuario elige salir
                break

            if 1 <= num <= len(paquetes_capturados):
                # Muestra el detalle del paquete seleccionado
                print(f"\nDetalle del paquete #{num}")
                _imprimir_paquete(paquetes_capturados[num - 1])
            else:
                # El número ingresado está fuera del rango válido
                print(
                    f"Número fuera de rango. Elige entre 1 y {len(paquetes_capturados)}."
                )

        except ValueError:
            # El usuario ingresó algo que no es un número
            print("Ingresa un número válido.")
