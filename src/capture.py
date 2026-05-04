# Importa la función sniff para capturar paquetes de red
from scapy.all import sniff

# Importa la función parse_packet desde el archivo parser
from parser import parse_packet


# Define una función privada para imprimir los datos del paquete
def _imprimir_paquete(datos):
    # Imprime en consola los campos del diccionario devuelto por parse_packet

    # Verifica si en el diccionario existe información de la capa Ethernet
    if "ethernet" in datos:
        # Guarda los datos de ethernet en una variable local
        eth = datos["ethernet"]
        # Imprime una línea separadora
        print("=" * 50)
        # Imprime el título de la capa 2
        print("CAPA 2 - ETHERNET")
        # Imprime otra línea separadora
        print("=" * 50)
        # Imprime la MAC de origen
        print(f"  MAC origen  : {eth['mac_origen']}")
        # Imprime la MAC de destino
        print(f"  MAC destino : {eth['mac_destino']}")
        # Imprime el protocolo de la trama Ethernet
        print(f"  Protocolo   : {eth['protocolo']}")

    # Verifica si existe información de IPv4 en el diccionario
    if "ipv4" in datos:
        # Guarda los datos de IPv4 en una variable
        ip = datos["ipv4"]
        # Imprime salto de línea + separador
        print("\n" + "=" * 50)
        # Imprime el título de la capa 3
        print("CAPA 3 - IPv4")
        # Imprime separador
        print("=" * 50)
        # Imprime la IP de origen
        print(f"  IP origen   : {ip['ip_origen']}")
        # Imprime la IP de destino
        print(f"  IP destino  : {ip['ip_destino']}")
        # Imprime el TTL (tiempo de vida del paquete)
        print(f"  TTL         : {ip['ttl']}")
        # Imprime el protocolo (TCP, UDP, ICMP, etc.)
        print(f"  Protocolo   : {ip['protocolo']}")

    # Verifica si existe información de TCP
    if "tcp" in datos:
        # Guarda los datos TCP en una variable
        tcp = datos["tcp"]
        # Imprime salto de línea + separador
        print("\n" + "=" * 50)
        # Imprime el título de la capa 4 (TCP)
        print("CAPA 4 - TCP")
        # Imprime separador
        print("=" * 50)
        # Imprime el puerto de origen
        print(f"  Puerto origen  : {tcp['puerto_origen']}")
        # Imprime el puerto de destino
        print(f"  Puerto destino : {tcp['puerto_destino']}")
        # Imprime el número de secuencia
        print(f"  Secuencia      : {tcp['secuencia']}")
        # Imprime el número de acuse (ACK)
        print(f"  Acuse (ACK)    : {tcp['ack']}")
        # Imprime los flags del paquete TCP
        print(f"  Flags          : {tcp['flags']}")

    # Si no es TCP, verifica si es UDP
    elif "udp" in datos:
        # Guarda los datos UDP
        udp = datos["udp"]
        # Imprime salto de línea + separador
        print("\n" + "=" * 50)
        # Imprime el título UDP
        print("CAPA 4 - UDP")
        # Imprime separador
        print("=" * 50)
        # Imprime puerto de origen
        print(f"  Puerto origen  : {udp['puerto_origen']}")
        # Imprime puerto de destino
        print(f"  Puerto destino : {udp['puerto_destino']}")
        # Imprime la longitud del segmento UDP
        print(f"  Longitud       : {udp['longitud']}")

    # Si no es UDP, verifica si es ICMP
    elif "icmp" in datos:
        # Guarda los datos ICMP
        icmp = datos["icmp"]
        # Imprime salto de línea + separador
        print("\n" + "=" * 50)
        # Imprime título ICMP (capa intermedia)
        print("CAPA 3.5 - ICMP")
        # Imprime separador
        print("=" * 50)
        # Imprime el tipo de mensaje ICMP
        print(f"  Tipo   : {icmp['tipo']}")
        # Imprime el código ICMP
        print(f"  Código : {icmp['codigo']}")

    # Verifica si existe payload (datos)
    if "payload" in datos:
        # Imprime salto de línea + separador
        print("\n" + "=" * 50)
        # Imprime título del payload
        print("PAYLOAD (primeros 32 bytes en hex)")
        # Imprime separador
        print("=" * 50)
        # Imprime el contenido del payload en hexadecimal
        print(f"  {datos['payload']}")

    # Imprime un salto de línea final
    print()


# Función para capturar un solo paquete
def capturar_uno():
    # Captura un solo paquete y lo imprime

    # Mensaje indicando que se está esperando un paquete
    print("Esperando un paquete...\n")

    # Define una función interna que será llamada cuando llegue un paquete
    def callback(paquete):
        # Procesa el paquete con la función parse_packet
        datos = parse_packet(paquete)
        # Imprime los datos ya procesados
        _imprimir_paquete(datos)

    # Inicia la captura de paquetes:
    # count=1 → captura solo 1 paquete
    # prn=callback → cada paquete capturado ejecuta la función callback
    sniff(count=1, prn=callback)


paquetes_capturados = []  # lista compartida entre funciones


def _callback_continuo(paquete):
    datos = parse_packet(paquete)
    paquetes_capturados.append(datos)
    num = len(paquetes_capturados)

    # Resumen de una línea por paquete
    ip = datos.get("ipv4", {})
    proto = (
        "TCP"
        if "tcp" in datos
        else "UDP" if "udp" in datos else "ICMP" if "icmp" in datos else "???"
    )
    src = ip.get("ip_origen", "?")
    dst = ip.get("ip_destino", "?")

    print(f"  [{num:>3}]  {proto:<5}  {src:<16}  ->  {dst}")


def capturar_continuo():
    # Captura paquetes sin límite hasta Ctrl+C
    global paquetes_capturados
    paquetes_capturados = []

    print("Captura continua iniciada. Presiona Ctrl+C para detener.\n")
    print(f"  {'#':>3}   {'Protocolo':<5}  {'IP Origen':<16}       IP Destino")
    print("  " + "-" * 50)

    try:
        sniff(prn=_callback_continuo, store=False)
    except KeyboardInterrupt:
        print(f"\nCaptura detenida. Paquetes capturados: {len(paquetes_capturados)}")

    seleccionar_paquete()


def seleccionar_paquete():
    # pide al usuario elegir un paquete y muestra su detalle
    if not paquetes_capturados:
        print("No hay paquetes capturados.")
        return

    while True:
        try:
            entrada = input(
                f"\nIngresa el número del paquete a analizar (1-{len(paquetes_capturados)}), o 0 para salir: "
            )
            num = int(entrada)
            if num == 0:
                break
            if 1 <= num <= len(paquetes_capturados):
                print(f"\nDetalle del paquete #{num}")
                _imprimir_paquete(paquetes_capturados[num - 1])
            else:
                print(
                    f"Número fuera de rango. Elige entre 1 y {len(paquetes_capturados)}."
                )
        except ValueError:
            print("Ingresa un número válido.")
