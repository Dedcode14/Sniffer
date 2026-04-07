#importa las clases necesarias para analizar paquetes de red
from scapy.all import Ether, IP, TCP, UDP, ICMP


#Definición de la función parse_packet que recibe un paquete de Scapy
def parse_packet(paquete):
    #Recibe un paquete de Scapy y devuelve un diccionario
    #con los campos de cada capa identificada
    
    #Se crea un diccionario vacío donde se guardará la información del paquete
    resultado = {}

    #Capa 2 - Ethernet
    #Verifica si el paquete contiene la capa Ethernet
    if paquete.haslayer(Ether):
        #Extrae la capa Ethernet del paquete
        eth = paquete[Ether]
        #Guarda los datos relevantes en el diccionario resultado
        resultado['ethernet'] = {
            #'mac_origen' guarda la dirección MAC de origen
            'mac_origen' : eth.src,
            #'mac_destino' guarda la dirección MAC de destino
            'mac_destino': eth.dst,
            #'protocolo' guarda el tipo de protocolo en formato hexadecimal
            'protocolo'  : hex(eth.type),
        }

    #Capa 3 - IPv4
    #Verifica si el paquete contiene la capa IP
    if paquete.haslayer(IP):
        #Extrae la capa IP
        ip = paquete[IP]
        #Guarda los datos IP en el diccionario
        resultado['ipv4'] = {
            #'ip_origen' dirección IP de origen
            'ip_origen'  : ip.src,
            #'ip_destino' dirección IP de destino
            'ip_destino' : ip.dst,
            #'ttl' tiempo de vida del paquete
            'ttl'        : ip.ttl,
            #'protocolo' indica el protocolo de la capa superior (TCP, UDP, etc.)
            'protocolo'  : ip.proto,
        }

    #Capa 4 - TCP
    #Verifica si el paquete contiene TCP
    if paquete.haslayer(TCP):
        #Extrae la capa TCP
        tcp = paquete[TCP]
        #Guarda los datos TCP en el diccionario
        resultado['tcp'] = {
            #'puerto_origen' puerto de origen
            'puerto_origen' : tcp.sport,
            #'puerto_destino' puerto de destino
            'puerto_destino': tcp.dport,
            #'secuencia' número de secuencia
            'secuencia'     : tcp.seq,
            #'ack' número de acuse de recibo
            'ack'           : tcp.ack,
            #'flags' banderas TCP convertidas a string
            'flags'         : str(tcp.flags),
        }

    #Capa 4 - UDP
    #Si no es TCP, verifica si es UDP
    elif paquete.haslayer(UDP):
        #Extrae la capa UDP
        udp = paquete[UDP]
        #Guarda los datos UDP
        resultado['udp'] = {
            #'puerto_origen' puerto de origen
            'puerto_origen' : udp.sport,
            #'puerto_destino' puerto de destino
            'puerto_destino': udp.dport,
            #'longitud' tamaño del segmento UDP
            'longitud'      : udp.len,
        }

    #ICMP
    #Si no es UDP, verifica si es ICMP
    elif paquete.haslayer(ICMP):
        #Extrae la capa ICMP
        icmp = paquete[ICMP]
        #Guarda los datos ICMP
        resultado['icmp'] = {
            #'tipo' tipo de mensaje ICMP
            'tipo'  : icmp.type,
            #'codigo' código ICMP
            'codigo': icmp.code,
        }

    #Verifica si existe carga útil (datos)
    if paquete.haslayer('Raw'):
        #Convierte el payload a bytes
        raw = bytes(paquete['Raw'])
        #Convierte los primeros 32 bytes a formato hexadecimal separados por espacio
        resultado['payload'] = ' '.join(f'{b:02x}' for b in raw[:32])

    #Retorna el diccionario con toda la información extraída
    return resultado