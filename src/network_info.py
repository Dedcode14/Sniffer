# Permite ejecutar comandos del sistema operativo y capturar su salida
import subprocess

# Permite crear conexiones de red para detectar la IP local como método alternativo
import socket

# Permite detectar en qué sistema operativo se está ejecutando el programa
import platform

# Permite buscar patrones de texto dentro de cadenas (expresiones regulares)
import re


# Detecta el nombre de la interfaz de red que tiene la ruta por defecto,
# es decir, la interfaz que el sistema usa para salir a internet
def _get_default_interface():

    # Obtiene el nombre del sistema operativo: 'Linux', 'Darwin' (macOS) o 'Windows'
    sistema = platform.system()

    try:
        if sistema == "Linux":
            # Ejecuta el comando 'ip route' que muestra la tabla de rutas del sistema
            salida = subprocess.check_output(["ip", "route"], text=True)

            # Recorre cada línea de la tabla de rutas buscando la ruta por defecto
            for linea in salida.splitlines():

                # La ruta por defecto siempre empieza con la palabra 'default'
                if linea.startswith("default"):
                    # Ejemplo de línea: "default via 192.168.1.1 dev wlan0 proto dhcp"
                    partes = linea.split()  # divide la línea en palabras

                    # Busca la posición de la palabra 'dev' que precede al nombre de interfaz
                    idx = partes.index("dev")

                    # La interfaz es la palabra inmediatamente después de 'dev'
                    return partes[idx + 1]

        elif sistema == "Darwin":  # macOS usa el comando 'route' para obtener la ruta
            salida = subprocess.check_output(["route", "-n", "get", "default"], text=True)

            # Busca la línea que contiene 'interface:' con el nombre de la interfaz
            for linea in salida.splitlines():
                if "interface:" in linea:
                    # Divide por ':' y toma la parte derecha eliminando espacios
                    return linea.split(":")[1].strip()

        elif sistema == "Windows":
            # Usa PowerShell para obtener la ruta con menor métrica (la ruta preferida)
            salida = subprocess.check_output(
                ["powershell", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                 "Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias"],
                text=True
            )
            # Elimina espacios y saltos de línea del resultado
            return salida.strip()

    except Exception:
        # Si cualquier comando falla (no existe, sin permisos, etc.) continúa sin error
        pass

    # Si no se pudo detectar la interfaz devuelve None
    return None


# Obtiene la dirección IP local del dispositivo en la red actual
def get_local_ip(interfaz=None):

    # Detecta el sistema operativo para usar el comando correcto
    sistema = platform.system()

    # Si se proporcionó una interfaz específica intenta obtener su IP directamente
    if interfaz:
        try:
            if sistema == "Linux":
                # Muestra la información de direcciones IPv4 de la interfaz indicada
                salida = subprocess.check_output(
                    ["ip", "-4", "addr", "show", interfaz], text=True
                )
                # Busca el patrón "inet X.X.X.X" en la salida del comando
                match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", salida)
                if match:
                    # Devuelve solo la IP extraída del patrón encontrado
                    return match.group(1)

            elif sistema == "Darwin":
                # En macOS ipconfig getifaddr devuelve directamente la IP de la interfaz
                salida = subprocess.check_output(
                    ["ipconfig", "getifaddr", interfaz], text=True
                )
                return salida.strip()  # elimina saltos de línea y espacios

            elif sistema == "Windows":
                # PowerShell obtiene la IP de la interfaz filtrando solo IPv4
                salida = subprocess.check_output(
                    ["powershell", "-Command",
                     f"(Get-NetIPAddress -InterfaceAlias '{interfaz}' "
                     f"-AddressFamily IPv4).IPAddress"],
                    text=True
                )
                return salida.strip()

        except Exception:
            # Si el comando falla continúa hacia el método alternativo
            pass

    # Método alternativo: abre un socket UDP hacia Google DNS sin enviar datos
    # El sistema operativo asigna automáticamente la IP de salida al socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # no envía datos, solo determina la ruta
            return s.getsockname()[0]   # devuelve la IP local asignada al socket
    except Exception:
        return "No disponible"  # si todo falla devuelve un mensaje de error


# Obtiene la dirección MAC de la interfaz de red que sale a internet
def get_mac_address(interfaz=None):

    # Detecta el sistema operativo para usar el método correcto
    sistema = platform.system()

    # Si se proporcionó una interfaz específica intenta leer su MAC directamente
    if interfaz:
        try:
            if sistema == "Linux":
                # En Linux la MAC de cada interfaz está en un archivo del sistema de archivos virtual
                salida = subprocess.check_output(
                    ["cat", f"/sys/class/net/{interfaz}/address"], text=True
                )
                return salida.strip()  # la MAC ya viene en formato xx:xx:xx:xx:xx:xx

            elif sistema == "Darwin":
                # ifconfig muestra toda la configuración de la interfaz incluyendo la MAC
                salida = subprocess.check_output(
                    ["ifconfig", interfaz], text=True
                )
                # Busca el patrón "ether XX:XX:XX:XX:XX:XX" en la salida
                match = re.search(r"ether\s+([0-9a-f:]{17})", salida)
                if match:
                    return match.group(1)  # devuelve solo los 17 caracteres de la MAC

            elif sistema == "Windows":
                # PowerShell obtiene la MAC del adaptador por su nombre de interfaz
                salida = subprocess.check_output(
                    ["powershell", "-Command",
                     f"(Get-NetAdapter -Name '{interfaz}').MacAddress"],
                    text=True
                )
                # Windows devuelve la MAC con guiones (XX-XX-XX), se normaliza a dos puntos
                return salida.strip().replace("-", ":")

        except Exception:
            # Si el comando falla continúa hacia el método alternativo
            pass

    # Método alternativo: usa el módulo uuid que puede obtener la MAC de alguna interfaz activa
    try:
        import uuid  # importación local ya que solo se usa como respaldo
        mac_int = uuid.getnode()  # devuelve la MAC como un entero de 48 bits

        # Convierte el entero a formato legible xx:xx:xx:xx:xx:xx extrayendo byte a byte
        mac_str = ":".join(
            f"{(mac_int >> (5 - i) * 8) & 0xFF:02x}" for i in range(6)
        )
        return mac_str
    except Exception:
        return "No disponible"  # si todo falla devuelve un mensaje de error


# Obtiene el nombre (SSID) de la red Wi-Fi a la que está conectado el dispositivo
def get_ssid():

    # Detecta el sistema operativo para usar el comando correcto
    sistema = platform.system()

    try:
        if sistema == "Linux":
            # Primer intento: iwgetid es una herramienta simple y rápida para obtener el SSID
            try:
                salida = subprocess.check_output(
                    ["iwgetid", "-r"],          # -r devuelve solo el nombre del SSID
                    text=True,
                    stderr=subprocess.DEVNULL  # suprime mensajes de error en consola
                )
                ssid = salida.strip()
                if ssid:  # si devolvió un valor no vacío es el SSID activo
                    return ssid
            except FileNotFoundError:
                # iwgetid no está instalado en el sistema, intenta con nmcli
                pass

            # Segundo intento: nmcli es la herramienta de NetworkManager, más común en distribuciones modernas
            salida = subprocess.check_output(
                ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],  # -t modo tabular, -f campos específicos
                text=True,
                stderr=subprocess.DEVNULL,
            )
            # Cada línea tiene el formato "yes:NombreRed" o "no:NombreRed"
            for linea in salida.splitlines():
                if linea.startswith("yes:"):  # solo la red activa empieza con "yes:"
                    return linea.split(":", 1)[1]  # devuelve el SSID después del primer ':'

        elif sistema == "Darwin":
            # macOS tiene una herramienta privada llamada 'airport' para información Wi-Fi
            salida = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework"
                 "/Versions/Current/Resources/airport", "-I"],  # -I muestra info de la conexión actual
                text=True,
                stderr=subprocess.DEVNULL,
            )
            # Busca la línea que contiene "SSID:" en la salida
            for linea in salida.splitlines():
                linea = linea.strip()  # elimina espacios al inicio y al final
                if linea.startswith("SSID:"):
                    # Divide por ':' y toma la parte derecha con el nombre de la red
                    return linea.split(":", 1)[1].strip()

        elif sistema == "Windows":
            # netsh es la herramienta de red de Windows que muestra información de interfaces Wi-Fi
            salida = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            # Busca la línea que contiene "SSID" pero no "BSSID" (BSSID es la MAC del router)
            for linea in salida.splitlines():
                if "SSID" in linea and "BSSID" not in linea:
                    partes = linea.split(":", 1)  # divide en máximo 2 partes por el primer ':'
                    if len(partes) == 2:
                        return partes[1].strip()  # devuelve el nombre de la red sin espacios

    except Exception:
        # Si cualquier comando falla continúa hacia el valor por defecto
        pass

    # Si no se detectó Wi-Fi activa el dispositivo probablemente usa Ethernet
    return "Ethernet / No disponible"


# Función principal del módulo que reúne toda la información de red en un solo diccionario
def get_network_info():

    # Detecta primero la interfaz por defecto ya que las demás funciones la necesitan
    interfaz = _get_default_interface()

    # Devuelve un diccionario con los cuatro campos de información de red
    return {
        "ssid": get_ssid(),               # nombre de la red Wi-Fi activa
        "mac": get_mac_address(interfaz), # MAC de la interfaz que sale a internet
        "ip_local": get_local_ip(interfaz), # IP local del dispositivo en la red
        "interfaz": interfaz or "desconocida",  # nombre de la interfaz, o 'desconocida' si no se detectó
    }
