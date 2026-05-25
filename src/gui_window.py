import threading  # para ejecutar la captura en un hilo separado sin bloquear la interfaz
from PyQt5.QtWidgets import (
    QMainWindow,  # ventana principal de la aplicación
    QWidget,  # widget base para contenedores
    QVBoxLayout,  # layout vertical
    QHBoxLayout,  # layout horizontal
    QTableWidget,  # tabla de paquetes
    QTableWidgetItem,  # celda individual de la tabla
    QLabel,  # etiqueta de texto
    QPushButton,  # botón
    QTextEdit,  # área de texto para el detalle del paquete
    QHeaderView,  # encabezado de la tabla
    QFrame,  # marco usado como separador visual
    QSplitter,  # divisor ajustable entre tabla y detalle
    QComboBox,  # lista desplegable para el filtro de protocolo
)
from PyQt5.QtCore import (
    Qt,
    pyqtSignal,
    QObject,
)  # constantes de alineación, señales y objeto base
from PyQt5.QtGui import QFont, QColor  # fuente y color para celdas de la tabla
from scapy.all import sniff  # función de captura de paquetes
from parser import parse_packet  # función que disecciona cada paquete
from gui_styles import STYLE, PROTO_COLORS  # estilos CSS y colores por protocolo
from network_info import get_network_info   # información de red del dispositivo


# Clase auxiliar para emitir señales entre el hilo de captura y la interfaz gráfica
class Signals(QObject):
    nuevo_paquete = pyqtSignal(
        dict
    )  # señal que transporta los datos de un paquete parseado


# Clase principal de la ventana
class SnifferWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Proyecto Sniffer | Equipo 2")  # título de la ventana
        self.setMinimumSize(1000, 620)  # tamaño mínimo de la ventana
        self.paquetes = []  # lista que almacena todos los paquetes capturados
        self.capturando = False  # bandera que indica si la captura está activa
        self.signals = Signals()  # instancia de señales para comunicación entre hilos
        self.signals.nuevo_paquete.connect(
            self._agregar_fila
        )  # conecta la señal al método que agrega filas
        self._build_ui()  # construye todos los elementos visuales
        self.setStyleSheet(STYLE)  # aplica los estilos CSS a la ventana

    # Construye el layout principal y agrega cada sección de la interfaz
    def _build_ui(self):
        central = QWidget()  # widget contenedor central
        self.setCentralWidget(central)  # lo asigna como widget principal de la ventana
        layout = QVBoxLayout(central)  # layout vertical que apila las secciones
        layout.setContentsMargins(16, 12, 16, 12)  # márgenes internos de la ventana
        layout.setSpacing(10)  # espacio entre secciones

        layout.addLayout(
            self._build_top_bar()
        )  # agrega la barra superior con título y botones
        layout.addWidget(self._build_network_info_bar())  # agrega la barra de info de red
        layout.addWidget(self._build_status_label())  # agrega la etiqueta de estado
        layout.addLayout(self._build_filtro())  # agrega el filtro de protocolo
        layout.addWidget(self._build_separator())  # agrega la línea separadora
        layout.addWidget(
            self._build_splitter()
        )  # agrega el splitter con tabla y detalle

    # Construye la barra superior con el título y los botones de captura
    def _build_top_bar(self):
        top = QHBoxLayout()  # layout horizontal para alinear título y botones

        titulo = QLabel(
            "Proyecto Sniffer | Equipo 2"
        )  # etiqueta con el nombre del proyecto
        titulo.setObjectName("label_title")  # nombre para aplicar estilo CSS
        top.addWidget(titulo)
        top.addStretch()  # espacio flexible que empuja los botones hacia la derecha

        self.btn_start = QPushButton(
            "▶  Iniciar captura"
        )  # botón para iniciar la captura
        self.btn_stop = QPushButton("■  Detener")  # botón para detener la captura
        self.btn_stop.setObjectName("btn_stop")  # nombre para aplicar estilo CSS rojo
        self.btn_stop.setEnabled(False)  # deshabilitado al inicio
        self.btn_start.clicked.connect(
            self._iniciar
        )  # conecta el clic al método de inicio
        self.btn_stop.clicked.connect(
            self._detener
        )  # conecta el clic al método de detención
        top.addWidget(self.btn_start)
        top.addWidget(self.btn_stop)

        return top

    # Construye la barra de información de red del dispositivo (SSID, MAC, IP local)
    def _build_network_info_bar(self):
        info = get_network_info()  # obtiene los datos de red al arrancar la ventana

        bar = QWidget()  # contenedor principal de la barra de información
        bar.setObjectName("network_info_bar")  # nombre para aplicar estilo CSS
        layout = QHBoxLayout(bar)  # layout horizontal para alinear los campos en fila
        layout.setContentsMargins(10, 6, 10, 6)  # márgenes internos de la barra
        layout.setSpacing(24)  # espacio horizontal entre cada campo de información

        # Función auxiliar interna que construye un par etiqueta + valor para cada campo
        def _campo(etiqueta, valor, color="#cdd6f4"):
            h = QHBoxLayout()  # layout horizontal que agrupa la etiqueta y su valor
            h.setSpacing(6)  # espacio entre la etiqueta descriptiva y el valor
            lbl = QLabel(etiqueta)  # etiqueta fija con el nombre del campo (ej. "IP local:")
            lbl.setObjectName("net_info_label")  # nombre para aplicar estilo CSS gris apagado
            val = QLabel(valor)  # etiqueta dinámica que muestra el valor actual del campo
            val.setObjectName("net_info_value")  # nombre para aplicar estilo CSS al valor
            val.setStyleSheet(f"color: {color}; font-weight: bold;")  # color único por campo y negrita
            h.addWidget(lbl)  # agrega la etiqueta fija al layout del campo
            h.addWidget(val)  # agrega el valor dinámico al layout del campo
            return h, val  # devuelve también el QLabel del valor para poder actualizarlo después

        # Crea el campo SSID con color verde y guarda referencia al QLabel para actualizarlo
        h_ssid, self.val_ssid = _campo(
            "📶  Red (SSID):", info["ssid"], "#a6e3a1"
        )
        # Crea el campo MAC con color azul y guarda referencia al QLabel para actualizarlo
        h_mac, self.val_mac = _campo(
            "🔌  MAC salida:", info["mac"], "#89b4fa"
        )
        # Crea el campo IP local con color amarillo y guarda referencia al QLabel para actualizarlo
        h_ip, self.val_ip = _campo(
            "🖥️  IP local:", info["ip_local"], "#f9e2af"
        )
        # Crea el campo Interfaz con color morado y guarda referencia al QLabel para actualizarlo
        h_iface, self.val_iface = _campo(
            "📡  Interfaz:", info["interfaz"], "#cba6f7"
        )

        # Agrega los cuatro campos al layout principal de la barra en orden
        for h in (h_ssid, h_mac, h_ip, h_iface):
            layout.addLayout(h)

        layout.addStretch()  # espacio flexible que empuja el botón Refrescar hacia la derecha

        # Botón para refrescar la información de red manualmente
        btn_refresh = QPushButton("⟳  Refrescar")  # botón con ícono de recarga
        btn_refresh.setFixedWidth(110)  # ancho fijo para que no se estire con el layout
        btn_refresh.clicked.connect(self._refrescar_network_info)  # conecta el clic al método de refresco
        layout.addWidget(btn_refresh)  # agrega el botón al extremo derecho de la barra

        # Aplica un fondo ligeramente diferente para distinguir la barra
        bar.setStyleSheet(
            "#network_info_bar { background-color: #181825; border-radius: 6px; }"  # fondo oscuro con bordes redondeados
            "QLabel#net_info_label { color: #6c7086; font-size: 12px; }"            # etiquetas fijas en gris apagado
            "QLabel#net_info_value { font-size: 12px; }"                             # valores con tamaño de fuente uniforme
        )

        return bar  # devuelve el widget completo de la barra para agregarlo al layout principal

    # Refresca los valores de SSID, MAC e IP consultando el sistema nuevamente
    def _refrescar_network_info(self):
        info = get_network_info()  # vuelve a consultar toda la información de red del sistema
        self.val_ssid.setText(info["ssid"])      # actualiza el texto del campo SSID en pantalla
        self.val_mac.setText(info["mac"])        # actualiza el texto del campo MAC en pantalla
        self.val_ip.setText(info["ip_local"])    # actualiza el texto del campo IP local en pantalla
        self.val_iface.setText(info["interfaz"]) # actualiza el texto del campo Interfaz en pantalla
    def _build_status_label(self):
        self.label_status = QLabel("Listo.")  # texto inicial
        self.label_status.setObjectName(
            "label_status"
        )  # nombre para aplicar estilo CSS
        return self.label_status

    # Construye el filtro desplegable de protocolo
    def _build_filtro(self):
        filtro_layout = QHBoxLayout()  # layout horizontal para alinear etiqueta y combo

        label = QLabel("Filtrar por protocolo:")  # etiqueta descriptiva del filtro
        self.combo_filtro = QComboBox()  # lista desplegable con los protocolos
        self.combo_filtro.addItems(
            [  # agrega las opciones disponibles
                "Todos",
                "TCP",
                "UDP",
                "ICMP",
                "DNS",
                "HTTP",
                "TLS",
                "ARP",
                "Desconocido",
            ]
        )
        self.combo_filtro.currentTextChanged.connect(
            self._aplicar_filtro
        )  # aplica el filtro al cambiar selección

        filtro_layout.addWidget(label)
        filtro_layout.addWidget(self.combo_filtro)
        filtro_layout.addStretch()  # espacio flexible para que el combo no ocupe todo el ancho

        return filtro_layout

    # Construye la línea horizontal separadora entre el filtro y la tabla
    def _build_separator(self):
        sep = QFrame()  # frame vacío usado como línea
        sep.setObjectName("separator")  # nombre para aplicar estilo CSS
        sep.setFrameShape(QFrame.HLine)  # forma horizontal
        sep.setFixedHeight(1)  # altura de 1 pixel
        return sep

    # Construye el splitter que divide la tabla y el panel de detalle
    def _build_splitter(self):
        splitter = QSplitter(Qt.Vertical)  # divisor vertical ajustable por el usuario
        splitter.addWidget(self._build_tabla())  # sección superior: tabla de paquetes
        splitter.addWidget(self._build_detalle())  # sección inferior: panel de detalle
        splitter.setSizes([350, 250])  # tamaño inicial de cada sección en píxeles
        return splitter

    # Construye la tabla que muestra el resumen de cada paquete capturado
    def _build_tabla(self):
        self.tabla = QTableWidget()  # tabla editable desactivada
        self.tabla.setColumnCount(5)  # cinco columnas
        self.tabla.setHorizontalHeaderLabels(  # nombres de las columnas
            ["#", "Protocolo", "IP Origen", "IP Destino", "Info"]
        )
        self.tabla.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.Stretch
        )  # columna Info ocupa el espacio restante
        self.tabla.horizontalHeader().setDefaultSectionSize(
            130
        )  # ancho por defecto de columnas
        self.tabla.setColumnWidth(0, 50)  # columna # más estrecha
        self.tabla.setColumnWidth(1, 90)  # columna Protocolo
        self.tabla.setEditTriggers(QTableWidget.NoEditTriggers)  # impide editar celdas
        self.tabla.setSelectionBehavior(
            QTableWidget.SelectRows
        )  # selecciona fila completa
        self.tabla.verticalHeader().setVisible(False)  # oculta números de fila
        self.tabla.setAlternatingRowColors(False)  # sin colores alternos
        self.tabla.itemSelectionChanged.connect(
            self._mostrar_detalle
        )  # muestra detalle al seleccionar
        return self.tabla

    # Construye el panel inferior que muestra el detalle del paquete seleccionado
    def _build_detalle(self):
        widget = QWidget()  # contenedor del panel
        layout = QVBoxLayout(widget)  # layout vertical interno
        layout.setContentsMargins(0, 8, 0, 0)  # margen superior

        label = QLabel("Detalle del paquete")  # título del panel
        label.setObjectName("label_detail_title")  # nombre para estilo CSS
        layout.addWidget(label)

        self.detalle = QTextEdit()  # área de texto de solo lectura
        self.detalle.setReadOnly(True)  # impide edición
        self.detalle.setPlaceholderText(  # texto cuando no hay selección
            "Selecciona un paquete de la tabla para ver su detalle..."
        )
        layout.addWidget(self.detalle)

        return widget

    # Limpia la interfaz e inicia la captura en un hilo separado
    def _iniciar(self):
        self.paquetes.clear()  # vacía la lista de paquetes anteriores
        self.tabla.setRowCount(0)  # limpia la tabla
        self.detalle.clear()  # limpia el panel de detalle
        self.capturando = True  # activa la bandera de captura
        self.btn_start.setEnabled(False)  # deshabilita el botón de inicio
        self.btn_stop.setEnabled(True)  # habilita el botón de detención
        self.label_status.setText("Capturando paquetes...")  # actualiza el estado
        threading.Thread(
            target=self._hilo_captura, daemon=True
        ).start()  # inicia el hilo de captura

    # Ejecuta la captura en segundo plano usando Scapy
    def _hilo_captura(self):
        sniff(
            prn=self._procesar_paquete,  # llama a este método por cada paquete capturado
            store=False,  # no almacena paquetes en memoria de Scapy
            stop_filter=lambda _: not self.capturando,  # detiene la captura cuando la bandera es False
        )

    # Parsea el paquete recibido y lo envía a la interfaz mediante una señal
    def _procesar_paquete(self, paquete):
        datos = parse_packet(paquete)  # disecciona el paquete en capas
        if not datos:  # descarta paquetes vacíos (IPv6 u otros no soportados)
            return
        self.paquetes.append(datos)  # agrega los datos a la lista
        self.signals.nuevo_paquete.emit(
            datos
        )  # emite la señal para actualizar la tabla

    # Detiene la captura y actualiza la interfaz
    def _detener(self):
        self.capturando = False  # desactiva la bandera para detener el hilo
        self.btn_start.setEnabled(True)  # habilita el botón de inicio nuevamente
        self.btn_stop.setEnabled(False)  # deshabilita el botón de detención
        self.label_status.setText(  # muestra el total de paquetes capturados
            f"Captura detenida.  Paquetes capturados: {len(self.paquetes)}"
        )

    # Agrega una nueva fila a la tabla con el resumen del paquete recibido
    def _agregar_fila(self, datos):
        ip = datos.get("ipv4", {})  # extrae datos IPv4 si existen
        src = ip.get("Source IP Address", "—")  # IP origen o guión si no aplica
        dst = ip.get("Destination IP Address", "—")  # IP destino o guión si no aplica
        proto = datos.get(
            "tipo_protocolo", "DESCONOCIDO"
        )  # protocolo detectado por parser

        if "tcp" in datos:  # genera la columna Info para TCP
            d = datos["tcp"]
            info = f"Puerto {d['puerto_origen']} → {d['puerto_destino']}  Flags: {d['flags']}"
        elif "udp" in datos:  # genera la columna Info para UDP
            d = datos["udp"]
            info = f"Puerto {d['puerto_origen']} → {d['puerto_destino']}  Len: {d['longitud']}"
        elif "icmp" in datos:  # genera la columna Info para ICMP
            d = datos["icmp"]
            info = f"Tipo: {d['tipo']}  Código: {d['codigo']}"
        elif "arp" in datos:  # genera la columna Info para ARP y usa IPs del ARP
            d = datos["arp"]
            info = f"{d['operacion']}  {d['ip_origen']} → {d['ip_destino']}"
            src = d["ip_origen"]
            dst = d["ip_destino"]
        else:
            info = "—"  # protocolo sin información adicional

        num = (
            self.tabla.rowCount()
        )  # obtiene el número de filas actuales para el índice
        self.tabla.insertRow(num)  # inserta una nueva fila al final

        for col, texto in enumerate([str(num + 1), proto, src, dst, info]):
            item = QTableWidgetItem(texto)  # crea la celda con el texto
            item.setTextAlignment(
                Qt.AlignVCenter | Qt.AlignLeft
            )  # alineación vertical y horizontal
            if col == 1:  # columna de protocolo recibe color y negrita según el tipo
                item.setForeground(QColor(PROTO_COLORS.get(proto, "#cdd6f4")))
                font = QFont()
                font.setBold(True)
                item.setFont(font)
            self.tabla.setItem(num, col, item)  # inserta la celda en la tabla

        self.tabla.scrollToBottom()  # desplaza la tabla para mostrar el último paquete

    # Muestra el detalle completo del paquete seleccionado en el panel inferior
    def _mostrar_detalle(self):
        if not self.tabla.selectedItems():  # no hace nada si no hay selección
            return
        idx = self.tabla.currentRow()  # índice de la fila seleccionada
        if idx >= len(self.paquetes):  # evita índice fuera de rango
            return

        datos = self.paquetes[idx]  # obtiene los datos del paquete seleccionado
        lineas = [
            f"Paquete #{idx + 1}",  # número del paquete seleccionado
            "═" * 46,  # línea decorativa de separación
            "",
        ]

        if "ethernet" in datos:  # sección Frame Ethernet
            e = datos["ethernet"]
            lineas += [
                " ---------- FRAME ETHERNET ----------",
                f"  PRE  (Preamble)          : {e['PRE']}",
                f"  SFD  (Start Frame Delim) : {e['SFD']}",
                f"  DAD  (Dest. Address)     : {e['DAD']}",
                f"  SAD  (Source Address)    : {e['SAD']}",
                f"  LNG  (EtherType/Length)  : {e['LNG']}",
                f"  DATA                     : {e['DATA']}",
                f"  FCS  (Frame Check Seq.)  : {e['FCS']}",
                f"  Longitud total           : {e['longitud']}",
                "",
            ]

        if "ipv4" in datos:  # sección Datagrama IPv4
            ip = datos["ipv4"]
            lineas += [
                " ---------- DATAGRAMA IPv4 ----------",
                f"  VER                      : {ip['VER']}",
                f"  HLEN                     : {ip['HLEN']}",
                f"  DS   (Diff. Services)    : {ip['DS']}",
                f"  TLEN (Total Length)      : {ip['TLEN']}",
                f"  Identification           : {ip['Identification']}",
                f"  Flags                    : {ip['Flags']}",
                f"  Fragmentation Offset     : {ip['Fragmentation Offset']}",
                f"  TTL                      : {ip['TTL']}",
                f"  Protocol                 : {ip['Protocol']}",
                f"  Checksum                 : {ip['Checksum']}",
                f"  Source IP Address        : {ip['Source IP Address']}",
                f"  Destination IP Address   : {ip['Destination IP Address']}",
                f"  Options                  : {ip['Options']}",
                "",
            ]

        if "arp" in datos:  # sección ARP
            a = datos["arp"]
            lineas += [
                " -------------- ARP ----------------",
                f"  Operación    : {a['operacion']}",
                f"  MAC Origen   : {a['mac_origen']}",
                f"  IP Origen    : {a['ip_origen']}",
                f"  MAC Destino  : {a['mac_destino']}",
                f"  IP Destino   : {a['ip_destino']}",
                "",
            ]

        if "tcp" in datos:  # sección TCP
            t = datos["tcp"]
            lineas += [
                " --------------- TCP ---------------",
                f"  Puerto Origen  : {t['puerto_origen']}",
                f"  Puerto Destino : {t['puerto_destino']}",
                f"  Secuencia      : {t['secuencia']}",
                f"  ACK            : {t['ack']}",
                f"  Flags          : {t['flags']}",
                "",
            ]
        elif "udp" in datos:  # sección UDP
            u = datos["udp"]
            lineas += [
                " --------------- UDP ---------------",
                f"  Puerto Origen  : {u['puerto_origen']}",
                f"  Puerto Destino : {u['puerto_destino']}",
                f"  Longitud       : {u['longitud']}",
                "",
            ]
        elif "icmp" in datos:  # sección ICMP
            ic = datos["icmp"]
            lineas += [
                " --------------- ICMP --------------",
                f"  Tipo   : {ic['tipo']}",
                f"  Código : {ic['codigo']}",
                "",
            ]

        if "payload" in datos:  # sección payload en hexadecimal
            lineas += [
                " ---------- DATA / PAYLOAD ----------",
                f"  {datos['payload']}",
                "",
            ]

        self.detalle.setText(
            "\n".join(lineas)
        )  # une todas las líneas y las muestra en el panel

    # Oculta o muestra filas según el protocolo seleccionado en el filtro
    def _aplicar_filtro(self, seleccion):
        for fila in range(self.tabla.rowCount()):  # recorre todas las filas de la tabla
            if seleccion == "Todos":  # si es Todos, muestra todas las filas
                self.tabla.setRowHidden(fila, False)
            else:
                proto_item = self.tabla.item(fila, 1)  # obtiene la celda de protocolo
                if proto_item:
                    coincide = (
                        proto_item.text().upper() == seleccion.upper()
                    )  # compara el protocolo
                    self.tabla.setRowHidden(fila, not coincide)  # oculta si no coincide
