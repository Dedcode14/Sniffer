import threading
from PyQt5.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QLabel,
    QPushButton,
    QTextEdit,
    QHeaderView,
    QFrame,
    QSplitter,
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor
from scapy.all import sniff
from parser import parse_packet
from gui_styles import STYLE, PROTO_COLORS


class Signals(QObject):
    nuevo_paquete = pyqtSignal(dict)


class SnifferWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Proyecto Sniffer | Equipo 2")
        self.setMinimumSize(1000, 620)
        self.paquetes = []
        self.capturando = False
        self.signals = Signals()
        self.signals.nuevo_paquete.connect(self._agregar_fila)
        self._build_ui()
        self.setStyleSheet(STYLE)

    # --- Construcción de la UI ---

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)

        layout.addLayout(self._build_top_bar())
        layout.addWidget(self._build_status_label())
        layout.addWidget(self._build_separator())
        layout.addWidget(self._build_splitter())

    def _build_top_bar(self):
        top = QHBoxLayout()

        titulo = QLabel("Proyecto Sniffer | Equipo 2")
        titulo.setObjectName("label_title")
        top.addWidget(titulo)
        top.addStretch()

        self.btn_start = QPushButton("▶  Iniciar captura")
        self.btn_stop = QPushButton("■  Detener")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setEnabled(False)
        self.btn_start.clicked.connect(self._iniciar)
        self.btn_stop.clicked.connect(self._detener)
        top.addWidget(self.btn_start)
        top.addWidget(self.btn_stop)

        return top

    def _build_status_label(self):
        self.label_status = QLabel("Listo.")
        self.label_status.setObjectName("label_status")
        return self.label_status

    def _build_separator(self):
        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        return sep

    def _build_splitter(self):
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self._build_tabla())
        splitter.addWidget(self._build_detalle())
        splitter.setSizes([350, 250])
        return splitter

    def _build_tabla(self):
        self.tabla = QTableWidget()
        self.tabla.setColumnCount(5)
        self.tabla.setHorizontalHeaderLabels(
            ["#", "Protocolo", "IP Origen", "IP Destino", "Info"]
        )
        self.tabla.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.tabla.horizontalHeader().setDefaultSectionSize(130)
        self.tabla.setColumnWidth(0, 50)
        self.tabla.setColumnWidth(1, 90)
        self.tabla.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tabla.setSelectionBehavior(QTableWidget.SelectRows)
        self.tabla.verticalHeader().setVisible(False)
        self.tabla.setAlternatingRowColors(False)
        self.tabla.itemSelectionChanged.connect(self._mostrar_detalle)
        return self.tabla

    def _build_detalle(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 8, 0, 0)

        label = QLabel("Detalle del paquete")
        label.setObjectName("label_detail_title")
        layout.addWidget(label)

        self.detalle = QTextEdit()
        self.detalle.setReadOnly(True)
        self.detalle.setPlaceholderText(
            "Selecciona un paquete de la tabla para ver su detalle..."
        )
        layout.addWidget(self.detalle)

        return widget

    # --- Captura ---

    def _iniciar(self):
        self.paquetes.clear()
        self.tabla.setRowCount(0)
        self.detalle.clear()
        self.capturando = True
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.label_status.setText("Capturando paquetes...")
        threading.Thread(target=self._hilo_captura, daemon=True).start()

    def _hilo_captura(self):
        sniff(
            prn=self._procesar_paquete,
            store=False,
            stop_filter=lambda _: not self.capturando,
        )

    def _procesar_paquete(self, paquete):
        datos = parse_packet(paquete)
        if not datos:
            return
        self.paquetes.append(datos)
        self.signals.nuevo_paquete.emit(datos)

    def _detener(self):
        self.capturando = False
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.label_status.setText(
            f"Captura detenida.  Paquetes capturados: {len(self.paquetes)}"
        )

    # --- Tabla ---

    def _agregar_fila(self, datos):
        ip = datos.get("ipv4", {})
        src = ip.get("Source IP Address", "—")
        dst = ip.get("Destination IP Address", "—")

        if "tcp" in datos:
            proto = "TCP"
            d = datos["tcp"]
            info = f"Puerto {d['puerto_origen']} → {d['puerto_destino']}  Flags: {d['flags']}"
        elif "udp" in datos:
            proto = "UDP"
            d = datos["udp"]
            info = f"Puerto {d['puerto_origen']} → {d['puerto_destino']}  Len: {d['longitud']}"
        elif "icmp" in datos:
            proto = "ICMP"
            d = datos["icmp"]
            info = f"Tipo: {d['tipo']}  Código: {d['codigo']}"
        else:
            proto = "???"
            info = "—"

        num = self.tabla.rowCount()
        self.tabla.insertRow(num)

        for col, texto in enumerate([str(num + 1), proto, src, dst, info]):
            item = QTableWidgetItem(texto)
            item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            if col == 1:
                item.setForeground(QColor(PROTO_COLORS.get(proto, "#cdd6f4")))
                font = QFont()
                font.setBold(True)
                item.setFont(font)
            self.tabla.setItem(num, col, item)

        self.tabla.scrollToBottom()

    # --- Detalle ---

    def _mostrar_detalle(self):
        if not self.tabla.selectedItems():
            return
        idx = self.tabla.currentRow()
        if idx >= len(self.paquetes):
            return

        datos = self.paquetes[idx]
        lineas = []

        if "ethernet" in datos:
            e = datos["ethernet"]
            lineas += [
                " ---------- FRAME ETHERNET ----------",
                f"  PRE  (Preamble)          : {e['PRE']}",
                f"  SFD  (Start Frame Delim) : {e['SFD']}",
                f"  DAD  (Dest. Address)     : {e['DAD']}",
                f"  SAD  (Source Address)    : {e['SAD']}",
                f"  LNG  (EtherType/Length)  : {e['LNG']}",
                f"  FCS  (Frame Check Seq.)  : {e['FCS']}",
                "",
            ]

        if "ipv4" in datos:
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

        if "tcp" in datos:
            t = datos["tcp"]
            lineas += [
                " --------------- TCP --------------- ",
                f"  Puerto Origen  : {t['puerto_origen']}",
                f"  Puerto Destino : {t['puerto_destino']}",
                f"  Secuencia      : {t['secuencia']}",
                f"  ACK            : {t['ack']}",
                f"  Flags          : {t['flags']}",
                "",
            ]
        elif "udp" in datos:
            u = datos["udp"]
            lineas += [
                " --------------- UDP --------------- ",
                f"  Puerto Origen  : {u['puerto_origen']}",
                f"  Puerto Destino : {u['puerto_destino']}",
                f"  Longitud       : {u['longitud']}",
                "",
            ]
        elif "icmp" in datos:
            ic = datos["icmp"]
            lineas += [
                " --------------- ICMP ---------------",
                f"  Tipo   : {ic['tipo']}",
                f"  Código : {ic['codigo']}",
                "",
            ]

        if "payload" in datos:
            lineas += [
                " ---------- DATA / PAYLOAD ----------",
                f"  {datos['payload']}",
                "",
            ]

        self.detalle.setText("\n".join(lineas))
