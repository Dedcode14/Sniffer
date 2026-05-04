import sys
import threading
from PyQt5.QtWidgets import (
    QApplication,
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

# ── Estilos ───────────────────────────────────────────────────────────────────

STYLE = """
    QMainWindow, QWidget {
        background-color: #1e1e2e;
        color: #cdd6f4;
        font-family: Arial;
        font-size: 13px;
    }
    QTableWidget {
        background-color: #181825;
        color: #cdd6f4;
        border: 1px solid #313244;
        gridline-color: #313244;
        selection-background-color: #45475a;
    }
    QTableWidget::item:selected {
        background-color: #45475a;
        color: #cdd6f4;
    }
    QHeaderView::section {
        background-color: #313244;
        color: #cdd6f4;
        padding: 6px;
        border: none;
        font-weight: bold;
    }
    QPushButton {
        background-color: #89b4fa;
        color: #1e1e2e;
        border: none;
        padding: 8px 20px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 13px;
    }
    QPushButton:hover {
        background-color: #b4befe;
    }
    QPushButton:disabled {
        background-color: #45475a;
        color: #6c7086;
    }
    QPushButton#btn_stop {
        background-color: #f38ba8;
        color: #1e1e2e;
    }
    QPushButton#btn_stop:hover {
        background-color: #eba0ac;
    }
    QTextEdit {
        background-color: #181825;
        color: #cdd6f4;
        border: 1px solid #313244;
        border-radius: 4px;
        padding: 8px;
        font-family: Consolas, monospace;
        font-size: 12px;
    }
    QLabel#label_title {
        font-size: 18px;
        font-weight: bold;
        color: #89b4fa;
        padding: 8px 0px;
    }
    QLabel#label_status {
        color: #a6e3a1;
        font-size: 12px;
        padding: 4px;
    }
    QLabel#label_detail_title {
        font-size: 14px;
        font-weight: bold;
        color: #cba6f7;
        padding: 4px 0px;
    }
    QFrame#separator {
        background-color: #313244;
    }
"""

PROTO_COLORS = {
    "TCP": "#89b4fa",
    "UDP": "#a6e3a1",
    "ICMP": "#fab387",
}

# ── Señales ───────────────────────────────────────────────────────────────────


class Signals(QObject):
    nuevo_paquete = pyqtSignal(dict)


# ── Ventana principal ─────────────────────────────────────────────────────────


class SnifferWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Sniffer")
        self.setMinimumSize(1000, 620)
        self.paquetes = []
        self.capturando = False
        self.signals = Signals()
        self.signals.nuevo_paquete.connect(self._agregar_fila)
        self._build_ui()
        self.setStyleSheet(STYLE)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)

        # Título y botones
        top = QHBoxLayout()
        titulo = QLabel("Network Sniffer")
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
        layout.addLayout(top)

        # Estado
        self.label_status = QLabel("Listo.")
        self.label_status.setObjectName("label_status")
        layout.addWidget(self.label_status)

        # Separador
        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        layout.addWidget(sep)

        # Splitter: tabla arriba, detalle abajo
        splitter = QSplitter(Qt.Vertical)

        # Tabla de paquetes
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
        splitter.addWidget(self.tabla)

        # Panel de detalle
        detalle_widget = QWidget()
        detalle_layout = QVBoxLayout(detalle_widget)
        detalle_layout.setContentsMargins(0, 8, 0, 0)
        detalle_label = QLabel("Detalle del paquete")
        detalle_label.setObjectName("label_detail_title")
        detalle_layout.addWidget(detalle_label)
        self.detalle = QTextEdit()
        self.detalle.setReadOnly(True)
        self.detalle.setPlaceholderText(
            "Selecciona un paquete de la tabla para ver su detalle..."
        )
        detalle_layout.addWidget(self.detalle)
        splitter.addWidget(detalle_widget)

        splitter.setSizes([350, 250])
        layout.addWidget(splitter)

    # ── Captura ───────────────────────────────────────────────────────────────

    def _iniciar(self):
        self.paquetes.clear()
        self.tabla.setRowCount(0)
        self.detalle.clear()
        self.capturando = True
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.label_status.setText("Capturando paquetes...")

        hilo = threading.Thread(target=self._hilo_captura, daemon=True)
        hilo.start()

    def _hilo_captura(self):
        sniff(
            prn=self._procesar_paquete,
            store=False,
            stop_filter=lambda _: not self.capturando,
        )

    def _procesar_paquete(self, paquete):
        datos = parse_packet(paquete)
        self.paquetes.append(datos)
        self.signals.nuevo_paquete.emit(datos)

    def _detener(self):
        self.capturando = False
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        total = len(self.paquetes)
        self.label_status.setText(f"Captura detenida.  Paquetes capturados: {total}")

    # ── Tabla ─────────────────────────────────────────────────────────────────

    def _agregar_fila(self, datos):
        ip = datos.get("ipv4", {})
        src = ip.get("ip_origen", "—")
        dst = ip.get("ip_destino", "—")

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

        items = [str(num + 1), proto, src, dst, info]
        for col, texto in enumerate(items):
            item = QTableWidgetItem(texto)
            item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            if col == 1:
                color = PROTO_COLORS.get(proto, "#cdd6f4")
                item.setForeground(QColor(color))
                font = QFont()
                font.setBold(True)
                item.setFont(font)
            self.tabla.setItem(num, col, item)

        self.tabla.scrollToBottom()

    # ── Detalle ───────────────────────────────────────────────────────────────

    def _mostrar_detalle(self):
        filas = self.tabla.selectedItems()
        if not filas:
            return
        idx = self.tabla.currentRow()
        if idx >= len(self.paquetes):
            return

        datos = self.paquetes[idx]
        lineas = []

        if "ethernet" in datos:
            e = datos["ethernet"]
            lineas += [
                "── ETHERNET ─────────────────────────",
                f"  MAC Origen  : {e['mac_origen']}",
                f"  MAC Destino : {e['mac_destino']}",
                f"  EtherType   : {e['protocolo']}",
                "",
            ]
        if "ipv4" in datos:
            ip = datos["ipv4"]
            lineas += [
                "── IPv4 ──────────────────────────────",
                f"  IP Origen   : {ip['ip_origen']}",
                f"  IP Destino  : {ip['ip_destino']}",
                f"  TTL         : {ip['ttl']}",
                f"  Protocolo   : {ip['protocolo']}",
                "",
            ]
        if "tcp" in datos:
            t = datos["tcp"]
            lineas += [
                "── TCP ───────────────────────────────",
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
                "── UDP ───────────────────────────────",
                f"  Puerto Origen  : {u['puerto_origen']}",
                f"  Puerto Destino : {u['puerto_destino']}",
                f"  Longitud       : {u['longitud']}",
                "",
            ]
        elif "icmp" in datos:
            ic = datos["icmp"]
            lineas += [
                "── ICMP ──────────────────────────────",
                f"  Tipo   : {ic['tipo']}",
                f"  Código : {ic['codigo']}",
                "",
            ]
        if "payload" in datos:
            lineas += [
                "── PAYLOAD ───────────────────────────",
                f"  {datos['payload']}",
                "",
            ]

        self.detalle.setText("\n".join(lineas))


# ── Entry point ───────────────────────────────────────────────────────────────


def iniciar_gui():
    app = QApplication(sys.argv)
    ventana = SnifferWindow()
    ventana.show()
    sys.exit(app.exec_())
