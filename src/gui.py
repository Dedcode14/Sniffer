import sys
from PyQt5.QtWidgets import QApplication
from gui_window import SnifferWindow


def iniciar_gui():
    app = QApplication(sys.argv)
    ventana = SnifferWindow()
    ventana.show()
    sys.exit(app.exec_())
