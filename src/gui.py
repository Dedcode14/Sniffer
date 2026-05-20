# Importa sys para acceder a los argumentos del sistema, necesario para QApplication
import sys

# Importa QApplication, que es el objeto principal de toda aplicación PyQt5
from PyQt5.QtWidgets import QApplication

# Importa la clase de la ventana principal definida en gui_window.py
from gui_window import SnifferWindow


# Función que inicializa y lanza la interfaz gráfica
def iniciar_gui():

    # Crea la aplicación PyQt5, sys.argv permite pasar argumentos desde la línea de comandos
    app = QApplication(sys.argv)

    # Crea una instancia de la ventana principal
    ventana = SnifferWindow()

    # Hace visible la ventana en pantalla
    ventana.show()

    # Inicia el bucle de eventos de la aplicación y cierra el programa cuando se cierre la ventana
    sys.exit(app.exec_())
