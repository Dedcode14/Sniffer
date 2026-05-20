# Hoja de estilos CSS de PyQt5 que define la apariencia visual de toda la aplicación
STYLE = """

    /* Ventana principal y todos los widgets heredan este fondo y color de texto */
    QMainWindow, QWidget {
        background-color: #1e1e2e;  /* fondo oscuro */
        color: #cdd6f4;             /* texto claro */
        font-family: Arial;
        font-size: 13px;
    }

    /* Estilo de la tabla de paquetes */
    QTableWidget {
        background-color: #181825;          /* fondo más oscuro que la ventana */
        color: #cdd6f4;                     /* texto claro */
        border: 1px solid #313244;          /* borde sutil */
        gridline-color: #313244;            /* color de las líneas de la cuadrícula */
        selection-background-color: #45475a; /* color de fila seleccionada */
    }

    /* Celda seleccionada dentro de la tabla */
    QTableWidget::item:selected {
        background-color: #45475a;  /* fondo de celda seleccionada */
        color: #cdd6f4;             /* texto de celda seleccionada */
    }

    /* Encabezados de columna de la tabla */
    QHeaderView::section {
        background-color: #313244;  /* fondo del encabezado */
        color: #cdd6f4;             /* texto del encabezado */
        padding: 6px;               /* espacio interno */
        border: none;               /* sin borde */
        font-weight: bold;          /* texto en negrita */
    }

    /* Estilo base de todos los botones */
    QPushButton {
        background-color: #89b4fa;  /* azul claro */
        color: #1e1e2e;             /* texto oscuro para contraste */
        border: none;
        padding: 8px 20px;          /* espacio interno vertical y horizontal */
        border-radius: 6px;         /* bordes redondeados */
        font-weight: bold;
        font-size: 13px;
    }

    /* Color del botón al pasar el cursor encima */
    QPushButton:hover {
        background-color: #b4befe;  /* azul más claro al hacer hover */
    }

    /* Color del botón cuando está deshabilitado */
    QPushButton:disabled {
        background-color: #45475a;  /* gris oscuro */
        color: #6c7086;             /* texto gris apagado */
    }

    /* Estilo específico del botón Detener (identificado por objectName btn_stop) */
    QPushButton#btn_stop {
        background-color: #f38ba8;  /* rojo rosado */
        color: #1e1e2e;
    }

    /* Color del botón Detener al pasar el cursor */
    QPushButton#btn_stop:hover {
        background-color: #eba0ac;  /* rojo más claro al hacer hover */
    }

    /* Área de texto del panel de detalle del paquete */
    QTextEdit {
        background-color: #181825;        /* fondo oscuro */
        color: #cdd6f4;                   /* texto claro */
        border: 1px solid #313244;        /* borde sutil */
        border-radius: 4px;               /* bordes ligeramente redondeados */
        padding: 8px;                     /* espacio interno */
        font-family: Consolas, monospace; /* fuente monoespaciada para alinear campos */
        font-size: 12px;
    }

    /* Etiqueta del título principal (Proyecto Sniffer | Equipo 2) */
    QLabel#label_title {
        font-size: 18px;
        font-weight: bold;
        color: #89b4fa;     /* azul claro */
        padding: 8px 0px;
    }

    /* Etiqueta de estado (Listo / Capturando / Captura detenida) */
    QLabel#label_status {
        color: #a6e3a1;  /* verde claro */
        font-size: 12px;
        padding: 4px;
    }

    /* Etiqueta del título del panel de detalle */
    QLabel#label_detail_title {
        font-size: 14px;
        font-weight: bold;
        color: #cba6f7;  /* morado claro */
        padding: 4px 0px;
    }

    /* Línea separadora horizontal entre el filtro y la tabla */
    QFrame#separator {
        background-color: #313244;  /* gris oscuro */
    }

    /* Lista desplegable del filtro de protocolo */
    QComboBox {
        background-color: #313244;       /* fondo oscuro */
        color: #cdd6f4;                  /* texto claro */
        border: 1px solid #45475a;       /* borde sutil */
        border-radius: 4px;              /* bordes redondeados */
        padding: 4px 8px;                /* espacio interno */
        min-width: 120px;                /* ancho mínimo del combo */
    }

    /* Flecha del desplegable sin borde adicional */
    QComboBox::drop-down {
        border: none;
    }

    /* Lista de opciones que aparece al abrir el combo */
    QComboBox QAbstractItemView {
        background-color: #313244;           /* fondo de la lista desplegada */
        color: #cdd6f4;                      /* texto de las opciones */
        selection-background-color: #45475a; /* fondo de la opción seleccionada */
    }
"""

# Diccionario que asigna un color a cada tipo de protocolo
# Estos colores se aplican al texto de la columna Protocolo en la tabla
PROTO_COLORS = {
    "TCP": "#89b4fa",  # azul claro
    "UDP": "#a6e3a1",  # verde claro
    "ICMP": "#fab387",  # naranja
    "DNS": "#f9e2af",  # amarillo claro
    "HTTP": "#cba6f7",  # morado claro
    "TLS": "#89dceb",  # celeste
    "ARP": "#a6e3a1",  # verde claro (igual que UDP)
    "DESCONOCIDO": "#6c7086",  # gris apagado
}
