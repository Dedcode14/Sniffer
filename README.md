# Sniffer
Repository containing the final project for network application programming, which consists of a sniffer.

## Integrantes

- Orozco Sánchez Diego Alejandro
- Torres Buenrostro Zaira Patricia
- Caro Flores Christopher Tristán

## Requisitos previos

- Python 3.x
- [Npcap](https://npcap.com/#download) — seleccionar la opción *"WinPcap API-compatible mode"* durante la instalación

## Instalación

1. Clonar el repositorio
   git clone https://github.com/usuario/network-sniffer.git
   cd network-sniffer

2. Instalar dependencias
   pip install -r requirements.txt

## Uso

Ejecutar como Administrador desde la raíz del proyecto:

    python src/main.py

Generar tráfico para capturar (en otra terminal):

    ping google.com

## Estructura del proyecto

    network-sniffer/
    ├── src/
    │   ├── main.py       # Punto de entrada
    │   ├── capture.py    # Lógica de captura
    │   ├── parser.py     # Disección de paquetes
    │ 
    ├── requirements.txt
    └── README.md

## Partes del proyecto

- **Parte 1** — Captura estática: captura un paquete y muestra sus campos por capa
- **Parte 2** — Captura dinámica: flujo continuo de paquetes con selección para análisis
- **Parte 3** — Interfaz gráfica: visualización de los campos del paquete capturado
