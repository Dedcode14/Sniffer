# Importa la función capturar_uno desde el módulo capture
from capture import capturar_uno, capturar_continuo

# Verifica si el archivo se está ejecutando directamente
if __name__ == "__main__":
    print("=" * 50)
    print("  Network Sniffer")
    print("=" * 50)
    print("  1. Captura estática  (un paquete)")
    print("  2. Captura dinámica  (flujo continuo)")
    print("=" * 50)

    opcion = input("Selecciona una opción (1 o 2): ").strip()

    if opcion == "1":
        capturar_uno()
    elif opcion == "2":
        capturar_continuo()
    else:
        print("Opción no válida.")
