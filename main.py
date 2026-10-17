import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

OPCIONES = {
    "1": ("ingestion", "Leer archivo, normalizar datos y controlar errores de entrada"),
    "2": ("validation", "Sanitizar cadenas y validar campos obligatorios y formatos"),
    "3": ("integrity", "Calcular y comparar hashes de evidencia"),
    "4": ("network_analyzer", "Analizar metadatos TCP/HTTP o registros de trafico autorizados"),
    "5": (None, "Salir"),
}


def mostrar_titulo():
    print(
        r"""
  ____      _                ____                     _
 / ___|   _| |__   ___ _ __ / ___|_   _  __ _ _ __ __| |
| |  | | | | '_ \ / _ \ '__| |  _| | | |/ _` | '__/ _` |
| |__| |_| | |_) |  __/ |  | |_| | |_| | (_| | | | (_| |
 \____\__, |_.__/ \___|_|   \____|\__,_|\__,_|_|  \__,_|
      |___/

    _                _
   / \   _ __   __ _| |_   _ _______ _ __
  / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 / ___ \| | | | (_| | | |_| |/ /  __/ |
/_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                       |___/
"""
    )


def pedir_archivo():
    return input("[+] ingresa el path a el archivo .txt: ")


def mostrar_menu():
    print()
    print("[+] menu")
    for numero, (_, descripcion) in OPCIONES.items():
        print(f"[{numero}] {descripcion}")
    print()


def llamar_modulo(nombre, ruta):
    modulo = importlib.import_module(nombre)
    funcion = getattr(modulo, "ejecutar", None)
    if funcion is None:
        print(f"[!] {nombre}.py fue llamado, pero todavia no tiene ejecutar(ruta)")
        return
    funcion(ruta)


def main():
    mostrar_titulo()
    ruta = pedir_archivo().strip()
    print(f"[+] archivo recibido: {ruta}")

    while True:
        mostrar_menu()
        opcion = input("[+] elige una opcion: ").strip()
        if opcion == "5":
            print("[+] salida")
            break
        if opcion not in OPCIONES:
            print("[!] opcion no valida")
            continue
        nombre, _ = OPCIONES[opcion]
        llamar_modulo(nombre, ruta)


if __name__ == "__main__":
    main()
