# -*- coding: utf-8 -*-
"""
main.py  -  Taller A4 · Seguridad Informática I (Universidad Domingo Savio)

Menú principal del taller de criptografía. Reúne los seis módulos prometidos en el informe A3
(Tablas 17 y 18) y permite ejecutarlos uno por uno o todos a la vez.

    1. aes_demo.py      AES-256-GCM con clave derivada por scrypt        (cifrado simétrico)
    2. hash_demo.py     SHA-256 y HMAC-SHA-256                           (integridad)
    3. token_demo.py    Token firmado con HMAC-SHA-256, estilo JWT HS256
    4. rsa_demo.py      RSA-2048 con OAEP (cifrar) y PSS (firmar)        (cifrado asimétrico)
    5. hibrido_demo.py  RSA protege la clave AES; AES-GCM cifra los datos
    6. tls_demo.py      Conexión TLS 1.3 y certificado X.509

Uso:
    python main.py          -> menú interactivo
    python main.py --auto   -> ejecuta TODAS las demostraciones y muestra un resumen final
    python main.py --tests  -> ejecuta las pruebas automáticas (carpeta tests/)
"""

import os
import subprocess
import sys

# Permite ejecutar main.py desde cualquier carpeta
CARPETA = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CARPETA)

try:
    import aes_demo
    import hash_demo
    import hibrido_demo
    import rsa_demo
    import tls_demo
    import token_demo
except ModuleNotFoundError as e:
    if e.name and e.name.startswith("cryptography"):
        print("Falta la biblioteca 'cryptography'. Instálala con:  pip install -r requirements.txt")
        sys.exit(1)
    raise

MODULOS = [
    ("AES-256-GCM (cifrado simétrico)", aes_demo),
    ("SHA-256 y HMAC (integridad)", hash_demo),
    ("Token HMAC-SHA-256 / JWT HS256", token_demo),
    ("RSA-2048: OAEP y PSS (asimétrico)", rsa_demo),
    ("Cifrado híbrido RSA + AES-GCM", hibrido_demo),
    ("TLS 1.3 y certificados X.509", tls_demo),
]


def banner() -> None:
    print("=" * 62)
    print("  TALLER A4 · CRIPTOGRAFÍA APLICADA")
    print("  Seguridad Informática I · Universidad Domingo Savio")
    print("=" * 62)


def ejecutar_todo() -> bool:
    """Ejecuta la demostración automática de cada módulo y muestra un resumen."""
    resumen = []
    for nombre, modulo in MODULOS:
        print("\n" + "#" * 62)
        print(f"#  {nombre}")
        print("#" * 62)
        try:
            ok = modulo.demo_automatica()
        except Exception as e:                       # un fallo no debe ocultar al resto
            print(f"  [ERROR] El módulo falló: {type(e).__name__}: {e}")
            ok = False
        resumen.append((nombre, ok))
    print("\n" + "=" * 62)
    print("  RESUMEN FINAL DEL TALLER")
    print("=" * 62)
    for nombre, ok in resumen:
        print(f"  [{'OK' if ok else 'FALLÓ'}] {nombre}")
    todo_ok = all(ok for _, ok in resumen)
    print("=" * 62)
    print("  " + ("TODAS LAS DEMOSTRACIONES FUERON CORRECTAS." if todo_ok else "HAY DEMOSTRACIONES CON ERRORES."))
    return todo_ok


def ejecutar_pruebas() -> bool:
    """Lanza las pruebas automáticas (unittest) de la carpeta tests/."""
    print("\nEjecutando las pruebas automáticas (carpeta tests/)...\n")
    resultado = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=CARPETA)
    return resultado.returncode == 0


def menu() -> None:
    while True:
        banner()
        for i, (nombre, _) in enumerate(MODULOS, start=1):
            print(f"  {i}. {nombre}")
        print("  7. Ejecutar TODAS las demostraciones")
        print("  8. Ejecutar las pruebas automáticas (tests/)")
        print("  0. Salir")
        opcion = input("\nElige una opción: ").strip()
        if opcion in {"1", "2", "3", "4", "5", "6"}:
            MODULOS[int(opcion) - 1][1].ejecutar()
        elif opcion == "7":
            ejecutar_todo()
            input("\nPresiona Enter para volver al menú...")
        elif opcion == "8":
            ejecutar_pruebas()
            input("\nPresiona Enter para volver al menú...")
        elif opcion == "0":
            print("Hasta luego.")
            break
        else:
            print("Opción no válida.\n")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        if "--auto" in sys.argv:
            sys.exit(0 if ejecutar_todo() else 1)
        elif "--tests" in sys.argv:
            sys.exit(0 if ejecutar_pruebas() else 1)
        else:
            menu()
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.")
