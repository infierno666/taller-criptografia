# -*- coding: utf-8 -*-
"""
hash_demo.py  -  Taller A4 · Seguridad Informática I (Universidad Domingo Savio)

Funciones hash (SHA-256) y código de autenticación HMAC-SHA-256.

Relación con el informe A3 (Tabla 17 y Tabla 18):
  - Calcula SHA-256 de un TEXTO y de un ARCHIVO.
  - Calcula y verifica HMAC-SHA-256 (hash + clave secreta compartida).
  - Muestra el EFECTO AVALANCHA: un cambio mínimo altera todo el hash.

Ideas clave que se demuestran:
  * Un hash NO es cifrado: no se puede revertir y no usa clave.
  * Un hash solo NO autentica: quien altera el mensaje puede recalcular el hash.
  * HMAC sí autentica entre las partes que comparten la clave, pero no da "no repudio".

Uso:
    python hash_demo.py          -> menú interactivo
    python hash_demo.py --auto   -> ejecuta todas las pruebas sin pedir datos
"""

import os
import sys
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac

TAM_BLOQUE_LECTURA = 64 * 1024  # los archivos se leen por trozos de 64 KiB (no se cargan enteros)

# Vectores de prueba oficiales (FIPS 180-4) para comprobar que SHA-256 funciona bien
VECTOR_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
VECTOR_VACIO = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------------------
# Funciones criptográficas
# ---------------------------------------------------------------------------
def sha256_bytes(datos: bytes) -> bytes:
    """SHA-256 de unos bytes. Devuelve el resumen de 32 bytes (256 bits)."""
    h = hashes.Hash(hashes.SHA256())
    h.update(datos)
    return h.finalize()


def sha256_texto(texto: str) -> str:
    """SHA-256 de un texto (se codifica en UTF-8). Devuelve 64 caracteres hexadecimales."""
    return sha256_bytes(texto.encode("utf-8")).hex()


def sha256_archivo(ruta: str) -> str:
    """SHA-256 de un archivo, leyéndolo por trozos para soportar archivos grandes."""
    h = hashes.Hash(hashes.SHA256())
    with open(ruta, "rb") as f:
        while True:
            trozo = f.read(TAM_BLOQUE_LECTURA)
            if not trozo:
                break
            h.update(trozo)
    return h.finalize().hex()


def hmac_sha256(clave: bytes, mensaje: bytes) -> bytes:
    """Etiqueta HMAC-SHA-256 de un mensaje con una clave secreta compartida."""
    m = hmac.HMAC(clave, hashes.SHA256())
    m.update(mensaje)
    return m.finalize()


def verificar_hmac(clave: bytes, mensaje: bytes, etiqueta: bytes) -> bool:
    """Verifica una etiqueta HMAC con comparación de TIEMPO CONSTANTE (la hace la biblioteca)."""
    m = hmac.HMAC(clave, hashes.SHA256())
    m.update(mensaje)
    try:
        m.verify(etiqueta)
        return True
    except InvalidSignature:
        return False


def bits_distintos(a: bytes, b: bytes) -> int:
    """Cuenta en cuántos bits difieren dos secuencias de igual longitud (distancia de Hamming)."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Demostraciones
# ---------------------------------------------------------------------------
def demo_sha256_y_avalancha() -> bool:
    print("\n=== 1) SHA-256 DE UN TEXTO Y EFECTO AVALANCHA ===")
    # Comprobación contra los vectores oficiales del estándar
    ok_abc = sha256_texto("abc") == VECTOR_ABC
    ok_vacio = sha256_texto("") == VECTOR_VACIO
    print(f"  SHA-256(\"abc\") coincide con el vector oficial FIPS 180-4 : [{'OK' if ok_abc else 'ERROR'}]")
    print(f"  SHA-256(\"\")    coincide con el vector oficial FIPS 180-4 : [{'OK' if ok_vacio else 'ERROR'}]")

    t1, t2 = "Hola mundo", "hola mundo"        # solo cambia la primera letra (H -> h)
    h1, h2 = sha256_bytes(t1.encode()), sha256_bytes(t2.encode())
    print(f"\n  SHA-256(\"{t1}\") = {h1.hex()}")
    print(f"  SHA-256(\"{t2}\") = {h2.hex()}")
    n = bits_distintos(h1, h2)
    print(f"\n  Los textos difieren en 1 letra y los hashes difieren en {n} de 256 bits ({n / 256:.0%}).")
    print("  Efecto avalancha: lo esperado es cerca del 50 %. El hash siempre mide 256 bits (64 hex).")
    return ok_abc and ok_vacio and len(h1) == 32 and 90 <= n <= 166


def demo_archivo(ruta: str = None) -> bool:
    print("\n=== 2) SHA-256 DE UN ARCHIVO ===")
    temporal = None
    if ruta is None:
        # Se crea un archivo de prueba de 1 MiB con contenido repetible
        fd, temporal = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(range(256)) * 4096)
        ruta = temporal
    try:
        tam = os.path.getsize(ruta)
        h_original = sha256_archivo(ruta)
        print(f"  Archivo : {ruta} ({tam} bytes)")
        print(f"  SHA-256 : {h_original}")
        if temporal is None:                 # archivo del usuario: no se modifica
            return True
        # Se altera UN solo byte del archivo de prueba y se vuelve a calcular
        with open(ruta, "r+b") as f:
            f.seek(1000)
            byte = f.read(1)
            f.seek(1000)
            f.write(bytes([byte[0] ^ 0x01]))
        h_alterado = sha256_archivo(ruta)
        print(f"\n  Se cambió 1 solo bit en la posición 1000 del archivo.")
        print(f"  SHA-256 : {h_alterado}")
        distinto = h_original != h_alterado
        print(f"  [{'OK' if distinto else 'ERROR'}] El hash cambió: así se detecta que un archivo descargado fue alterado.")
        return distinto
    finally:
        if temporal and os.path.exists(temporal):
            os.remove(temporal)


def demo_hmac() -> bool:
    print("\n=== 3) HMAC-SHA-256: HASH CON CLAVE SECRETA COMPARTIDA ===")
    clave = os.urandom(32)                   # clave compartida (solo la conocen emisor y receptor)
    mensaje = b"Transferir 100 Bs a la cuenta 12345"
    etiqueta = hmac_sha256(clave, mensaje)
    print(f"  Mensaje  : {mensaje.decode()}")
    print(f"  HMAC     : {etiqueta.hex()}")
    ok1 = verificar_hmac(clave, mensaje, etiqueta)
    print(f"  Verificación del mensaje original   : [{'OK' if ok1 else 'ERROR'}] válido")

    alterado = b"Transferir 900 Bs a la cuenta 12345"
    ok2 = not verificar_hmac(clave, alterado, etiqueta)
    print(f"  Mensaje alterado (100 -> 900)       : [{'OK' if ok2 else 'ERROR'}] RECHAZADO (la etiqueta no coincide)")

    ok3 = not verificar_hmac(os.urandom(32), mensaje, etiqueta)
    print(f"  Clave incorrecta                    : [{'OK' if ok3 else 'ERROR'}] RECHAZADO")

    print("\n  ¿Por qué no basta con un hash simple?")
    hash_atacante = sha256_bytes(alterado).hex()
    print(f"  Un atacante altera el mensaje y recalcula SHA-256 él mismo: {hash_atacante[:32]}...")
    print("  Ese hash sería 'válido' para el mensaje falso: el hash solo no autentica.")
    print("  Con HMAC, sin la clave secreta el atacante no puede producir una etiqueta válida.")
    print("  Nota: como ambas partes conocen la clave, HMAC NO ofrece no repudio (eso lo da la firma digital).")
    return ok1 and ok2 and ok3


def demo_automatica() -> bool:
    resultados = [demo_sha256_y_avalancha(), demo_archivo(), demo_hmac()]
    print("\n" + "=" * 60)
    print(f"RESULTADO FINAL: {sum(resultados)}/{len(resultados)} pruebas correctas")
    return all(resultados)


def ejecutar() -> None:
    """Menú interactivo (también lo llama main.py)."""
    while True:
        print("\n----- SHA-256 y HMAC (Taller A4) -----")
        print("1. Hash de mi propio texto")
        print("2. Efecto avalancha y vectores oficiales")
        print("3. Hash de un archivo (el mío o uno de prueba)")
        print("4. HMAC-SHA-256 (autenticación con clave)")
        print("5. Ejecutar todas las pruebas")
        print("0. Volver / salir")
        opcion = input("Elige una opción: ").strip()
        if opcion == "1":
            texto = input("Escribe un texto: ")
            print(f"  SHA-256 = {sha256_texto(texto)}")
        elif opcion == "2":
            demo_sha256_y_avalancha()
        elif opcion == "3":
            ruta = input("Ruta del archivo (Enter = usar archivo de prueba): ").strip().strip('"')
            if ruta and not os.path.isfile(ruta):
                print("  Ese archivo no existe.")
            else:
                demo_archivo(ruta or None)
        elif opcion == "4":
            demo_hmac()
        elif opcion == "5":
            demo_automatica()
        elif opcion == "0":
            break
        else:
            print("Opción no válida.")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if "--auto" in sys.argv:
        sys.exit(0 if demo_automatica() else 1)
    ejecutar()
