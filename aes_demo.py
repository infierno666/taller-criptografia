# -*- coding: utf-8 -*-
"""
aes_demo.py  -  Taller A4 · Seguridad Informática I (Universidad Domingo Savio)

Cifra y descifra un TEXTO con AES-256-GCM. La clave de 256 bits NO se escribe a mano:
se DERIVA de una contraseña con scrypt (función de derivación de claves lenta).

Relación con el informe A3 (Tabla 17 y Tabla 18):
  - Algoritmo : AES-256-GCM (cifrado autenticado, estándar NIST FIPS 197 + SP 800-38D)
  - Clave     : 256 bits (32 bytes) derivada con scrypt
  - Nonce     : 96 bits (12 bytes), aleatorio y distinto en cada cifrado
  - Etiqueta  : 128 bits (16 bytes) de autenticación, que detecta cualquier alteración

Formato del paquete cifrado (todo en bytes):
    [ sal (16) ][ nonce (12) ][ texto cifrado (n) ][ etiqueta GCM (16) ]

Uso:
    python aes_demo.py          -> menú interactivo
    python aes_demo.py --auto   -> ejecuta todas las pruebas sin pedir datos
"""

import base64
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ---------------------------------------------------------------------------
# Parámetros (coinciden con la Tabla 17 del informe)
# ---------------------------------------------------------------------------
TAM_SAL = 16        # bytes de sal para scrypt (valor aleatorio, no secreto)
TAM_NONCE = 12      # 96 bits: tamaño recomendado para GCM (NIST SP 800-38D)
TAM_CLAVE = 32      # 256 bits: AES-256
TAM_ETIQUETA = 16   # 128 bits: etiqueta de autenticación que añade GCM

SCRYPT_N = 2 ** 15  # costo de CPU/memoria (cuanto mayor, más lento atacar por fuerza bruta)
SCRYPT_R = 8        # tamaño de bloque interno
SCRYPT_P = 1        # paralelismo

TEXTO_EJEMPLO = "Hola, este es un mensaje secreto del Taller A4 de Seguridad Informática I."
CONTRASENA_EJEMPLO = "taller-A4-2026"


# ---------------------------------------------------------------------------
# Funciones criptográficas (la parte importante del programa)
# ---------------------------------------------------------------------------
def derivar_clave(contrasena: str, sal: bytes) -> bytes:
    """Convierte una contraseña en una clave AES de 256 bits usando scrypt.

    Una contraseña humana tiene poca entropía; scrypt la hace costosa de adivinar.
    La misma contraseña con la MISMA sal siempre da la misma clave, por eso la sal
    viaja dentro del paquete cifrado.
    """
    kdf = Scrypt(salt=sal, length=TAM_CLAVE, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(contrasena.encode("utf-8"))


def cifrar(texto: str, contrasena: str) -> bytes:
    """Cifra un texto con AES-256-GCM y devuelve el paquete [sal|nonce|cifrado+etiqueta]."""
    sal = os.urandom(TAM_SAL)          # os.urandom = generador aleatorio seguro del sistema
    nonce = os.urandom(TAM_NONCE)      # NUNCA se debe repetir un nonce con la misma clave
    clave = derivar_clave(contrasena, sal)
    # AESGCM.encrypt devuelve el texto cifrado con la etiqueta de 16 bytes añadida al final
    cifrado_y_etiqueta = AESGCM(clave).encrypt(nonce, texto.encode("utf-8"), None)
    return sal + nonce + cifrado_y_etiqueta


def descifrar(paquete: bytes, contrasena: str) -> str:
    """Descifra un paquete. Lanza InvalidTag si la contraseña es incorrecta o si el
    paquete fue modificado (en ese caso NO se entrega ningún texto plano)."""
    if len(paquete) < TAM_SAL + TAM_NONCE + TAM_ETIQUETA:
        raise ValueError("El paquete es demasiado corto para ser válido.")
    sal = paquete[:TAM_SAL]
    nonce = paquete[TAM_SAL:TAM_SAL + TAM_NONCE]
    cifrado_y_etiqueta = paquete[TAM_SAL + TAM_NONCE:]
    clave = derivar_clave(contrasena, sal)
    texto_plano = AESGCM(clave).decrypt(nonce, cifrado_y_etiqueta, None)
    return texto_plano.decode("utf-8")


# ---------------------------------------------------------------------------
# Demostraciones (lo que se ve en pantalla)
# ---------------------------------------------------------------------------
def _hex(b: bytes) -> str:
    return b.hex()


def _mostrar_paquete(paquete: bytes) -> None:
    """Muestra las partes del paquete. Base64 se usa SOLO para poder imprimir los bytes;
    no es cifrado."""
    sal = paquete[:TAM_SAL]
    nonce = paquete[TAM_SAL:TAM_SAL + TAM_NONCE]
    cifrado = paquete[TAM_SAL + TAM_NONCE:-TAM_ETIQUETA]
    etiqueta = paquete[-TAM_ETIQUETA:]
    print(f"  Sal scrypt ({len(sal)} bytes)      : {_hex(sal)}")
    print(f"  Nonce      ({len(nonce)} bytes)      : {_hex(nonce)}")
    print(f"  Texto cifrado ({len(cifrado)} bytes): {_hex(cifrado)}")
    print(f"  Etiqueta GCM ({len(etiqueta)} bytes) : {_hex(etiqueta)}")
    print(f"  Paquete completo en Base64 : {base64.b64encode(paquete).decode()}")


def demo_cifrar_descifrar(texto: str = TEXTO_EJEMPLO, contrasena: str = CONTRASENA_EJEMPLO) -> bool:
    print("\n=== 1) CIFRAR Y DESCIFRAR UN TEXTO (AES-256-GCM + scrypt) ===")
    print(f"Texto original : {texto}")
    print(f"Contraseña     : {contrasena}")
    print(f"Parámetros     : clave {TAM_CLAVE * 8} bits | nonce {TAM_NONCE * 8} bits | "
          f"etiqueta {TAM_ETIQUETA * 8} bits | scrypt N={SCRYPT_N}, r={SCRYPT_R}, p={SCRYPT_P}")
    paquete = cifrar(texto, contrasena)
    print("\n[CIFRADO]")
    _mostrar_paquete(paquete)
    recuperado = descifrar(paquete, contrasena)
    print("\n[DESCIFRADO]")
    print(f"  Texto recuperado: {recuperado}")
    ok = recuperado == texto
    print(f"  [{'OK' if ok else 'ERROR'}] El texto recuperado {'coincide' if ok else 'NO coincide'} con el original.")
    return ok


def demo_nonce_distinto(texto: str = TEXTO_EJEMPLO, contrasena: str = CONTRASENA_EJEMPLO) -> bool:
    print("\n=== 2) EL MISMO TEXTO, DOS VECES, DA RESULTADOS DISTINTOS ===")
    p1 = cifrar(texto, contrasena)
    p2 = cifrar(texto, contrasena)
    print(f"  Cifrado 1: {_hex(p1)[:64]}...")
    print(f"  Cifrado 2: {_hex(p2)[:64]}...")
    distintos = p1 != p2
    print(f"  [{'OK' if distintos else 'ERROR'}] Los paquetes {'son distintos' if distintos else 'son IGUALES'} "
          "(sal y nonce aleatorios en cada cifrado).")
    return distintos and descifrar(p1, contrasena) == texto and descifrar(p2, contrasena) == texto


def demo_manipulacion(texto: str = TEXTO_EJEMPLO, contrasena: str = CONTRASENA_EJEMPLO) -> bool:
    print("\n=== 3) PRUEBA DE MANIPULACIÓN: SE ALTERA UN SOLO BYTE ===")
    paquete = bytearray(cifrar(texto, contrasena))
    posicion = TAM_SAL + TAM_NONCE + 2           # un byte dentro del texto cifrado
    print(f"  Se cambia el byte {posicion}: {paquete[posicion]:02x} -> {paquete[posicion] ^ 0x01:02x}")
    paquete[posicion] ^= 0x01                    # invierte 1 solo bit
    try:
        descifrar(bytes(paquete), contrasena)
        print("  [ERROR] GCM aceptó un mensaje alterado.")
        return False
    except InvalidTag:
        print("  [OK] RECHAZADO: la etiqueta de autenticación no coincide (InvalidTag).")
        print("       No se entregó ningún texto plano: GCM garantiza integridad además de confidencialidad.")
        return True


def demo_contrasena_incorrecta(texto: str = TEXTO_EJEMPLO, contrasena: str = CONTRASENA_EJEMPLO) -> bool:
    print("\n=== 4) CONTRASEÑA INCORRECTA ===")
    paquete = cifrar(texto, contrasena)
    try:
        descifrar(paquete, contrasena + "x")
        print("  [ERROR] Se descifró con una contraseña incorrecta.")
        return False
    except InvalidTag:
        print("  [OK] RECHAZADO: otra contraseña produce otra clave y la etiqueta no coincide.")
        return True


def demo_automatica() -> bool:
    """Ejecuta todas las pruebas con los valores de ejemplo (sin pedir datos)."""
    resultados = [
        demo_cifrar_descifrar(),
        demo_nonce_distinto(),
        demo_manipulacion(),
        demo_contrasena_incorrecta(),
    ]
    print("\n" + "=" * 60)
    print(f"RESULTADO FINAL: {sum(resultados)}/{len(resultados)} pruebas correctas")
    return all(resultados)


def _pedir(mensaje: str, defecto: str) -> str:
    valor = input(f"{mensaje} [{defecto}]: ").strip()
    return valor if valor else defecto


def ejecutar() -> None:
    """Menú interactivo (también lo llama main.py)."""
    while True:
        print("\n----- AES-256-GCM (Taller A4) -----")
        print("1. Cifrar y descifrar mi propio texto")
        print("2. Ver que el mismo texto cifra distinto cada vez")
        print("3. Probar manipulación (alterar un byte)")
        print("4. Probar contraseña incorrecta")
        print("5. Ejecutar todas las pruebas")
        print("0. Volver / salir")
        opcion = input("Elige una opción: ").strip()
        if opcion == "1":
            texto = _pedir("Texto a cifrar", TEXTO_EJEMPLO)
            contrasena = _pedir("Contraseña", CONTRASENA_EJEMPLO)
            demo_cifrar_descifrar(texto, contrasena)
        elif opcion == "2":
            demo_nonce_distinto()
        elif opcion == "3":
            demo_manipulacion()
        elif opcion == "4":
            demo_contrasena_incorrecta()
        elif opcion == "5":
            demo_automatica()
        elif opcion == "0":
            break
        else:
            print("Opción no válida.")


if __name__ == "__main__":
    # En Windows la consola puede no usar UTF-8; esto evita errores con tildes.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if "--auto" in sys.argv:
        sys.exit(0 if demo_automatica() else 1)
    ejecutar()
