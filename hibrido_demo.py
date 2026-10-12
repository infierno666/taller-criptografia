# -*- coding: utf-8 -*-
"""
hibrido_demo.py  -  Taller A4 · Seguridad Informática I (Universidad Domingo Savio)

CRIPTOGRAFÍA HÍBRIDA: RSA protege una clave AES y AES-256-GCM cifra el mensaje largo.

Por qué existe: RSA-2048 solo cifra hasta 190 bytes y es lento; AES es rápido y cifra
cualquier tamaño pero exige que las dos partes compartan una clave. El esquema híbrido
combina lo mejor de ambos (es el mismo patrón que usan TLS, las VPN y el correo cifrado).

Flujo (Tabla 12 del informe A3):
  EMISOR                                              RECEPTOR
  1. genera una clave de sesión AES de 256 bits
  2. cifra los datos con AES-256-GCM (nonce único)
  3. cifra la clave de sesión con la clave PÚBLICA     5. recupera la clave de sesión con su
     del receptor (RSA-OAEP)                              clave PRIVADA (RSA-OAEP)
  4. envía el paquete                                  6. descifra y verifica con AES-256-GCM
  (opcional) firma el paquete con RSA-PSS              (opcional) verifica la firma del emisor

Formato del paquete (bytes):
  [ clave de sesión cifrada (256) ][ nonce (12) ][ datos cifrados + etiqueta GCM ][ firma PSS (256) ]

Se usan DOS pares RSA distintos (uno del receptor para cifrar, otro del emisor para firmar),
siguiendo la buena práctica de no usar el mismo par para cifrar y para firmar.

Uso:
    python hibrido_demo.py          -> menú interactivo
    python hibrido_demo.py --auto   -> ejecuta todas las pruebas sin pedir datos
"""

import os
import sys
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import rsa_demo   # reutiliza RSA-OAEP y RSA-PSS ya implementados

TAM_CLAVE_SESION = 32      # 256 bits
TAM_NONCE = 12             # 96 bits
TAM_RSA = rsa_demo.TAM_MODULO_BYTES  # 256 bytes (tamaño del cifrado RSA y de la firma)


class PaqueteInvalido(Exception):
    """El paquete es corto, fue alterado o la firma no es válida."""


# ---------------------------------------------------------------------------
# Funciones criptográficas
# ---------------------------------------------------------------------------
def cifrar_hibrido(datos: bytes, publica_receptor: rsa.RSAPublicKey,
                   privada_emisor: rsa.RSAPrivateKey = None) -> bytes:
    """Cifra datos de cualquier tamaño. Si se da la clave privada del emisor, firma el paquete."""
    clave_sesion = AESGCM.generate_key(bit_length=256)             # paso 1
    nonce = os.urandom(TAM_NONCE)                                  # nonce único por mensaje
    datos_cifrados = AESGCM(clave_sesion).encrypt(nonce, datos, None)   # paso 2 (incluye etiqueta)
    clave_cifrada = rsa_demo.cifrar_oaep(publica_receptor, clave_sesion)  # paso 3: RSA solo ve 32 bytes
    paquete = clave_cifrada + nonce + datos_cifrados               # paso 4
    if privada_emisor is not None:
        paquete += rsa_demo.firmar_pss(privada_emisor, paquete)    # firma opcional
    return paquete


def descifrar_hibrido(paquete: bytes, privada_receptor: rsa.RSAPrivateKey,
                      publica_emisor: rsa.RSAPublicKey = None) -> bytes:
    """Descifra un paquete. Si se da la clave pública del emisor, exige y verifica la firma PRIMERO."""
    minimo = TAM_RSA + TAM_NONCE + 16 + (TAM_RSA if publica_emisor else 0)
    if len(paquete) < minimo:
        raise PaqueteInvalido("El paquete es demasiado corto.")
    if publica_emisor is not None:
        cuerpo, firma = paquete[:-TAM_RSA], paquete[-TAM_RSA:]
        if not rsa_demo.verificar_pss(publica_emisor, cuerpo, firma):
            raise PaqueteInvalido("La firma del emisor NO es válida: el paquete fue alterado o no es de quien dice.")
    else:
        cuerpo = paquete
    clave_cifrada = cuerpo[:TAM_RSA]
    nonce = cuerpo[TAM_RSA:TAM_RSA + TAM_NONCE]
    datos_cifrados = cuerpo[TAM_RSA + TAM_NONCE:]
    try:
        clave_sesion = rsa_demo.descifrar_oaep(privada_receptor, clave_cifrada)   # paso 5
    except ValueError as e:
        raise PaqueteInvalido("No se pudo recuperar la clave de sesión (clave privada incorrecta o paquete alterado).") from e
    try:
        return AESGCM(clave_sesion).decrypt(nonce, datos_cifrados, None)          # paso 6
    except InvalidTag as e:
        raise PaqueteInvalido("AES-GCM rechazó los datos: la etiqueta de autenticación no coincide.") from e


def cifrar_archivo(ruta_entrada: str, ruta_salida: str, publica_receptor, privada_emisor=None) -> int:
    """Cifra un archivo completo (se carga en memoria: pensado para archivos de hasta unos cientos de MB)."""
    with open(ruta_entrada, "rb") as f:
        datos = f.read()
    paquete = cifrar_hibrido(datos, publica_receptor, privada_emisor)
    with open(ruta_salida, "wb") as f:
        f.write(paquete)
    return len(paquete)


def descifrar_archivo(ruta_entrada: str, ruta_salida: str, privada_receptor, publica_emisor=None) -> int:
    with open(ruta_entrada, "rb") as f:
        paquete = f.read()
    datos = descifrar_hibrido(paquete, privada_receptor, publica_emisor)
    with open(ruta_salida, "wb") as f:
        f.write(datos)
    return len(datos)


# ---------------------------------------------------------------------------
# Demostraciones
# ---------------------------------------------------------------------------
def _hash(datos: bytes) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(datos)
    return h.finalize().hex()


_pares = None


def _obtener_pares():
    """Dos pares RSA: receptor (cifrado) y emisor (firma). Se generan una sola vez."""
    global _pares
    if _pares is None:
        _pares = (rsa_demo.generar_par_rsa(), rsa_demo.generar_par_rsa())
    return _pares


def demo_mensaje_largo(tam_mb: int = 5) -> bool:
    print(f"\n=== 1) ENVIAR UN INFORME DE {tam_mb} MB (RSA protege la clave, AES cifra los datos) ===")
    receptor, emisor = _obtener_pares()
    informe = os.urandom(tam_mb * 1024 * 1024)
    print(f"  Tamaño del informe: {len(informe):,} bytes. SHA-256: {_hash(informe)[:32]}...")

    try:
        rsa_demo.cifrar_oaep(receptor.public_key(), informe)
        print("  [ERROR] RSA cifró el informe completo (no debería).")
        return False
    except ValueError:
        print(f"  [OK] RSA directo es IMPOSIBLE: el límite es {rsa_demo.MAX_OAEP} bytes. Se necesita el esquema híbrido.")

    t0 = time.perf_counter()
    paquete = cifrar_hibrido(informe, receptor.public_key(), emisor)
    t1 = time.perf_counter()
    print(f"\n  [CIFRADO HÍBRIDO] {t1 - t0:.3f} s")
    print(f"  Clave de sesión AES (RSA-OAEP): {TAM_CLAVE_SESION} bytes protegidos con RSA -> {TAM_RSA} bytes")
    print(f"  Datos cifrados (AES-256-GCM)  : {len(informe):,} bytes + 16 de etiqueta")
    print(f"  Firma del emisor (RSA-PSS)     : {TAM_RSA} bytes")
    print(f"  Paquete total                  : {len(paquete):,} bytes")
    print(f"  RSA procesó solo {TAM_CLAVE_SESION} bytes; los {tam_mb} MB los procesó AES.")

    t2 = time.perf_counter()
    recuperado = descifrar_hibrido(paquete, receptor, emisor.public_key())
    t3 = time.perf_counter()
    ok = recuperado == informe
    print(f"\n  [DESCIFRADO] {t3 - t2:.3f} s. SHA-256 recuperado: {_hash(recuperado)[:32]}...")
    print(f"  [{'OK' if ok else 'ERROR'}] El informe recuperado {'coincide' if ok else 'NO coincide'} con el original.")
    return ok


def demo_texto(texto: str = "Mensaje confidencial largo. " * 20) -> bool:
    print("\n=== 2) CIFRAR UN TEXTO LARGO ===")
    receptor, emisor = _obtener_pares()
    datos = texto.encode("utf-8")
    print(f"  Texto de {len(datos)} bytes (más que los {rsa_demo.MAX_OAEP} que admite RSA directamente).")
    paquete = cifrar_hibrido(datos, receptor.public_key(), emisor)
    recuperado = descifrar_hibrido(paquete, receptor, emisor.public_key()).decode("utf-8")
    ok = recuperado == texto
    print(f"  Paquete cifrado: {paquete.hex()[:64]}... ({len(paquete)} bytes)")
    print(f"  [{'OK' if ok else 'ERROR'}] El texto recuperado {'coincide' if ok else 'NO coincide'} con el original.")
    return ok


def demo_manipulacion() -> bool:
    print("\n=== 3) PRUEBAS DE MANIPULACIÓN ===")
    receptor, emisor = _obtener_pares()
    datos = b"Contrato confidencial: pago de 10000 Bs." * 50
    paquete = cifrar_hibrido(datos, receptor.public_key(), emisor)
    resultados = []

    def intentar(titulo, funcion):
        try:
            funcion()
            print(f"  [ERROR] {titulo}: fue ACEPTADO (no debería).")
            resultados.append(False)
        except PaqueteInvalido as e:
            print(f"  [OK] {titulo}: RECHAZADO -> {e}")
            resultados.append(True)

    alterado = bytearray(paquete)
    alterado[TAM_RSA + TAM_NONCE + 5] ^= 0x01
    intentar("1 byte alterado en los datos cifrados (con firma)",
             lambda: descifrar_hibrido(bytes(alterado), receptor, emisor.public_key()))

    # Sin verificar firma, la defensa es la etiqueta de AES-GCM
    sin_firma = cifrar_hibrido(datos, receptor.public_key())
    alterado2 = bytearray(sin_firma)
    alterado2[TAM_RSA + TAM_NONCE + 5] ^= 0x01
    intentar("1 byte alterado en los datos (sin firma): defiende AES-GCM",
             lambda: descifrar_hibrido(bytes(alterado2), receptor))

    alterado3 = bytearray(sin_firma)
    alterado3[10] ^= 0x01
    intentar("clave de sesión cifrada alterada: defiende RSA-OAEP",
             lambda: descifrar_hibrido(bytes(alterado3), receptor))

    intruso = rsa_demo.generar_par_rsa()
    intentar("un tercero intenta descifrar con SU clave privada",
             lambda: descifrar_hibrido(sin_firma, intruso))

    falso_emisor = rsa_demo.generar_par_rsa()
    intentar("paquete firmado por otra persona (suplantación)",
             lambda: descifrar_hibrido(paquete, receptor, falso_emisor.public_key()))
    return all(resultados)


def demo_archivo(ruta: str = None) -> bool:
    import tempfile
    print("\n=== 4) CIFRAR Y DESCIFRAR UN ARCHIVO ===")
    receptor, emisor = _obtener_pares()
    with tempfile.TemporaryDirectory() as carpeta:
        if ruta is None:
            ruta = os.path.join(carpeta, "documento.txt")
            with open(ruta, "w", encoding="utf-8") as f:
                f.write("Contenido de prueba del Taller A4.\n" * 2000)
        enc = os.path.join(carpeta, "documento.hib")
        dec = os.path.join(carpeta, "documento_recuperado")
        tam_enc = cifrar_archivo(ruta, enc, receptor.public_key(), emisor)
        tam_dec = descifrar_archivo(enc, dec, receptor, emisor.public_key())
        with open(ruta, "rb") as a, open(dec, "rb") as b:
            ok = a.read() == b.read()
        print(f"  Archivo original : {ruta}")
        print(f"  Archivo cifrado  : {tam_enc:,} bytes | recuperado: {tam_dec:,} bytes")
        print(f"  [{'OK' if ok else 'ERROR'}] El archivo recuperado es idéntico al original.")
    return ok


def demo_automatica() -> bool:
    resultados = [demo_mensaje_largo(), demo_texto(), demo_manipulacion(), demo_archivo()]
    print("\n" + "=" * 60)
    print(f"RESULTADO FINAL: {sum(resultados)}/{len(resultados)} pruebas correctas")
    return all(resultados)


def ejecutar() -> None:
    """Menú interactivo (también lo llama main.py)."""
    while True:
        print("\n----- Criptografía híbrida RSA + AES-GCM (Taller A4) -----")
        print("1. Enviar un informe de 5 MB (RSA protege la clave)")
        print("2. Cifrar un texto largo")
        print("3. Pruebas de manipulación")
        print("4. Cifrar y descifrar un archivo (el mío o uno de prueba)")
        print("5. Ejecutar todas las pruebas")
        print("0. Volver / salir")
        opcion = input("Elige una opción: ").strip()
        if opcion == "1":
            demo_mensaje_largo()
        elif opcion == "2":
            t = input("Texto [Enter = ejemplo]: ")
            demo_texto(t) if t.strip() else demo_texto()
        elif opcion == "3":
            demo_manipulacion()
        elif opcion == "4":
            r = input("Ruta del archivo (Enter = archivo de prueba): ").strip().strip('"')
            if r and not os.path.isfile(r):
                print("  Ese archivo no existe.")
            else:
                demo_archivo(r or None)
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
