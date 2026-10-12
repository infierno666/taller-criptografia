# -*- coding: utf-8 -*-
"""
rsa_demo.py  -  Taller A4 · Seguridad Informática I (Universidad Domingo Savio)

Criptografía ASIMÉTRICA con RSA-2048:
  * CIFRAR con la clave PÚBLICA del destinatario  y  DESCIFRAR con su clave PRIVADA
    usando el relleno OAEP (SHA-256 y MGF1 con SHA-256).
  * FIRMAR con la clave PRIVADA del firmante  y  VERIFICAR con su clave PÚBLICA
    usando el esquema PSS (SHA-256 y sal de 32 bytes).

Relación con el informe A3 (Tabla 17 y Tabla 18):
  - RSA-OAEP : clave de 2048 bits; SHA-256 como hash y en MGF1.
  - RSA-PSS  : clave de 2048 bits; SHA-256; sal de 32 bytes.
  - Límite   : con RSA-2048 y OAEP-SHA-256 el mensaje máximo es 256 - 2*32 - 2 = 190 bytes.

Idea clave: nunca se usa "RSA de libro" (sin relleno). OAEP y PSS son probabilísticos:
el mismo mensaje da resultados distintos cada vez, lo que evita ataques sobre el RSA básico.

Uso:
    python rsa_demo.py          -> menú interactivo
    python rsa_demo.py --auto   -> ejecuta todas las pruebas sin pedir datos
"""

import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------------------------------------------------------------------
# Parámetros (coinciden con la Tabla 17 del informe)
# ---------------------------------------------------------------------------
TAM_CLAVE_BITS = 2048
EXPONENTE_PUBLICO = 65537
TAM_HASH = 32                                      # SHA-256 produce 32 bytes
TAM_SAL_PSS = 32                                   # sal de 32 bytes en PSS
TAM_MODULO_BYTES = TAM_CLAVE_BITS // 8             # 256 bytes
MAX_OAEP = TAM_MODULO_BYTES - 2 * TAM_HASH - 2     # 190 bytes

TEXTO_EJEMPLO = "Clave de sesion: 7f3a-91bc. Confidencial."


# ---------------------------------------------------------------------------
# Funciones criptográficas
# ---------------------------------------------------------------------------
def generar_par_rsa() -> rsa.RSAPrivateKey:
    """Genera un par RSA-2048 (la clave pública se obtiene con .public_key())."""
    return rsa.generate_private_key(public_exponent=EXPONENTE_PUBLICO, key_size=TAM_CLAVE_BITS)


def _oaep() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=TAM_SAL_PSS)


def cifrar_oaep(clave_publica: rsa.RSAPublicKey, datos: bytes) -> bytes:
    """Cifra datos CORTOS (máx. 190 bytes) con la clave pública. Lanza ValueError si exceden el límite."""
    return clave_publica.encrypt(datos, _oaep())


def descifrar_oaep(clave_privada: rsa.RSAPrivateKey, cifrado: bytes) -> bytes:
    """Descifra con la clave privada. Lanza ValueError si el cifrado es inválido o la clave no corresponde."""
    return clave_privada.decrypt(cifrado, _oaep())


def firmar_pss(clave_privada: rsa.RSAPrivateKey, mensaje: bytes) -> bytes:
    """Firma el mensaje (RSA calcula internamente el hash SHA-256 y firma ese hash)."""
    return clave_privada.sign(mensaje, _pss(), hashes.SHA256())


def verificar_pss(clave_publica: rsa.RSAPublicKey, mensaje: bytes, firma: bytes) -> bool:
    """Verifica la firma con la clave pública. True si es válida; False si no."""
    try:
        clave_publica.verify(firma, mensaje, _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def publica_a_pem(clave_publica: rsa.RSAPublicKey) -> bytes:
    return clave_publica.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def privada_a_pem(clave_privada: rsa.RSAPrivateKey, contrasena: str) -> bytes:
    """Exporta la clave privada CIFRADA con una contraseña (nunca se guarda en claro)."""
    return clave_privada.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(contrasena.encode("utf-8")))


def privada_desde_pem(pem: bytes, contrasena: str) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=contrasena.encode("utf-8"))


# ---------------------------------------------------------------------------
# Demostraciones
# ---------------------------------------------------------------------------
_par_en_memoria = None


def obtener_par() -> rsa.RSAPrivateKey:
    """Genera el par una sola vez por ejecución para no repetir el cálculo en cada demo."""
    global _par_en_memoria
    if _par_en_memoria is None:
        _par_en_memoria = generar_par_rsa()
    return _par_en_memoria


def demo_generar_par() -> bool:
    print("\n=== 1) GENERAR UN PAR DE CLAVES RSA-2048 ===")
    privada = obtener_par()
    publica = privada.public_key()
    nums = publica.public_numbers()
    print(f"  Tamaño del módulo n : {publica.key_size} bits")
    print(f"  Exponente público e : {nums.e}")
    print(f"  n (primeros 48 hex) : {format(nums.n, 'x')[:48]}...")
    print("  Clave PÚBLICA (se puede compartir libremente):")
    for linea in publica_a_pem(publica).decode().strip().splitlines()[:4]:
        print("    " + linea)
    print("    ...")
    print("  La clave PRIVADA se mantiene en secreto (aquí solo existe en memoria).")
    return publica.key_size == 2048 and nums.e == 65537


def demo_cifrar_descifrar(texto: str = TEXTO_EJEMPLO) -> bool:
    print("\n=== 2) CIFRAR CON LA PÚBLICA Y DESCIFRAR CON LA PRIVADA (RSA-OAEP) ===")
    privada = obtener_par()
    publica = privada.public_key()
    datos = texto.encode("utf-8")
    print(f"  Texto original : {texto}  ({len(datos)} bytes)")
    c1 = cifrar_oaep(publica, datos)
    c2 = cifrar_oaep(publica, datos)
    print(f"  Cifrado 1 ({len(c1)} bytes): {c1.hex()[:64]}...")
    print(f"  Cifrado 2 ({len(c2)} bytes): {c2.hex()[:64]}...")
    probabilistico = c1 != c2
    print(f"  [{'OK' if probabilistico else 'ERROR'}] El mismo mensaje cifra distinto cada vez (OAEP añade aleatoriedad).")
    recuperado = descifrar_oaep(privada, c1).decode("utf-8")
    ok = recuperado == texto
    print(f"  Texto recuperado con la clave privada: {recuperado}")
    print(f"  [{'OK' if ok else 'ERROR'}] El texto recuperado {'coincide' if ok else 'NO coincide'} con el original.")
    return ok and probabilistico


def demo_limite() -> bool:
    print(f"\n=== 3) LÍMITE DE TAMAÑO: RSA SOLO CIFRA DATOS CORTOS (máx. {MAX_OAEP} bytes) ===")
    publica = obtener_par().public_key()
    print(f"  Cálculo: {TAM_MODULO_BYTES} - 2 x {TAM_HASH} - 2 = {MAX_OAEP} bytes")
    cifrado = cifrar_oaep(publica, b"A" * MAX_OAEP)
    ok1 = len(cifrado) == TAM_MODULO_BYTES
    print(f"  [{'OK' if ok1 else 'ERROR'}] {MAX_OAEP} bytes: se cifra bien (resultado de {len(cifrado)} bytes).")
    try:
        cifrar_oaep(publica, b"A" * (MAX_OAEP + 1))
        print(f"  [ERROR] {MAX_OAEP + 1} bytes se cifraron (no debería).")
        return False
    except ValueError:
        print(f"  [OK] {MAX_OAEP + 1} bytes: RECHAZADO (el mensaje supera el máximo de {MAX_OAEP} bytes que admite RSA-2048 con OAEP-SHA-256)")
    print("  Por eso para archivos o mensajes largos se usa el esquema HÍBRIDO (ver hibrido_demo.py).")
    return ok1


def demo_firma(mensaje: str = "Autorizo la transferencia de 500 Bs a Leonardo.") -> bool:
    print("\n=== 4) FIRMA DIGITAL: FIRMAR CON LA PRIVADA, VERIFICAR CON LA PÚBLICA (RSA-PSS) ===")
    privada = obtener_par()
    publica = privada.public_key()
    datos = mensaje.encode("utf-8")
    firma1 = firmar_pss(privada, datos)
    firma2 = firmar_pss(privada, datos)
    print(f"  Mensaje : {mensaje}")
    print(f"  Firma 1 ({len(firma1)} bytes): {firma1.hex()[:64]}...")
    print(f"  Firma 2 ({len(firma2)} bytes): {firma2.hex()[:64]}...")
    distintas = firma1 != firma2
    validas = verificar_pss(publica, datos, firma1) and verificar_pss(publica, datos, firma2)
    print(f"  [{'OK' if distintas else 'ERROR'}] Las dos firmas son distintas (PSS usa una sal aleatoria de {TAM_SAL_PSS} bytes).")
    print(f"  [{'OK' if validas else 'ERROR'}] Ambas firmas son VÁLIDAS al verificarlas con la clave pública.")

    alterado = b"Autorizo la transferencia de 900 Bs a Leonardo."
    ok_alt = not verificar_pss(publica, alterado, firma1)
    print(f"  [{'OK' if ok_alt else 'ERROR'}] Mensaje modificado (500 -> 900): firma RECHAZADA (se detecta la alteración).")

    firma_mala = bytearray(firma1)
    firma_mala[10] ^= 0x01
    ok_firma = not verificar_pss(publica, datos, bytes(firma_mala))
    print(f"  [{'OK' if ok_firma else 'ERROR'}] Firma con 1 bit alterado: RECHAZADA.")

    otra_publica = generar_par_rsa().public_key()
    ok_otra = not verificar_pss(otra_publica, datos, firma1)
    print(f"  [{'OK' if ok_otra else 'ERROR'}] Verificada con la clave pública de OTRA persona: RECHAZADA (autenticidad).")
    print("  La firma aporta integridad, autenticidad y no repudio: solo el dueño de la clave privada pudo producirla.")
    return distintas and validas and ok_alt and ok_firma and ok_otra


def demo_guardar_clave() -> bool:
    print("\n=== 5) GUARDAR LA CLAVE PRIVADA PROTEGIDA CON CONTRASEÑA ===")
    privada = obtener_par()
    pem = privada_a_pem(privada, "contrasena-del-taller")
    print("  Clave privada exportada (PKCS#8 cifrada):")
    for linea in pem.decode().strip().splitlines()[:2]:
        print("    " + linea)
    print("    ...")
    recargada = privada_desde_pem(pem, "contrasena-del-taller")
    mensaje = b"prueba de recarga"
    ok = descifrar_oaep(recargada, cifrar_oaep(privada.public_key(), mensaje)) == mensaje
    print(f"  [{'OK' if ok else 'ERROR'}] La clave recargada con la contraseña correcta funciona.")
    try:
        privada_desde_pem(pem, "contrasena-incorrecta")
        print("  [ERROR] Se cargó con una contraseña incorrecta.")
        return False
    except ValueError:
        print("  [OK] Con una contraseña incorrecta la clave privada NO se puede cargar.")
    print("  Buena práctica: no usar el mismo par para cifrar y para firmar (en el taller el híbrido usa dos pares).")
    return ok


def demo_automatica() -> bool:
    resultados = [demo_generar_par(), demo_cifrar_descifrar(), demo_limite(), demo_firma(), demo_guardar_clave()]
    print("\n" + "=" * 60)
    print(f"RESULTADO FINAL: {sum(resultados)}/{len(resultados)} pruebas correctas")
    return all(resultados)


def ejecutar() -> None:
    """Menú interactivo (también lo llama main.py)."""
    while True:
        print("\n----- RSA-2048: OAEP y PSS (Taller A4) -----")
        print("1. Generar par de claves")
        print("2. Cifrar y descifrar un texto corto (OAEP)")
        print(f"3. Límite de tamaño ({MAX_OAEP} bytes)")
        print("4. Firmar y verificar un mensaje (PSS)")
        print("5. Guardar la clave privada con contraseña")
        print("6. Ejecutar todas las pruebas")
        print("0. Volver / salir")
        opcion = input("Elige una opción: ").strip()
        if opcion == "1":
            demo_generar_par()
        elif opcion == "2":
            t = input(f"Texto corto [{TEXTO_EJEMPLO}]: ").strip() or TEXTO_EJEMPLO
            try:
                demo_cifrar_descifrar(t)
            except ValueError as e:
                print(f"  RECHAZADO: {e} (¡el texto supera {MAX_OAEP} bytes!)")
        elif opcion == "3":
            demo_limite()
        elif opcion == "4":
            m = input("Mensaje a firmar [Enter = ejemplo]: ").strip()
            demo_firma(m) if m else demo_firma()
        elif opcion == "5":
            demo_guardar_clave()
        elif opcion == "6":
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
