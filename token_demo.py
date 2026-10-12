# -*- coding: utf-8 -*-
"""
token_demo.py  -  Taller A4 · Seguridad Informática I (Universidad Domingo Savio)

Crea y verifica un TOKEN FIRMADO con HMAC-SHA-256, al estilo de un JWT con HS256
(JSON Web Token, RFC 7519; firma JWS, RFC 7515; algoritmos, RFC 7518).

Estructura de un token (tres partes en Base64url separadas por puntos):
    encabezado.carga_util.firma
    - encabezado : {"alg":"HS256","typ":"JWT"}
    - carga útil : afirmaciones (claims): quién es el usuario, cuándo expira, etc.
    - firma      : HMAC-SHA-256(secreto, "encabezado.carga_util")

IMPORTANTE (informe A3, sección de tokens): un JWT firmado NO está cifrado.
Cualquiera puede LEER la carga útil; lo que la firma garantiza es que NO fue
MODIFICADA. Por eso no se debe poner información secreta dentro del token.

Buenas prácticas que implementa la verificación (RFC 8725):
  * Solo acepta el algoritmo HS256 (rechaza "none" y cualquier otro).
  * Compara la firma en tiempo constante.
  * Exige fecha de expiración (exp) y la comprueba.

Uso:
    python token_demo.py          -> menú interactivo
    python token_demo.py --auto   -> ejecuta todas las pruebas sin pedir datos
"""

import base64
import json
import os
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac

ALGORITMO = "HS256"

# Token de ejemplo oficial del RFC 7515 (Apéndice A.1), para probar interoperabilidad
# con cualquier otra implementación estándar de JWT/JWS.
RFC7515_CLAVE = ("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
RFC7515_TOKEN = ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
                 "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
                 "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")


# ---------------------------------------------------------------------------
# Errores propios (permiten explicar POR QUÉ se rechazó un token)
# ---------------------------------------------------------------------------
class TokenError(Exception):
    """Clase base de los errores de verificación."""


class TokenMalformado(TokenError):
    pass


class AlgoritmoNoPermitido(TokenError):
    pass


class FirmaInvalida(TokenError):
    pass


class TokenExpirado(TokenError):
    pass


# ---------------------------------------------------------------------------
# Base64url (variante de Base64 segura para URLs, sin relleno "=")
# Se usa solo para CODIFICAR; no es cifrado.
# ---------------------------------------------------------------------------
def b64url_codificar(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).decode("ascii").rstrip("=")


def b64url_decodificar(texto: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))
    except Exception as e:
        raise TokenMalformado("Parte del token con Base64url inválido.") from e


def _json_a_b64url(objeto: dict) -> str:
    return b64url_codificar(json.dumps(objeto, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _firmar(secreto: bytes, mensaje: bytes) -> bytes:
    m = hmac.HMAC(secreto, hashes.SHA256())
    m.update(mensaje)
    return m.finalize()


# ---------------------------------------------------------------------------
# Crear y verificar
# ---------------------------------------------------------------------------
def crear_token(secreto: bytes, claims: dict, vigencia_segundos: int = 3600, ahora: float = None) -> str:
    """Crea un token HS256. Añade iat (emitido en) y exp (expira en)."""
    ahora = int(time.time() if ahora is None else ahora)
    carga = dict(claims)
    carga["iat"] = ahora
    carga["exp"] = ahora + vigencia_segundos
    encabezado = {"alg": ALGORITMO, "typ": "JWT"}
    firmando = f"{_json_a_b64url(encabezado)}.{_json_a_b64url(carga)}"
    firma = _firmar(secreto, firmando.encode("ascii"))
    return f"{firmando}.{b64url_codificar(firma)}"


def verificar_token(token: str, secreto: bytes, ahora: float = None) -> dict:
    """Verifica un token y devuelve sus claims. Lanza un TokenError si algo falla."""
    partes = token.split(".")
    if len(partes) != 3:
        raise TokenMalformado("Un token debe tener exactamente 3 partes separadas por puntos.")
    parte_enc, parte_carga, parte_firma = partes

    # 1) Encabezado: solo se acepta HS256 (esto bloquea el ataque del algoritmo "none"
    #    y la confusión HS256/RS256).
    try:
        encabezado = json.loads(b64url_decodificar(parte_enc))
    except (ValueError, TokenMalformado) as e:
        raise TokenMalformado("El encabezado no es un JSON válido.") from e
    if not isinstance(encabezado, dict) or encabezado.get("alg") != ALGORITMO:
        raise AlgoritmoNoPermitido(f"Algoritmo no permitido: {encabezado.get('alg') if isinstance(encabezado, dict) else '?'}")

    # 2) Firma: se recalcula y se compara en tiempo constante (verify lo hace la biblioteca).
    m = hmac.HMAC(secreto, hashes.SHA256())
    m.update(f"{parte_enc}.{parte_carga}".encode("ascii"))
    try:
        m.verify(b64url_decodificar(parte_firma))
    except InvalidSignature as e:
        raise FirmaInvalida("La firma no coincide: el token fue modificado o el secreto es otro.") from e

    # 3) Solo ahora se confía en la carga útil; se comprueba la expiración.
    try:
        carga = json.loads(b64url_decodificar(parte_carga))
    except ValueError as e:
        raise TokenMalformado("La carga útil no es un JSON válido.") from e
    if "exp" not in carga:
        raise TokenMalformado("El token no tiene fecha de expiración (exp).")
    ahora = time.time() if ahora is None else ahora
    if ahora >= carga["exp"]:
        raise TokenExpirado("El token ya expiró.")
    return carga


# ---------------------------------------------------------------------------
# Demostraciones
# ---------------------------------------------------------------------------
def _probar_rechazo(titulo: str, token: str, secreto: bytes, error_esperado, ahora: float = None) -> bool:
    try:
        verificar_token(token, secreto, ahora)
        print(f"  [ERROR] {titulo}: el token fue ACEPTADO (no debería).")
        return False
    except error_esperado as e:
        print(f"  [OK] RECHAZADO ({type(e).__name__}): {e}")
        return True


def demo_crear_y_verificar() -> bool:
    print("\n=== 1) CREAR Y VERIFICAR UN TOKEN (HMAC-SHA-256, estilo JWT HS256) ===")
    secreto = os.urandom(32)      # HS256 exige un secreto de al menos 256 bits (RFC 7518)
    token = crear_token(secreto, {"sub": "daniel", "rol": "usuario", "iss": "taller-a4"}, vigencia_segundos=3600)
    enc, carga, firma = token.split(".")
    print(f"  Token completo:\n    {token}\n")
    print(f"  Parte 1 (encabezado): {enc}")
    print(f"     decodificada     : {b64url_decodificar(enc).decode()}")
    print(f"  Parte 2 (carga útil): {carga}")
    print(f"     decodificada     : {b64url_decodificar(carga).decode()}")
    print(f"  Parte 3 (firma)     : {firma}")
    print("\n  Observa: la carga útil se lee sin ninguna clave. El token está FIRMADO, no CIFRADO.")
    claims = verificar_token(token, secreto)
    ok = claims["sub"] == "daniel" and claims["rol"] == "usuario"
    print(f"  [{'OK' if ok else 'ERROR'}] Verificación correcta. Claims recuperados: {claims}")
    return ok


def demo_manipulacion() -> bool:
    print("\n=== 2) MANIPULACIÓN: UN USUARIO INTENTA CONVERTIRSE EN ADMINISTRADOR ===")
    secreto = os.urandom(32)
    token = crear_token(secreto, {"sub": "daniel", "rol": "usuario"})
    enc, carga, firma = token.split(".")
    datos = json.loads(b64url_decodificar(carga))
    datos["rol"] = "admin"                                   # el atacante edita la carga útil
    carga_falsa = _json_a_b64url(datos)
    falso = f"{enc}.{carga_falsa}.{firma}"                   # conserva la firma original
    print(f"  Carga útil alterada: {b64url_decodificar(carga_falsa).decode()}")
    return _probar_rechazo("manipulación", falso, secreto, FirmaInvalida)


def demo_expirado() -> bool:
    print("\n=== 3) TOKEN EXPIRADO ===")
    secreto = os.urandom(32)
    emitido_hace_2_horas = time.time() - 7200
    token = crear_token(secreto, {"sub": "daniel"}, vigencia_segundos=3600, ahora=emitido_hace_2_horas)
    print("  Token emitido hace 2 horas con vigencia de 1 hora.")
    return _probar_rechazo("expirado", token, secreto, TokenExpirado)


def demo_algoritmo_none() -> bool:
    print("\n=== 4) ATAQUE DEL ALGORITMO \"none\" (token sin firma) ===")
    secreto = os.urandom(32)
    enc = _json_a_b64url({"alg": "none", "typ": "JWT"})
    carga = _json_a_b64url({"sub": "atacante", "rol": "admin", "exp": int(time.time()) + 3600})
    sin_firma = f"{enc}.{carga}."
    print("  El atacante fabrica un token con alg=none y sin firma.")
    return _probar_rechazo("alg none", sin_firma, secreto, AlgoritmoNoPermitido)


def demo_secreto_incorrecto() -> bool:
    print("\n=== 5) VERIFICAR CON OTRO SECRETO ===")
    token = crear_token(os.urandom(32), {"sub": "daniel"})
    return _probar_rechazo("secreto incorrecto", token, os.urandom(32), FirmaInvalida)


def demo_interoperabilidad() -> bool:
    print("\n=== 6) INTEROPERABILIDAD: TOKEN DE EJEMPLO OFICIAL DEL RFC 7515 ===")
    clave = b64url_decodificar(RFC7515_CLAVE)
    partes = RFC7515_TOKEN.split(".")
    m = hmac.HMAC(clave, hashes.SHA256())
    m.update(f"{partes[0]}.{partes[1]}".encode("ascii"))
    ok_firma = b64url_codificar(m.finalize()) == partes[2]
    print("  Se recalcula la firma HS256 del token publicado en el RFC 7515 con su clave de ejemplo.")
    print(f"  [{'OK' if ok_firma else 'ERROR'}] La firma calculada por este programa coincide con la del estándar.")
    # El token del RFC ya expiró (año 2011): la firma es válida pero verificar_token lo rechaza por exp.
    ok_exp = _probar_rechazo("token del RFC", RFC7515_TOKEN, clave, TokenExpirado)
    # Con una fecha de referencia anterior a su expiración, se acepta:
    claims = verificar_token(RFC7515_TOKEN, clave, ahora=1300819000)
    ok_acepta = claims.get("iss") == "joe"
    print(f"  [{'OK' if ok_acepta else 'ERROR'}] Con fecha de referencia anterior a su expiración se acepta: iss={claims.get('iss')}")
    return ok_firma and ok_exp and ok_acepta


def demo_automatica() -> bool:
    resultados = [demo_crear_y_verificar(), demo_manipulacion(), demo_expirado(),
                  demo_algoritmo_none(), demo_secreto_incorrecto(), demo_interoperabilidad()]
    print("\n" + "=" * 60)
    print(f"RESULTADO FINAL: {sum(resultados)}/{len(resultados)} pruebas correctas")
    return all(resultados)


def ejecutar() -> None:
    """Menú interactivo (también lo llama main.py)."""
    while True:
        print("\n----- Token HMAC-SHA-256 / JWT HS256 (Taller A4) -----")
        print("1. Crear y verificar un token")
        print("2. Probar manipulación (cambiar rol a admin)")
        print("3. Probar token expirado")
        print("4. Probar ataque del algoritmo none")
        print("5. Probar secreto incorrecto")
        print("6. Interoperabilidad con el ejemplo del RFC 7515")
        print("7. Ejecutar todas las pruebas")
        print("0. Volver / salir")
        opcion = input("Elige una opción: ").strip()
        acciones = {"1": demo_crear_y_verificar, "2": demo_manipulacion, "3": demo_expirado,
                    "4": demo_algoritmo_none, "5": demo_secreto_incorrecto, "6": demo_interoperabilidad,
                    "7": demo_automatica}
        if opcion in acciones:
            acciones[opcion]()
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
