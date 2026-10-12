# -*- coding: utf-8 -*-
"""
tls_demo.py  -  Taller A4 · Seguridad Informática I (Universidad Domingo Savio)

Abre una conexión TLS y MUESTRA la versión del protocolo, la suite de cifrado negociada
y el certificado X.509 del servidor. Es la parte práctica de HTTPS / TLS 1.3 del informe A3.

Dos modos:
  A) LOCAL (no necesita internet): el programa crea su propia autoridad de certificación de
     juguete (certificado autofirmado), levanta un servidor TLS 1.3 en tu computadora y se
     conecta a él. Sirve para demostrar el handshake y los rechazos.
  B) SITIO REAL (necesita internet): se conecta a un sitio HTTPS verdadero y muestra qué
     versión y qué suite negoció, y su certificado.

Qué se demuestra (relación con el informe):
  * El handshake TLS 1.3 negocia una suite AEAD (AES-GCM o ChaCha20-Poly1305): cifrado simétrico.
  * El servidor se autentica con un certificado X.509 (clave pública + identidad, firmado).
  * El cliente VERIFICA el certificado: si no confía en quien lo firmó, rechaza la conexión.
  * Un servidor que exige TLS 1.3 rechaza a un cliente que solo habla TLS 1.2 o menor.
  * Nombre SSL: SSL y TLS 1.0/1.1 están obsoletos; hoy se usan TLS 1.2 y, sobre todo, TLS 1.3.

Uso:
    python tls_demo.py          -> menú interactivo
    python tls_demo.py --auto   -> ejecuta las pruebas locales (y el sitio real si hay internet)
"""

import datetime
import ipaddress
import os
import socket
import ssl
import sys
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

NOMBRE_SERVIDOR = "localhost"
SITIO_REAL_POR_DEFECTO = "www.wikipedia.org"


# ---------------------------------------------------------------------------
# Certificado de prueba (autofirmado) con la biblioteca cryptography
# ---------------------------------------------------------------------------
def crear_certificado_autofirmado(carpeta: str):
    """Crea una clave RSA-2048 y un certificado X.509 autofirmado válido para 'localhost'.
    Devuelve las rutas (certificado.pem, clave.pem). Es un certificado de PRUEBA."""
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nombre = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BO"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Taller A4 - Seguridad Informatica I"),
        x509.NameAttribute(NameOID.COMMON_NAME, NOMBRE_SERVIDOR),
    ])
    ahora = datetime.datetime.now(datetime.timezone.utc)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)                                   # autofirmado: emisor = sujeto
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - datetime.timedelta(minutes=5))
        .not_valid_after(ahora + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(NOMBRE_SERVIDOR), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(clave, hashes.SHA256())
    )
    ruta_cert = os.path.join(carpeta, "servidor.crt")
    ruta_clave = os.path.join(carpeta, "servidor.key")
    with open(ruta_cert, "wb") as f:
        f.write(certificado.public_bytes(serialization.Encoding.PEM))
    with open(ruta_clave, "wb") as f:
        f.write(clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return ruta_cert, ruta_clave


# ---------------------------------------------------------------------------
# Servidor TLS local (en un hilo) que solo acepta TLS 1.3
# ---------------------------------------------------------------------------
class ServidorTLS:
    """Servidor de eco: responde lo que recibe, con el prefijo 'ECO: '. Mínimo TLS 1.3."""

    def __init__(self, ruta_cert: str, ruta_clave: str):
        self.contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.contexto.minimum_version = ssl.TLSVersion.TLSv1_3     # rechaza TLS 1.2 y anteriores
        self.contexto.load_cert_chain(ruta_cert, ruta_clave)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))                          # puerto libre elegido por el sistema
        self.socket.listen(5)
        self.socket.settimeout(0.3)
        self.puerto = self.socket.getsockname()[1]
        self._detener = threading.Event()
        self._hilo = threading.Thread(target=self._atender, daemon=True)

    def iniciar(self):
        self._hilo.start()
        return self

    def _atender(self):
        while not self._detener.is_set():
            try:
                conexion, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conexion.settimeout(5)
                with self.contexto.wrap_socket(conexion, server_side=True) as seguro:
                    datos = seguro.recv(4096)
                    if datos:
                        seguro.sendall(b"ECO: " + datos)
            except (ssl.SSLError, OSError):
                pass                                               # handshake rechazado: el servidor sigue vivo
            finally:
                try:
                    conexion.close()
                except OSError:
                    pass

    def detener(self):
        self._detener.set()
        self._hilo.join(timeout=2)
        self.socket.close()


# ---------------------------------------------------------------------------
# Mostrar lo negociado y el certificado
# ---------------------------------------------------------------------------
def describir_certificado(der: bytes) -> None:
    cert = x509.load_der_x509_certificate(der)
    clave = cert.public_key()
    tipo = type(clave).__name__.replace("_", "").replace("PublicKey", "")
    tam = getattr(clave, "key_size", "?")
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        nombres = ", ".join(san.get_values_for_type(x509.DNSName)[:4]) or "(sin DNS)"
    except x509.ExtensionNotFound:
        nombres = "(sin SAN)"
    hash_firma = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?"
    print("  CERTIFICADO X.509 DEL SERVIDOR:")
    print(f"    Sujeto (a quién pertenece) : {cert.subject.rfc4514_string()}")
    print(f"    Emisor (quién lo firmó)    : {cert.issuer.rfc4514_string()}")
    print(f"    Válido desde / hasta       : {cert.not_valid_before_utc:%Y-%m-%d} / {cert.not_valid_after_utc:%Y-%m-%d}")
    print(f"    Nombres (SAN)              : {nombres}")
    print(f"    Clave pública              : {tipo} de {tam} bits")
    print(f"    Firma del certificado      : {hash_firma} ({cert.signature_algorithm_oid._name})")


def describir_conexion(seguro: ssl.SSLSocket) -> dict:
    version = seguro.version()
    nombre_suite, _, bits = seguro.cipher()
    print(f"  Versión del protocolo      : {version}")
    print(f"  Suite de cifrado negociada : {nombre_suite} ({bits} bits de clave simétrica)")
    print("    -> en TLS 1.3 la suite indica el cifrado AEAD (simétrico) y el hash; el acuerdo de claves es ECDHE.")
    describir_certificado(seguro.getpeercert(binary_form=True))
    return {"version": version, "suite": nombre_suite, "bits": bits}


# ---------------------------------------------------------------------------
# Demostraciones
# ---------------------------------------------------------------------------
def _con_servidor_local(funcion) -> bool:
    with tempfile.TemporaryDirectory() as carpeta:
        ruta_cert, ruta_clave = crear_certificado_autofirmado(carpeta)
        servidor = ServidorTLS(ruta_cert, ruta_clave).iniciar()
        try:
            return funcion(servidor, ruta_cert)
        finally:
            servidor.detener()


def demo_local_exitosa() -> bool:
    print("\n=== 1) CONEXIÓN TLS 1.3 LOCAL (el cliente CONFÍA en el certificado) ===")

    def prueba(servidor, ruta_cert):
        contexto = ssl.create_default_context(cafile=ruta_cert)    # el cliente confía SOLO en nuestro certificado
        contexto.minimum_version = ssl.TLSVersion.TLSv1_3
        print(f"  Servidor TLS local escuchando en 127.0.0.1:{servidor.puerto} (solo TLS 1.3)")
        with socket.create_connection(("127.0.0.1", servidor.puerto), timeout=5) as crudo:
            with contexto.wrap_socket(crudo, server_hostname=NOMBRE_SERVIDOR) as seguro:
                info = describir_conexion(seguro)
                seguro.sendall("Hola servidor, este mensaje viaja cifrado.".encode("utf-8"))
                respuesta = seguro.recv(4096).decode("utf-8")
                print(f"  Mensaje enviado  : Hola servidor, este mensaje viaja cifrado.")
                print(f"  Respuesta        : {respuesta}")
        ok = info["version"] == "TLSv1.3" and respuesta.startswith("ECO: ")
        print(f"  [{'OK' if ok else 'ERROR'}] Handshake TLS 1.3 completado e intercambio de datos protegido.")
        return ok
    return _con_servidor_local(prueba)


def demo_certificado_no_confiable() -> bool:
    print("\n=== 2) EL CLIENTE NO CONFÍA EN EL CERTIFICADO (autoridad desconocida) ===")

    def prueba(servidor, _ruta_cert):
        contexto = ssl.create_default_context()                    # confía solo en las autoridades del sistema
        try:
            with socket.create_connection(("127.0.0.1", servidor.puerto), timeout=5) as crudo:
                with contexto.wrap_socket(crudo, server_hostname=NOMBRE_SERVIDOR):
                    print("  [ERROR] Se aceptó un certificado autofirmado desconocido.")
                    return False
        except ssl.SSLCertVerificationError as e:
            print(f"  [OK] RECHAZADO: {e.verify_message}")
            print("       El navegador mostraría 'Su conexión no es privada'. Ningún dato se envió.")
            return True
    return _con_servidor_local(prueba)


def demo_version_antigua() -> bool:
    print("\n=== 3) CLIENTE QUE SOLO HABLA TLS 1.2 CONTRA UN SERVIDOR QUE EXIGE TLS 1.3 ===")

    def prueba(servidor, ruta_cert):
        contexto = ssl.create_default_context(cafile=ruta_cert)
        contexto.maximum_version = ssl.TLSVersion.TLSv1_2          # simula un cliente antiguo
        try:
            with socket.create_connection(("127.0.0.1", servidor.puerto), timeout=5) as crudo:
                with contexto.wrap_socket(crudo, server_hostname=NOMBRE_SERVIDOR):
                    print("  [ERROR] Se negoció una versión antigua (no debería).")
                    return False
        except ssl.SSLError as e:
            print(f"  [OK] RECHAZADO: no hay una versión de protocolo en común ({e.reason or 'protocol version'}).")
            print("       SSL 3.0, TLS 1.0 y TLS 1.1 están obsoletos y los servidores modernos los rechazan.")
            return True
    return _con_servidor_local(prueba)


def demo_sitio_real(host: str = SITIO_REAL_POR_DEFECTO) -> bool:
    print(f"\n=== 4) SITIO REAL: {host}:443 (necesita internet) ===")
    contexto = ssl.create_default_context()                        # usa las autoridades de confianza del sistema
    try:
        with socket.create_connection((host, 443), timeout=8) as crudo:
            with contexto.wrap_socket(crudo, server_hostname=host) as seguro:
                info = describir_conexion(seguro)
        ok = info["version"] in ("TLSv1.2", "TLSv1.3")
        print(f"  [{'OK' if ok else 'ERROR'}] Conexión verificada contra las autoridades de confianza del sistema.")
        return ok
    except (OSError, ssl.SSLError) as e:
        print(f"  [AVISO] No se pudo conectar ({type(e).__name__}: {e}).")
        print("          Revisa tu conexión a internet; esta prueba es opcional y no afecta a las demás.")
        return None                                                # prueba omitida: no es un fallo del programa


def demo_automatica() -> bool:
    resultados = [demo_local_exitosa(), demo_certificado_no_confiable(), demo_version_antigua(), demo_sitio_real()]
    omitidas = sum(1 for r in resultados if r is None)      # el sitio real se omite si no hay internet
    validas = [r for r in resultados if r is not None]
    print("\n" + "=" * 60)
    extra = f" ({omitidas} omitida por falta de internet)" if omitidas else ""
    print(f"RESULTADO FINAL: {sum(validas)}/{len(validas)} pruebas correctas{extra}")
    return all(validas)


def ejecutar() -> None:
    """Menú interactivo (también lo llama main.py)."""
    while True:
        print("\n----- TLS 1.3 y certificados X.509 (Taller A4) -----")
        print("1. Conexión TLS 1.3 local (sin internet)")
        print("2. Certificado no confiable (rechazo)")
        print("3. Cliente con TLS antiguo (rechazo)")
        print("4. Conectarme a un sitio real (internet)")
        print("5. Ejecutar todas las pruebas")
        print("0. Volver / salir")
        opcion = input("Elige una opción: ").strip()
        if opcion == "1":
            demo_local_exitosa()
        elif opcion == "2":
            demo_certificado_no_confiable()
        elif opcion == "3":
            demo_version_antigua()
        elif opcion == "4":
            h = input(f"Sitio [{SITIO_REAL_POR_DEFECTO}]: ").strip() or SITIO_REAL_POR_DEFECTO
            demo_sitio_real(h)
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
