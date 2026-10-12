# -*- coding: utf-8 -*-
"""Pruebas de tls_demo.py: servidor TLS 1.3 local (no necesitan internet)."""
import os
import socket
import ssl
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import tls_demo as t


class PruebasTLS(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.TemporaryDirectory()
        self.cert, clave = t.crear_certificado_autofirmado(self.carpeta.name)
        self.servidor = t.ServidorTLS(self.cert, clave).iniciar()

    def tearDown(self):
        self.servidor.detener()
        self.carpeta.cleanup()

    def _conectar(self, contexto, nombre="localhost"):
        crudo = socket.create_connection(("127.0.0.1", self.servidor.puerto), timeout=5)
        return contexto.wrap_socket(crudo, server_hostname=nombre)

    def test_conexion_tls13_y_eco(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        with self._conectar(ctx) as s:
            self.assertEqual(s.version(), "TLSv1.3")
            self.assertIn(s.cipher()[0], ("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"))
            s.sendall(b"hola")
            self.assertEqual(s.recv(100), b"ECO: hola")

    def test_certificado_desconocido_se_rechaza(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self._conectar(ssl.create_default_context())

    def test_nombre_de_servidor_incorrecto_se_rechaza(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        with self.assertRaises(ssl.SSLCertVerificationError):
            self._conectar(ctx, nombre="otro-sitio.com")

    def test_cliente_tls12_es_rechazado(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        with self.assertRaises(ssl.SSLError):
            self._conectar(ctx)

    def test_el_servidor_sigue_vivo_tras_un_rechazo(self):
        with self.assertRaises(ssl.SSLError):
            self._conectar(ssl.create_default_context())
        ctx = ssl.create_default_context(cafile=self.cert)
        with self._conectar(ctx) as s:
            s.sendall(b"otra vez")
            self.assertEqual(s.recv(100), b"ECO: otra vez")

    def test_certificado_x509_generado(self):
        from cryptography import x509
        with open(self.cert, "rb") as f:
            c = x509.load_pem_x509_certificate(f.read())
        self.assertEqual(c.public_key().key_size, 2048)
        self.assertEqual(c.subject, c.issuer)                      # autofirmado
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("localhost", san.get_values_for_type(x509.DNSName))


if __name__ == "__main__":
    unittest.main()
