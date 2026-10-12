# -*- coding: utf-8 -*-
"""Pruebas de hash_demo.py: SHA-256 y HMAC-SHA-256 contra vectores oficiales y la biblioteca estándar."""
import hashlib
import hmac as hmac_std
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import hash_demo as h


class PruebasHash(unittest.TestCase):
    def test_vectores_oficiales_fips_180_4(self):
        self.assertEqual(h.sha256_texto("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(h.sha256_texto(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        largo = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        self.assertEqual(h.sha256_texto(largo), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")

    def test_valores_del_informe(self):
        self.assertEqual(h.sha256_texto("Hola mundo"), "ca8f60b2cc7f05837d98b208b57fb6481553fc5f1219d59618fd025002a66f5c")
        self.assertEqual(h.sha256_texto("hola mundo"), "0b894166d3336435c800bea36ff21b29eaa801a52f584c006c49289a0dcf6e2f")

    def test_coincide_con_hashlib(self):
        for n in (0, 1, 55, 56, 64, 1000, 100000):
            datos = os.urandom(n)
            self.assertEqual(h.sha256_bytes(datos).hex(), hashlib.sha256(datos).hexdigest())

    def test_longitud_fija_de_256_bits(self):
        self.assertEqual(len(h.sha256_bytes(b"a")), 32)
        self.assertEqual(len(h.sha256_bytes(os.urandom(10000))), 32)

    def test_efecto_avalancha(self):
        d = h.bits_distintos(h.sha256_bytes(b"Hola mundo"), h.sha256_bytes(b"hola mundo"))
        self.assertTrue(90 <= d <= 166, d)       # alrededor de 128 de 256 bits

    def test_hash_de_archivo_coincide_con_hashlib(self):
        contenido = os.urandom(300000)           # mayor que el trozo de lectura de 64 KiB
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(contenido)
            ruta = f.name
        try:
            self.assertEqual(h.sha256_archivo(ruta), hashlib.sha256(contenido).hexdigest())
        finally:
            os.remove(ruta)

    def test_hmac_vector_rfc_4231_caso_1(self):
        etiqueta = h.hmac_sha256(b"\x0b" * 20, b"Hi There")
        self.assertEqual(etiqueta.hex(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

    def test_hmac_coincide_con_biblioteca_estandar(self):
        clave, msg = os.urandom(32), os.urandom(500)
        self.assertEqual(h.hmac_sha256(clave, msg), hmac_std.new(clave, msg, hashlib.sha256).digest())

    def test_verificar_hmac(self):
        clave, msg = os.urandom(32), b"Transferir 100"
        etiqueta = h.hmac_sha256(clave, msg)
        self.assertTrue(h.verificar_hmac(clave, msg, etiqueta))
        self.assertFalse(h.verificar_hmac(clave, b"Transferir 900", etiqueta))      # mensaje alterado
        self.assertFalse(h.verificar_hmac(os.urandom(32), msg, etiqueta))           # clave incorrecta
        malo = bytearray(etiqueta)
        malo[0] ^= 1
        self.assertFalse(h.verificar_hmac(clave, msg, bytes(malo)))                  # etiqueta alterada

    def test_demo_automatica(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(h.demo_automatica())


if __name__ == "__main__":
    unittest.main()
