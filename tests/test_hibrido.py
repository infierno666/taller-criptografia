# -*- coding: utf-8 -*-
"""Pruebas de hibrido_demo.py: RSA-OAEP protege la clave AES y AES-256-GCM cifra los datos."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import hibrido_demo as h
import rsa_demo


class PruebasHibrido(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receptor = rsa_demo.generar_par_rsa()
        cls.emisor = rsa_demo.generar_par_rsa()

    def test_mensaje_largo_con_firma(self):
        datos = os.urandom(1024 * 1024)       # 1 MB: imposible con RSA directo
        p = h.cifrar_hibrido(datos, self.receptor.public_key(), self.emisor)
        self.assertEqual(h.descifrar_hibrido(p, self.receptor, self.emisor.public_key()), datos)

    def test_mensaje_largo_sin_firma(self):
        datos = b"texto largo " * 1000
        p = h.cifrar_hibrido(datos, self.receptor.public_key())
        self.assertEqual(h.descifrar_hibrido(p, self.receptor), datos)

    def test_rsa_directo_no_puede_con_mensajes_largos(self):
        with self.assertRaises(ValueError):
            rsa_demo.cifrar_oaep(self.receptor.public_key(), b"x" * 1000)

    def test_estructura_del_paquete(self):
        datos = b"x" * 100
        p = h.cifrar_hibrido(datos, self.receptor.public_key(), self.emisor)
        self.assertEqual(len(p), 256 + 12 + 100 + 16 + 256)     # clave + nonce + datos + etiqueta + firma

    def test_mismo_mensaje_da_paquetes_distintos(self):
        a = h.cifrar_hibrido(b"igual", self.receptor.public_key())
        b = h.cifrar_hibrido(b"igual", self.receptor.public_key())
        self.assertNotEqual(a, b)

    def test_dato_alterado_con_firma_se_rechaza(self):
        p = bytearray(h.cifrar_hibrido(b"contrato" * 50, self.receptor.public_key(), self.emisor))
        p[256 + 12 + 3] ^= 1
        with self.assertRaises(h.PaqueteInvalido):
            h.descifrar_hibrido(bytes(p), self.receptor, self.emisor.public_key())

    def test_dato_alterado_sin_firma_lo_rechaza_aes_gcm(self):
        p = bytearray(h.cifrar_hibrido(b"contrato" * 50, self.receptor.public_key()))
        p[256 + 12 + 3] ^= 1
        with self.assertRaises(h.PaqueteInvalido):
            h.descifrar_hibrido(bytes(p), self.receptor)

    def test_clave_de_sesion_alterada_la_rechaza_oaep(self):
        p = bytearray(h.cifrar_hibrido(b"contrato", self.receptor.public_key()))
        p[10] ^= 1
        with self.assertRaises(h.PaqueteInvalido):
            h.descifrar_hibrido(bytes(p), self.receptor)

    def test_tercero_no_puede_descifrar(self):
        p = h.cifrar_hibrido(b"secreto", self.receptor.public_key())
        with self.assertRaises(h.PaqueteInvalido):
            h.descifrar_hibrido(p, rsa_demo.generar_par_rsa())

    def test_suplantacion_del_emisor(self):
        p = h.cifrar_hibrido(b"secreto", self.receptor.public_key(), self.emisor)
        with self.assertRaises(h.PaqueteInvalido):
            h.descifrar_hibrido(p, self.receptor, rsa_demo.generar_par_rsa().public_key())

    def test_paquete_corto(self):
        with self.assertRaises(h.PaqueteInvalido):
            h.descifrar_hibrido(b"corto", self.receptor)

    def test_archivo_ida_y_vuelta(self):
        with tempfile.TemporaryDirectory() as d:
            origen, enc, dec = (os.path.join(d, n) for n in ("a.bin", "a.hib", "a.out"))
            contenido = os.urandom(200000)
            with open(origen, "wb") as f:
                f.write(contenido)
            h.cifrar_archivo(origen, enc, self.receptor.public_key(), self.emisor)
            h.descifrar_archivo(enc, dec, self.receptor, self.emisor.public_key())
            with open(dec, "rb") as f:
                self.assertEqual(f.read(), contenido)
            with open(enc, "rb") as f:
                self.assertNotIn(contenido[:64], f.read())      # el archivo cifrado no contiene el original

    def test_demo_automatica(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(h.demo_automatica())


if __name__ == "__main__":
    unittest.main()
