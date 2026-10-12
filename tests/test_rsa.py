# -*- coding: utf-8 -*-
"""Pruebas de rsa_demo.py: RSA-2048 con OAEP (cifrar) y PSS (firmar)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import rsa_demo as r


class PruebasRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.privada = r.generar_par_rsa()
        cls.publica = cls.privada.public_key()

    def test_parametros_del_par(self):
        self.assertEqual(self.publica.key_size, 2048)
        self.assertEqual(self.publica.public_numbers().e, 65537)

    def test_cifrar_y_descifrar_oaep(self):
        c = r.cifrar_oaep(self.publica, b"clave secreta")
        self.assertEqual(len(c), 256)
        self.assertEqual(r.descifrar_oaep(self.privada, c), b"clave secreta")

    def test_oaep_es_probabilistico(self):
        self.assertNotEqual(r.cifrar_oaep(self.publica, b"igual"), r.cifrar_oaep(self.publica, b"igual"))

    def test_limite_de_190_bytes(self):
        self.assertEqual(r.MAX_OAEP, 190)
        self.assertEqual(r.descifrar_oaep(self.privada, r.cifrar_oaep(self.publica, b"A" * 190)), b"A" * 190)
        with self.assertRaises(ValueError):
            r.cifrar_oaep(self.publica, b"A" * 191)

    def test_otra_clave_privada_no_descifra(self):
        c = r.cifrar_oaep(self.publica, b"secreto")
        with self.assertRaises(ValueError):
            r.descifrar_oaep(r.generar_par_rsa(), c)

    def test_cifrado_alterado_se_rechaza(self):
        c = bytearray(r.cifrar_oaep(self.publica, b"secreto"))
        c[5] ^= 1
        with self.assertRaises(ValueError):
            r.descifrar_oaep(self.privada, bytes(c))

    def test_firma_valida(self):
        firma = r.firmar_pss(self.privada, b"mensaje")
        self.assertEqual(len(firma), 256)
        self.assertTrue(r.verificar_pss(self.publica, b"mensaje", firma))

    def test_pss_es_probabilistico_pero_ambas_firmas_validan(self):
        f1, f2 = r.firmar_pss(self.privada, b"m"), r.firmar_pss(self.privada, b"m")
        self.assertNotEqual(f1, f2)
        self.assertTrue(r.verificar_pss(self.publica, b"m", f1) and r.verificar_pss(self.publica, b"m", f2))

    def test_mensaje_firmado_alterado_se_rechaza(self):
        firma = r.firmar_pss(self.privada, b"500 Bs")
        self.assertFalse(r.verificar_pss(self.publica, b"900 Bs", firma))

    def test_firma_alterada_se_rechaza(self):
        firma = bytearray(r.firmar_pss(self.privada, b"m"))
        firma[10] ^= 1
        self.assertFalse(r.verificar_pss(self.publica, b"m", bytes(firma)))

    def test_firma_con_otra_clave_publica_se_rechaza(self):
        firma = r.firmar_pss(self.privada, b"m")
        self.assertFalse(r.verificar_pss(r.generar_par_rsa().public_key(), b"m", firma))

    def test_clave_privada_cifrada_con_contrasena(self):
        pem = r.privada_a_pem(self.privada, "pw")
        self.assertIn(b"ENCRYPTED PRIVATE KEY", pem)
        recargada = r.privada_desde_pem(pem, "pw")
        self.assertEqual(r.descifrar_oaep(recargada, r.cifrar_oaep(self.publica, b"x")), b"x")
        with self.assertRaises(ValueError):
            r.privada_desde_pem(pem, "otra")

    def test_demo_automatica(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(r.demo_automatica())


if __name__ == "__main__":
    unittest.main()
