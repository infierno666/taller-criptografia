# -*- coding: utf-8 -*-
"""Pruebas de aes_demo.py: AES-256-GCM con clave derivada por scrypt."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.exceptions import InvalidTag

import aes_demo as a


class PruebasAES(unittest.TestCase):
    def test_cifrar_y_descifrar_devuelve_el_original(self):
        paquete = a.cifrar("Hola mundo", "clave")
        self.assertEqual(a.descifrar(paquete, "clave"), "Hola mundo")

    def test_texto_con_tildes_y_simbolos(self):
        texto = "Contraseña: ñandú, café, 日本, 😀"
        self.assertEqual(a.descifrar(a.cifrar(texto, "x"), "x"), texto)

    def test_texto_vacio(self):
        self.assertEqual(a.descifrar(a.cifrar("", "x"), "x"), "")

    def test_estructura_del_paquete(self):
        texto = "abcde"
        paquete = a.cifrar(texto, "x")
        self.assertEqual(len(paquete), a.TAM_SAL + a.TAM_NONCE + len(texto) + a.TAM_ETIQUETA)
        self.assertEqual((a.TAM_CLAVE, a.TAM_NONCE, a.TAM_ETIQUETA), (32, 12, 16))   # 256, 96 y 128 bits

    def test_mismo_texto_cifra_distinto(self):
        self.assertNotEqual(a.cifrar("igual", "x"), a.cifrar("igual", "x"))

    def test_contrasena_incorrecta_se_rechaza(self):
        with self.assertRaises(InvalidTag):
            a.descifrar(a.cifrar("secreto", "correcta"), "incorrecta")

    def test_alterar_cualquier_parte_del_paquete_se_rechaza(self):
        paquete = a.cifrar("mensaje de prueba", "x")
        # sal, nonce, texto cifrado y etiqueta: un solo bit cambiado en cada zona
        for pos in (0, a.TAM_SAL, a.TAM_SAL + a.TAM_NONCE + 1, len(paquete) - 1):
            malo = bytearray(paquete)
            malo[pos] ^= 0x01
            with self.subTest(posicion=pos), self.assertRaises(InvalidTag):
                a.descifrar(bytes(malo), "x")

    def test_paquete_truncado(self):
        with self.assertRaises(ValueError):
            a.descifrar(b"corto", "x")

    def test_derivacion_es_determinista_con_la_misma_sal(self):
        sal = os.urandom(16)
        self.assertEqual(a.derivar_clave("x", sal), a.derivar_clave("x", sal))
        self.assertEqual(len(a.derivar_clave("x", sal)), 32)
        self.assertNotEqual(a.derivar_clave("x", sal), a.derivar_clave("y", sal))

    def test_demo_automatica(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(a.demo_automatica())


if __name__ == "__main__":
    unittest.main()
