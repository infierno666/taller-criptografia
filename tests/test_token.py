# -*- coding: utf-8 -*-
"""Pruebas de token_demo.py: token firmado con HMAC-SHA-256 (JWT HS256)."""
import importlib.util
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import token_demo as t


class PruebasToken(unittest.TestCase):
    def setUp(self):
        self.secreto = os.urandom(32)

    def test_crear_y_verificar(self):
        claims = t.verificar_token(t.crear_token(self.secreto, {"sub": "daniel", "rol": "usuario"}), self.secreto)
        self.assertEqual((claims["sub"], claims["rol"]), ("daniel", "usuario"))
        self.assertIn("exp", claims)
        self.assertIn("iat", claims)

    def test_tiene_tres_partes_y_cabecera_hs256(self):
        enc, _, _ = t.crear_token(self.secreto, {}).split(".")
        self.assertEqual(json.loads(t.b64url_decodificar(enc)), {"alg": "HS256", "typ": "JWT"})

    def test_la_carga_util_es_legible_sin_clave(self):
        token = t.crear_token(self.secreto, {"sub": "daniel"})
        carga = json.loads(t.b64url_decodificar(token.split(".")[1]))
        self.assertEqual(carga["sub"], "daniel")      # firmado, NO cifrado

    def test_carga_modificada_se_rechaza(self):
        enc, carga, firma = t.crear_token(self.secreto, {"rol": "usuario"}).split(".")
        datos = json.loads(t.b64url_decodificar(carga))
        datos["rol"] = "admin"
        falso = f"{enc}.{t._json_a_b64url(datos)}.{firma}"
        with self.assertRaises(t.FirmaInvalida):
            t.verificar_token(falso, self.secreto)

    def test_firma_alterada_se_rechaza(self):
        enc, carga, firma = t.crear_token(self.secreto, {}).split(".")
        mala = ("A" if firma[0] != "A" else "B") + firma[1:]
        with self.assertRaises(t.FirmaInvalida):
            t.verificar_token(f"{enc}.{carga}.{mala}", self.secreto)

    def test_secreto_incorrecto(self):
        with self.assertRaises(t.FirmaInvalida):
            t.verificar_token(t.crear_token(self.secreto, {}), os.urandom(32))

    def test_token_expirado(self):
        token = t.crear_token(self.secreto, {}, vigencia_segundos=60, ahora=time.time() - 3600)
        with self.assertRaises(t.TokenExpirado):
            t.verificar_token(token, self.secreto)

    def test_algoritmo_none_se_rechaza(self):
        enc = t._json_a_b64url({"alg": "none", "typ": "JWT"})
        carga = t._json_a_b64url({"sub": "x", "exp": int(time.time()) + 100})
        with self.assertRaises(t.AlgoritmoNoPermitido):
            t.verificar_token(f"{enc}.{carga}.", self.secreto)

    def test_otro_algoritmo_se_rechaza(self):
        enc = t._json_a_b64url({"alg": "RS256", "typ": "JWT"})
        carga = t._json_a_b64url({"exp": int(time.time()) + 100})
        with self.assertRaises(t.AlgoritmoNoPermitido):
            t.verificar_token(f"{enc}.{carga}.AAAA", self.secreto)

    def test_token_mal_formado(self):
        for malo in ("", "una.parte", "a.b.c.d", "###.###.###"):
            with self.subTest(token=malo), self.assertRaises(t.TokenError):
                t.verificar_token(malo, self.secreto)

    def test_sin_expiracion_se_rechaza(self):
        enc = t._json_a_b64url({"alg": "HS256", "typ": "JWT"})
        carga = t._json_a_b64url({"sub": "x"})
        firma = t.b64url_codificar(t._firmar(self.secreto, f"{enc}.{carga}".encode()))
        with self.assertRaises(t.TokenMalformado):
            t.verificar_token(f"{enc}.{carga}.{firma}", self.secreto)

    def test_vector_oficial_rfc_7515(self):
        clave = t.b64url_decodificar(t.RFC7515_CLAVE)
        claims = t.verificar_token(t.RFC7515_TOKEN, clave, ahora=1300819000)
        self.assertEqual(claims["iss"], "joe")
        with self.assertRaises(t.TokenExpirado):
            t.verificar_token(t.RFC7515_TOKEN, clave)

    @unittest.skipUnless(importlib.util.find_spec("jwt"), "PyJWT no está instalado (prueba opcional)")
    def test_interoperabilidad_con_pyjwt(self):
        import jwt
        token = t.crear_token(self.secreto, {"sub": "daniel"})
        self.assertEqual(jwt.decode(token, self.secreto, algorithms=["HS256"])["sub"], "daniel")
        otro = jwt.encode({"sub": "leonardo", "exp": int(time.time()) + 600}, self.secreto, algorithm="HS256")
        self.assertEqual(t.verificar_token(otro, self.secreto)["sub"], "leonardo")

    def test_demo_automatica(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(t.demo_automatica())


if __name__ == "__main__":
    unittest.main()
