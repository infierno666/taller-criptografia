# Taller A4 · Implementación práctica de algoritmos de criptografía

**Materia:** Seguridad Informática I · **Universidad:** Universidad Domingo Savio
**Docente:** Ing. José Abraham Mita Huanca
**Integrantes:** Daniel Maldonado Céspedes · Leonardo Nogales Torres
**Lenguaje:** Python 3 · **Biblioteca criptográfica:** [`cryptography`](https://cryptography.io/)

Este programa es la parte práctica del informe **A3 (Criptografía simétrica y asimétrica)**.
Implementa **exactamente** lo prometido en las **Tablas 17 y 18** del informe: cifra y descifra
con **AES-256-GCM** y **RSA-2048 (OAEP y PSS)**, y además muestra SHA-256, HMAC, un token estilo
JWT, el cifrado híbrido y una conexión TLS 1.3.

> No se usa ningún algoritmo inventado ni cifrados triviales como César o Base64.
> Todo el cifrado lo realiza la biblioteca `cryptography`. (Base64 aparece solo para
> *mostrar* bytes en pantalla; no es cifrado.)

---

## 1. Contenido del proyecto

| Archivo | Qué hace | Tema del informe |
|---|---|---|
| `aes_demo.py` | Cifra y descifra un texto con **AES-256-GCM**; la clave de 256 bits se deriva de una contraseña con **scrypt**; nonce aleatorio de 96 bits. | Criptografía simétrica; AES-GCM |
| `hash_demo.py` | **SHA-256** de un texto y de un archivo, **HMAC-SHA-256** y demostración del efecto avalancha. | SHA-256 y HMAC |
| `token_demo.py` | Crea y verifica un token firmado con HMAC-SHA-256, **al estilo de JWT HS256**. | Tokens (JWT) |
| `rsa_demo.py` | **RSA-2048**: cifra/descifra con **OAEP** y firma/verifica con **PSS**; muestra el límite de 190 bytes. | RSA; firma digital |
| `hibrido_demo.py` | **Cifrado híbrido**: RSA protege una clave AES y AES-GCM cifra un mensaje largo (5 MB). | Criptografía híbrida |
| `tls_demo.py` | Abre una conexión **TLS 1.3** y muestra la versión, la suite negociada y el certificado X.509. | HTTPS/TLS y certificados |
| `main.py` | Menú principal que ejecuta todo. | Todos |
| `tests/` | **66 pruebas automáticas** (cifrado, descifrado y rechazo de mensajes alterados). | Todos |
| `requirements.txt` | Dependencias (`cryptography`). | — |
| `capturas/` | Capturas de la ejecución exitosa. | — |

### Algoritmos y parámetros (Tabla 17 del informe)

| Función | Algoritmo | Parámetros |
|---|---|---|
| Cifrado simétrico | AES-256-GCM | Clave de 256 bits derivada con scrypt; nonce aleatorio de 96 bits; etiqueta de 128 bits |
| Cifrado asimétrico | RSA-OAEP | Clave de 2048 bits; SHA-256 como hash y en MGF1 |
| Firma digital | RSA-PSS | Clave de 2048 bits; SHA-256; sal de 32 bytes |
| Cifrado híbrido | RSA-OAEP + AES-256-GCM | RSA protege la clave AES; AES-GCM cifra el mensaje largo |
| Integridad | SHA-256 y HMAC-SHA-256 | Hash de textos y archivos; código de autenticación con clave |
| Token | HMAC-SHA-256 | Token firmado al estilo de JWT con HS256 |
| Canal seguro | TLS 1.3 | Muestra la versión y la suite negociadas |

---

## 2. Requisitos

- **Python 3.9 o superior** (probado con Python 3.12).
- La biblioteca **`cryptography` 42.0.0 o superior** (se instala con `requirements.txt`; probado con la 50.0.2).
- **No se necesita internet** para ejecutar el programa. Solo la opción opcional *"sitio real"* de TLS (módulo 6) se conecta a internet.

---

## 3. Instalación

Elige tu sistema. Ambas formas crean un **entorno virtual** (`venv`) para no tocar el Python del sistema.
Ejecuta los comandos **dentro de la carpeta `taller-criptografia`**.

### 3.1 Windows (PowerShell o CMD)

```powershell
# 1) Entrar a la carpeta del proyecto (ajusta la ruta a donde la guardaste)
cd C:\Users\TU_USUARIO\Desktop\taller-criptografia

# 2) Comprobar que Python está instalado
py --version

# 3) Crear y activar el entorno virtual
py -m venv venv
venv\Scripts\activate

# 4) Instalar la dependencia
pip install -r requirements.txt

# 5) Comprobar la instalación
python -c "import cryptography; print(cryptography.__version__)"
```

> **Si PowerShell bloquea la activación** (mensaje *"la ejecución de scripts está deshabilitada"*),
> ejecuta esto y vuelve a intentar el paso 3:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
> O usa **CMD** en lugar de PowerShell.
>
> Si `py` no se reconoce, instala Python desde <https://www.python.org/downloads/> marcando
> la casilla **"Add python.exe to PATH"**.

### 3.2 Kali Linux (máquina virtual)

```bash
# 1) Entrar a la carpeta del proyecto
cd ~/taller-criptografia

# 2) Comprobar la versión de Python
python3 --version

# 3) (Solo si falta) instalar el soporte de entornos virtuales
sudo apt update && sudo apt install -y python3-venv

# 4) Crear y activar el entorno virtual
python3 -m venv venv
source venv/bin/activate

# 5) Instalar la dependencia
pip install -r requirements.txt

# 6) Comprobar la instalación
python -c "import cryptography; print(cryptography.__version__)"
```

> **¿Por qué un entorno virtual en Kali?** Las versiones recientes de Kali bloquean `pip install`
> global y muestran el error `externally-managed-environment`. El entorno virtual evita ese problema.

Cada vez que abras una terminal nueva, **activa de nuevo el entorno** antes de ejecutar el programa:
`venv\Scripts\activate` (Windows) o `source venv/bin/activate` (Kali).
En los ejemplos siguientes se usa `python`; con el entorno activado funciona igual en ambos sistemas.

---

## 4. Cómo ejecutar el programa

### 4.1 Menú principal (recomendado)

```bash
python main.py
```

Aparece este menú:

```
==============================================================
  TALLER A4 · CRIPTOGRAFÍA APLICADA
  Seguridad Informática I · Universidad Domingo Savio
==============================================================
  1. AES-256-GCM (cifrado simétrico)
  2. SHA-256 y HMAC (integridad)
  3. Token HMAC-SHA-256 / JWT HS256
  4. RSA-2048: OAEP y PSS (asimétrico)
  5. Cifrado híbrido RSA + AES-GCM
  6. TLS 1.3 y certificados X.509
  7. Ejecutar TODAS las demostraciones
  8. Ejecutar las pruebas automáticas (tests/)
  0. Salir
```

Escribe el número de la opción y pulsa Enter. Cada módulo tiene su propio submenú.

### 4.2 Ejecutar todo de una vez

```bash
python main.py --auto
```

Ejecuta las demostraciones de los 6 módulos y muestra un resumen final. **Salida esperada (al final):**

```
==============================================================
  RESUMEN FINAL DEL TALLER
==============================================================
  [OK] AES-256-GCM (cifrado simétrico)
  [OK] SHA-256 y HMAC (integridad)
  [OK] Token HMAC-SHA-256 / JWT HS256
  [OK] RSA-2048: OAEP y PSS (asimétrico)
  [OK] Cifrado híbrido RSA + AES-GCM
  [OK] TLS 1.3 y certificados X.509
==============================================================
  TODAS LAS DEMOSTRACIONES FUERON CORRECTAS.
```

### 4.3 Ejecutar un módulo por separado

Cada archivo se puede ejecutar solo, con menú (`python archivo.py`) o en modo automático (`--auto`):

```bash
python aes_demo.py --auto
python hash_demo.py --auto
python token_demo.py --auto
python rsa_demo.py --auto
python hibrido_demo.py --auto
python tls_demo.py --auto
```

### 4.4 Pruebas automáticas

```bash
python -m unittest discover -s tests -v
```

**Salida esperada (al final):**

```
Ran 66 tests in 5.1s

OK
```

> Si PyJWT no está instalado, una prueba opcional de interoperabilidad se omite y verás
> `OK (skipped=1)`. Es normal: no es un error.

---

## 5. Qué mostrará cada módulo

### `aes_demo.py` · AES-256-GCM
Cifra un texto y muestra la sal, el nonce, el texto cifrado y la etiqueta de autenticación; luego lo
descifra y confirma que coincide con el original. También demuestra que:
el mismo texto cifra distinto cada vez, **alterar un solo byte** hace que GCM rechace el mensaje
(`InvalidTag`), y una contraseña incorrecta es rechazada.
Cierre esperado: `RESULTADO FINAL: 4/4 pruebas correctas`.

### `hash_demo.py` · SHA-256 y HMAC
Verifica SHA-256 contra los vectores oficiales del estándar FIPS 180-4, muestra el **efecto avalancha**
(`"Hola mundo"` frente a `"hola mundo"`: cerca de la mitad de los 256 bits cambian), calcula el hash
de un archivo y demuestra que un archivo con **1 bit** alterado produce otro hash. Con HMAC rechaza el
mensaje alterado y la clave incorrecta.
Cierre esperado: `RESULTADO FINAL: 3/3 pruebas correctas`.

### `token_demo.py` · Token estilo JWT HS256
Crea un token de tres partes (encabezado, carga útil, firma) y lo verifica. Muestra que la carga útil
**se puede leer sin clave** (está firmada, no cifrada) y rechaza: carga alterada (cambiar `rol` a `admin`),
token expirado, el ataque del algoritmo `none` y un secreto incorrecto. Comprueba además la firma del
token de ejemplo oficial del RFC 7515.
Cierre esperado: `RESULTADO FINAL: 6/6 pruebas correctas`.

### `rsa_demo.py` · RSA-2048 (OAEP y PSS)
Genera un par de claves, cifra con la clave pública y descifra con la privada (OAEP), muestra el
**límite de 190 bytes** (190 se cifran, 191 se rechazan), firma y verifica con PSS (rechaza mensajes o
firmas alterados y claves públicas ajenas) y guarda la clave privada protegida con contraseña.
Cierre esperado: `RESULTADO FINAL: 5/5 pruebas correctas`.

### `hibrido_demo.py` · Cifrado híbrido
Envía un informe de **5 MB**: RSA directo es imposible, pero RSA protege solo la clave de sesión
(32 bytes) y AES-256-GCM cifra los 5 MB. Firma el paquete con RSA-PSS y rechaza cinco manipulaciones
(datos alterados, clave de sesión alterada, tercero con otra clave, suplantación del emisor).
Cierre esperado: `RESULTADO FINAL: 4/4 pruebas correctas`.

### `tls_demo.py` · TLS 1.3 y certificados X.509
Crea un certificado de prueba y un servidor TLS 1.3 **en tu propio equipo** (sin internet), se conecta
y muestra versión (`TLSv1.3`), suite de cifrado (por ejemplo `TLS_AES_256_GCM_SHA384`) y los datos del
certificado. Demuestra el rechazo de un certificado desconocido y de un cliente que solo habla TLS 1.2.
La opción 4 del menú se conecta a un **sitio real** (necesita internet).
Cierre esperado: `RESULTADO FINAL: 3/3 pruebas correctas`, o `4/4` si hay internet. Sin conexión
verás `3/3 pruebas correctas (1 omitida por falta de internet)`, y es correcto.

---

## 6. Solución de problemas

| Problema | Causa y solución |
|---|---|
| `ModuleNotFoundError: No module named 'cryptography'` | No está instalada la biblioteca o el entorno virtual no está activo. Activa el entorno y ejecuta `pip install -r requirements.txt`. |
| `error: externally-managed-environment` (Kali) | Intentaste instalar con `pip` fuera de un entorno virtual. Sigue el apartado 3.2. |
| PowerShell: *"la ejecución de scripts está deshabilitada"* | Ejecuta `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` o usa CMD. |
| `py` / `python` no se reconoce (Windows) | Instala Python marcando *Add python.exe to PATH*. |
| Las tildes se ven mal en la consola de Windows | El programa ya configura UTF-8. Si persiste, ejecuta `chcp 65001` antes de iniciar. |
| TLS opción 4: `No se pudo conectar` | No hay internet o un proxy bloquea la conexión. Es una prueba opcional; las pruebas locales funcionan sin internet. |
| La ventana de la terminal corta la salida | Maximiza la ventana o desplázate hacia arriba; la salida completa sigue ahí. |

---

## 7. Notas de seguridad y alcance

- Se usa **GCM** (cifrado autenticado), no ECB; se usa **OAEP** para cifrar con RSA, no PKCS#1 v1.5; los
  nonces, sales y claves se generan con el generador aleatorio seguro del sistema (`os.urandom`).
- El **certificado de TLS es de prueba** (autofirmado, válido un día) y solo sirve para la demostración local.
- El programa es **didáctico**: no gestiona almacenamiento seguro de claves ni está pensado para
  producción. En producción las claves se guardan en un gestor de claves o módulo de seguridad.
- Aviso del informe: RSA-2048 es aceptable hoy, pero el borrador NIST IR 8547 propone su retiro
  progresivo con la llegada de la criptografía poscuántica.

---

## 8. Evidencia de ejecución

Las capturas de pantalla de la ejecución exitosa están en la carpeta [`capturas/`](capturas/).
