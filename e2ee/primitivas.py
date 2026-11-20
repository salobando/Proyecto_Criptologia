"""
Sección 5 del documento de diseño (E1): Tabla de primitivas criptográficas.

Todas las primitivas vienen de la biblioteca `cryptography` (permitida por el
enunciado). No se implementa ninguna primitiva propia.

  Eje                | Primitiva                    | Parámetros
  -------------------+------------------------------+-------------------------------
  Simétrica (AEAD)   | ChaCha20-Poly1305 (RFC 8439) | clave 256 b, nonce 96 b, tag 128 b
  Asimétrica         | X25519 (RFC 7748)            | 32 bytes
  Autenticación      | Argon2id (RFC 9106)          | 64 MiB, t=3, p=4, sal 128 b
  Firma digital      | Ed25519 (RFC 8032)           | firma 64 bytes
  Hash / derivación  | SHA-256, HKDF (RFC 5869),    | salida 32 bytes
                     | HMAC-SHA256                  |
"""
from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Parámetros (tabla de la sección 5 del documento de diseño)
# --------------------------------------------------------------------------- #
ARGON2_MEMORIA_KIB = 64 * 1024  # 64 MiB
ARGON2_ITERACIONES = 3
ARGON2_PARALELISMO = 4
ARGON2_SAL_BYTES = 16  # 128 bits
ARGON2_SALIDA_BYTES = 32

CLAVE_BYTES = 32  # ChaCha20-Poly1305: 256 bits
NONCE_BYTES = 12  # 96 bits
TAG_BYTES = 16  # Poly1305: 128 bits


class AutenticacionFallida(Exception):
    """Verificación fallida (firma inválida, tag AEAD inválido, etc.)."""


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def borrar(buf: bytearray | None) -> None:
    """Sobrescribe un bytearray con ceros (borrado de claves efímeras).

    Limitación honesta: Python no garantiza que no existan otras copias en
    memoria (objetos inmutables `bytes`, objetos de la librería). Se hace el
    mejor esfuerzo posible sobre los secretos que controlamos.
    """
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


def sha256(*partes: bytes) -> bytes:
    h = hashlib.sha256()
    for p in partes:
        h.update(p)
    return h.digest()


def hmac_sha256(clave: bytes | bytearray, datos: bytes) -> bytes:
    return hmac.new(bytes(clave), datos, hashlib.sha256).digest()


def lp(*campos: bytes) -> bytes:
    """Serialización canónica con prefijo de longitud (evita ambigüedades)."""
    out = bytearray()
    for c in campos:
        out += len(c).to_bytes(4, "big") + c
    return bytes(out)


# --------------------------------------------------------------------------- #
# Hash y derivación: HKDF-SHA256
# --------------------------------------------------------------------------- #
def hkdf(ikm: bytes, info: bytes, longitud: int = 32, sal: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=longitud, salt=sal, info=info).derive(ikm)


# --------------------------------------------------------------------------- #
# Asimétrica: X25519
# --------------------------------------------------------------------------- #
def x25519_generar() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    return priv, x25519_pub_bytes(priv)


def x25519_pub_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def x25519_dh(priv: X25519PrivateKey, pub_bytes: bytes) -> bytearray:
    """Diffie-Hellman. La librería rechaza el secreto de orden bajo (todo ceros)."""
    return bytearray(priv.exchange(X25519PublicKey.from_public_bytes(pub_bytes)))


# --------------------------------------------------------------------------- #
# Firma digital: Ed25519
# --------------------------------------------------------------------------- #
def ed25519_generar() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, pub


def firmar(priv: Ed25519PrivateKey, datos: bytes) -> bytes:
    return priv.sign(datos)


def verificar_firma(pub_bytes: bytes, firma: bytes, datos: bytes) -> None:
    """Verificación OBLIGATORIA: lanza AutenticacionFallida si no es válida."""
    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(firma, datos)
    except (InvalidSignature, ValueError) as e:
        raise AutenticacionFallida("Firma Ed25519 inválida") from e


def datos_firmados_bundle(usuario: str, ik_dh: bytes, spk: bytes) -> bytes:
    """Lo que firma la clave de identidad Ed25519 en el prekey bundle.
    Liga el nombre de usuario, la clave de identidad X25519 y la signed prekey,
    para que el servidor no pueda recombinar piezas de bundles distintos."""
    return lp(b"E2EE-bundle-v1", usuario.encode("utf-8"), ik_dh, spk)


# --------------------------------------------------------------------------- #
# Simétrica: ChaCha20-Poly1305 (AEAD)
# --------------------------------------------------------------------------- #
def aead_cifrar(clave: bytes, nonce: bytes, plano: bytes, ad: bytes) -> bytes:
    assert len(clave) == CLAVE_BYTES and len(nonce) == NONCE_BYTES
    return ChaCha20Poly1305(clave).encrypt(nonce, plano, ad)


def aead_descifrar(clave: bytes, nonce: bytes, cifrado: bytes, ad: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(clave).decrypt(nonce, cifrado, ad)
    except InvalidTag as e:
        raise AutenticacionFallida("Etiqueta Poly1305 inválida (mensaje alterado)") from e


# --------------------------------------------------------------------------- #
# Autenticación: Argon2id para contraseñas
# --------------------------------------------------------------------------- #
def _argon2(sal: bytes) -> Argon2id:
    return Argon2id(
        salt=sal,
        length=ARGON2_SALIDA_BYTES,
        iterations=ARGON2_ITERACIONES,
        lanes=ARGON2_PARALELISMO,
        memory_cost=ARGON2_MEMORIA_KIB,
    )


def argon2_hash(contrasena: str) -> tuple[bytes, bytes]:
    """Devuelve (sal, hash). La sal es aleatoria de 128 bits."""
    sal = os.urandom(ARGON2_SAL_BYTES)
    return sal, _argon2(sal).derive(contrasena.encode("utf-8"))


def argon2_verificar(contrasena: str, sal: bytes, esperado: bytes) -> bool:
    """Comparación en tiempo constante (la hace la librería)."""
    try:
        _argon2(sal).verify(contrasena.encode("utf-8"), esperado)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Safety numbers (SHA-256): 60 dígitos, deterministas, simétricos entre pares
# --------------------------------------------------------------------------- #
_SN_ITERACIONES = 5200  # como en Signal: encarece la búsqueda de colisiones


def _huella_numerica(usuario: str, ik_firma: bytes, ik_dh: bytes) -> str:
    h = lp(b"E2EE-safety-v1", usuario.encode(), ik_firma, ik_dh)
    for _ in range(_SN_ITERACIONES):
        h = sha256(h, ik_firma, ik_dh)
    # 6 bloques de 5 bytes -> 6 grupos de 5 dígitos = 30 dígitos por parte
    return "".join(
        f"{int.from_bytes(h[i * 5:(i + 1) * 5], 'big') % 100000:05d}" for i in range(6)
    )


def safety_number(
    usuario_a: str, ik_firma_a: bytes, ik_dh_a: bytes,
    usuario_b: str, ik_firma_b: bytes, ik_dh_b: bytes,
) -> str:
    """60 dígitos (12 grupos de 5). Es idéntico visto desde A o desde B."""
    partes = sorted(
        [
            _huella_numerica(usuario_a, ik_firma_a, ik_dh_a),
            _huella_numerica(usuario_b, ik_firma_b, ik_dh_b),
        ]
    )
    todo = "".join(partes)
    return " ".join(todo[i:i + 5] for i in range(0, 60, 5))


# --------------------------------------------------------------------------- #
# Serialización de claves privadas y clave de la bóveda local (almacen.py)
# --------------------------------------------------------------------------- #
BOVEDA_SAL_BYTES = 16  # 128 bits, distinta de la sal que guarda el servidor


def ed25519_priv_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def ed25519_desde_bytes(raw: bytes) -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub


def x25519_priv_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def x25519_desde_bytes(raw: bytes) -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.from_private_bytes(raw)
    return priv, x25519_pub_bytes(priv)


def derivar_clave_boveda(contrasena: str, sal: bytes) -> bytes:
    """Clave de 256 b para cifrar la bóveda local: Argon2id(contraseña, sal_local)
    separada por dominio con HKDF. Como la sal es distinta de la que usa el
    servidor, el hash que éste guarda no sirve para abrir la bóveda."""
    return hkdf(_argon2(sal).derive(contrasena.encode("utf-8")), info=b"E2EE-boveda-v1")
