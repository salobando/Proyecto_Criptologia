"""
Bóveda local cifrada (almacenamiento persistente del cliente).

Guarda en disco, cifrado con ChaCha20-Poly1305, lo que el cliente necesita para
volver a iniciar sesión tras cerrar el programa:
  * claves privadas (identidad Ed25519, identidad X25519, signed prekey),
  * contactos con la identidad fijada (TOFU) y su estado de verificación,
  * identificadores de sesión ya vistos (anti-replay del mensaje inicial),
  * historial local.

NO se guardan cadenas del ratchet: al reiniciar se negocia una sesión nueva
(X3DH) y así se conserva el secreto hacia adelante entre ejecuciones.

Formato del archivo:  MAGIC(8) | sal(16) | nonce(12) | texto cifrado + tag(16)
Clave:  Argon2id(contraseña, sal) -> HKDF("E2EE-boveda-v1")   (ver primitivas)
AD:     MAGIC ‖ usuario ‖ sal   (la bóveda no se puede pasar por la de otro usuario)
"""
from __future__ import annotations

import json
import os
import tempfile

from . import primitivas as P

MAGIC = b"E2EEVLT1"
_MIN_TAM = len(MAGIC) + P.BOVEDA_SAL_BYTES + P.NONCE_BYTES + P.TAG_BYTES


class ErrorBoveda(Exception):
    """Bóveda inexistente, corrupta o en uso incorrecto."""


class ContrasenaIncorrecta(ErrorBoveda):
    """La etiqueta AEAD no valida: contraseña errónea o archivo alterado."""


class Boveda:
    def __init__(self, ruta: str, usuario: str):
        self.ruta = ruta
        self.usuario = usuario
        self._clave: bytearray | None = None
        self._sal: bytes | None = None

    def existe(self) -> bool:
        return os.path.isfile(self.ruta)

    @property
    def abierta(self) -> bool:
        return self._clave is not None

    def _ad(self, sal: bytes) -> bytes:
        return P.lp(MAGIC, self.usuario.encode("utf-8"), sal)

    def crear(self, contrasena: str, estado: dict) -> None:
        if self.existe():
            raise ErrorBoveda("La bóveda ya existe: no se sobrescribe (perdería las claves privadas)")
        self._sal = os.urandom(P.BOVEDA_SAL_BYTES)
        self._clave = bytearray(P.derivar_clave_boveda(contrasena, self._sal))
        self.guardar(estado)

    def abrir(self, contrasena: str) -> dict:
        try:
            with open(self.ruta, "rb") as f:
                datos = f.read()
        except OSError as e:
            raise ErrorBoveda(f"No se pudo leer la bóveda: {e}") from e
        if len(datos) < _MIN_TAM or datos[: len(MAGIC)] != MAGIC:
            raise ErrorBoveda("Formato de bóveda inválido")
        o = len(MAGIC)
        sal = datos[o:o + P.BOVEDA_SAL_BYTES]
        nonce = datos[o + P.BOVEDA_SAL_BYTES:o + P.BOVEDA_SAL_BYTES + P.NONCE_BYTES]
        ct = datos[o + P.BOVEDA_SAL_BYTES + P.NONCE_BYTES:]
        clave = P.derivar_clave_boveda(contrasena, sal)
        try:
            plano = P.aead_descifrar(clave, nonce, ct, self._ad(sal))
        except P.AutenticacionFallida as e:
            raise ContrasenaIncorrecta("Contraseña incorrecta (o la bóveda fue alterada)") from e
        self._sal, self._clave = sal, bytearray(clave)
        return json.loads(plano)

    def guardar(self, estado: dict) -> None:
        """Reescribe la bóveda con un nonce nuevo (misma clave y sal). Escritura
        atómica: nunca queda un archivo a medias si el proceso se interrumpe."""
        if not self.abierta:
            raise ErrorBoveda("La bóveda no está abierta")
        nonce = os.urandom(P.NONCE_BYTES)
        plano = json.dumps(estado, ensure_ascii=False).encode("utf-8")
        ct = P.aead_cifrar(bytes(self._clave), nonce, plano, self._ad(self._sal))
        carpeta = os.path.dirname(os.path.abspath(self.ruta))
        os.makedirs(carpeta, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=carpeta, prefix=".vault-")  # permisos 0600
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(MAGIC + self._sal + nonce + ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.ruta)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    def eliminar(self) -> None:
        self.cerrar()
        if self.existe():
            os.remove(self.ruta)

    def cerrar(self) -> None:
        P.borrar(self._clave)
        self._clave = None
