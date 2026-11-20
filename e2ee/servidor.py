"""
Servidor de retransmisión y directorio (modelo «honesto pero curioso»).

Rol del desarrollador del servidor (documento de diseño, sección 2):
  * directorio de claves públicas (prekey bundles),
  * buzón de mensajes cifrados para usuarios desconectados,
  * autenticación de usuarios con Argon2id + token de sesión opaco con expiración.

Lo que el servidor NUNCA almacena: claves privadas, claves de sesión, texto
plano, contraseñas (solo Argon2id + sal). Metadatos (quién escribe a quién y
cuándo) sí son visibles: limitación conocida, igual que en Signal sin sealed
sender.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import time

from . import primitivas as P
from .red import b64, unb64

TTL_SESION_SEG = 15 * 60
# Defensa contra adivinación de contraseñas (además del coste de Argon2id)
MAX_FALLOS = 5            # intentos fallidos seguidos antes de bloquear
BLOQUEO_BASE_SEG = 30     # el bloqueo se duplica con cada fallo extra...
BLOQUEO_MAX_SEG = 15 * 60  # ...hasta este tope
MAX_USUARIO, MIN_USUARIO, MIN_PW, MAX_PW = 32, 3, 8, 256


class ErrorServidor(Exception):
    pass


class Servidor:
    def __init__(self, ruta_bd: str = ":memory:"):
        self.bd = sqlite3.connect(ruta_bd, check_same_thread=False)
        self.bd.executescript(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                usuario TEXT PRIMARY KEY,
                sal BLOB NOT NULL,
                hash_pw BLOB NOT NULL,          -- Argon2id(contraseña, sal)
                bundle TEXT NOT NULL            -- solo claves PÚBLICAS + firma
            );
            CREATE TABLE IF NOT EXISTS sesiones (
                token_hash BLOB PRIMARY KEY,    -- SHA-256 del token (no el token)
                usuario TEXT NOT NULL,
                expira REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS buzon (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                destinatario TEXT NOT NULL,
                sobre TEXT NOT NULL             -- solo texto cifrado + cabecera
            );
            """
        )
        # Hash señuelo: iguala el tiempo de login de usuarios inexistentes
        # (evita enumeración de usuarios por temporización).
        self._sal_senuelo, self._hash_senuelo = P.argon2_hash(secrets.token_urlsafe(16))
        self._fallos: dict[str, tuple[int, float]] = {}  # usuario -> (fallos, bloqueado_hasta)

    # ------------------------------------------------------------------ #
    # Paso 1 del flujo: Registro
    # ------------------------------------------------------------------ #
    def registrar(self, usuario: str, contrasena: str, bundle: dict) -> dict:
        if not isinstance(usuario, str) or not isinstance(contrasena, str):
            raise ErrorServidor("Datos de registro inválidos")
        # Solo ASCII: evita suplantación con caracteres Unicode parecidos (p. ej. «аlice» con 'а' cirílica)
        if (not MIN_USUARIO <= len(usuario) <= MAX_USUARIO
                or not usuario.isascii() or not usuario.isidentifier()):
            raise ErrorServidor(
                f"Nombre de usuario inválido ({MIN_USUARIO}-{MAX_USUARIO} caracteres ASCII: "
                "letras, dígitos y «_», sin empezar por dígito)"
            )
        if not MIN_PW <= len(contrasena) <= MAX_PW:
            raise ErrorServidor(f"La contraseña debe tener entre {MIN_PW} y {MAX_PW} caracteres")
        self._validar_bundle(usuario, bundle)
        existe = self.bd.execute("SELECT 1 FROM usuarios WHERE usuario=?", (usuario,)).fetchone()
        if existe:
            raise ErrorServidor("El usuario ya existe")
        sal, h = P.argon2_hash(contrasena)
        self.bd.execute(
            "INSERT INTO usuarios VALUES (?,?,?,?)", (usuario, sal, h, json.dumps(bundle))
        )
        self.bd.commit()
        return {"ok": True}

    # ------------------------------------------------------------------ #
    # Paso 2 del flujo: Autenticación ante el servidor
    # ------------------------------------------------------------------ #
    def login(self, usuario: str, contrasena: str) -> dict:
        if not isinstance(usuario, str) or not isinstance(contrasena, str) or len(contrasena) > MAX_PW:
            raise ErrorServidor("Credenciales inválidas")
        self._exigir_no_bloqueado(usuario)  # antes de gastar CPU/memoria en Argon2id
        fila = self.bd.execute(
            "SELECT sal, hash_pw FROM usuarios WHERE usuario=?", (usuario,)
        ).fetchone()
        if fila is None:
            P.argon2_verificar(contrasena, self._sal_senuelo, self._hash_senuelo)
            self._registrar_fallo(usuario)
            raise ErrorServidor("Credenciales inválidas")
        if not P.argon2_verificar(contrasena, fila[0], fila[1]):
            self._registrar_fallo(usuario)
            raise ErrorServidor("Credenciales inválidas")
        self._fallos.pop(usuario, None)
        ahora = time.time()
        self.bd.execute("DELETE FROM sesiones WHERE expira < ?", (ahora,))  # limpieza de tokens vencidos
        token = secrets.token_urlsafe(32)  # 256 bits de un CSPRNG: no predecible
        self.bd.execute(
            "INSERT INTO sesiones VALUES (?,?,?)",
            (P.sha256(token.encode()), usuario, ahora + TTL_SESION_SEG),
        )
        self.bd.commit()
        return {"token": token}

    # Limitación de intentos: se aplica igual a usuarios existentes e inexistentes
    # (no revela qué cuentas existen). Contrapartida conocida: quien conozca un
    # nombre de usuario puede bloquearlo temporalmente (hasta 15 min).
    def _exigir_no_bloqueado(self, usuario: str) -> None:
        _, hasta = self._fallos.get(usuario, (0, 0.0))
        restante = hasta - time.time()
        if restante > 0:
            raise ErrorServidor(f"Demasiados intentos fallidos. Reintente en {int(restante) + 1} s")

    def _registrar_fallo(self, usuario: str) -> None:
        n = self._fallos.get(usuario, (0, 0.0))[0] + 1
        hasta = 0.0
        if n >= MAX_FALLOS:
            hasta = time.time() + min(BLOQUEO_BASE_SEG * 2 ** (n - MAX_FALLOS), BLOQUEO_MAX_SEG)
        if len(self._fallos) > 10_000:  # evita crecimiento sin límite con nombres inventados
            ahora = time.time()
            self._fallos = {u: v for u, v in self._fallos.items() if v[1] > ahora}
        self._fallos[usuario] = (n, hasta)

    def logout(self, token: str) -> dict:
        if not isinstance(token, str):
            raise ErrorServidor("Sesión inválida o expirada")
        self.bd.execute("DELETE FROM sesiones WHERE token_hash=?", (P.sha256(token.encode()),))
        self.bd.commit()
        return {"ok": True}

    def _usuario_de(self, token: str) -> str:
        if not isinstance(token, str):
            raise ErrorServidor("Sesión inválida o expirada")
        fila = self.bd.execute(
            "SELECT usuario, expira FROM sesiones WHERE token_hash=?", (P.sha256(token.encode()),)
        ).fetchone()
        if fila is None or fila[1] < time.time():
            raise ErrorServidor("Sesión inválida o expirada")
        return fila[0]

    # ------------------------------------------------------------------ #
    # Directorio de claves públicas
    # ------------------------------------------------------------------ #
    def obtener_bundle(self, token: str, usuario: str) -> dict:
        self._usuario_de(token)
        fila = self.bd.execute("SELECT bundle FROM usuarios WHERE usuario=?", (usuario,)).fetchone()
        if fila is None:
            raise ErrorServidor("Usuario no encontrado")
        return json.loads(fila[0])

    def listar_usuarios(self, token: str) -> dict:
        self._usuario_de(token)
        filas = self.bd.execute("SELECT usuario FROM usuarios ORDER BY usuario").fetchall()
        return {"usuarios": [f[0] for f in filas]}

    def actualizar_bundle(self, token: str, bundle: dict) -> dict:
        """Rotación legítima de claves (p. ej. reinstalación en otro dispositivo).
        Los contactos lo detectarán como cambio de clave de identidad."""
        usuario = self._usuario_de(token)
        self._validar_bundle(usuario, bundle)
        self.bd.execute("UPDATE usuarios SET bundle=? WHERE usuario=?", (json.dumps(bundle), usuario))
        self.bd.commit()
        return {"ok": True}

    @staticmethod
    def _validar_bundle(usuario: str, bundle: dict) -> None:
        """El servidor solo verifica forma y que la firma sea coherente; la
        confianza real la decide cada cliente (el servidor no es de confianza)."""
        try:
            ik_f, ik_dh = unb64(bundle["ik_firma"]), unb64(bundle["ik_dh"])
            spk, firma = unb64(bundle["spk"]), unb64(bundle["spk_firma"])
            if bundle.get("usuario") != usuario or len(ik_f) != 32 or len(ik_dh) != 32 or len(spk) != 32:
                raise ValueError
            P.verificar_firma(ik_f, firma, P.datos_firmados_bundle(usuario, ik_dh, spk))
        except Exception as e:
            raise ErrorServidor("Prekey bundle inválido") from e

    # ------------------------------------------------------------------ #
    # Buzón de retransmisión (solo texto cifrado)
    # ------------------------------------------------------------------ #
    def enviar(self, token: str, sobre: dict) -> dict:
        remitente = self._usuario_de(token)
        if not isinstance(sobre, dict) or not isinstance(sobre.get("para"), str):
            raise ErrorServidor("Sobre mal formado")
        if sobre.get("de") != remitente:
            raise ErrorServidor("El remitente no coincide con la sesión")
        existe = self.bd.execute("SELECT 1 FROM usuarios WHERE usuario=?", (sobre.get("para"),)).fetchone()
        if not existe:
            raise ErrorServidor("Destinatario no encontrado")
        self.bd.execute(
            "INSERT INTO buzon (destinatario, sobre) VALUES (?,?)", (sobre["para"], json.dumps(sobre))
        )
        self.bd.commit()
        return {"ok": True}

    def recibir(self, token: str) -> dict:
        """Entrega y elimina los mensajes pendientes (en orden de llegada)."""
        usuario = self._usuario_de(token)
        filas = self.bd.execute(
            "SELECT id, sobre FROM buzon WHERE destinatario=? ORDER BY id", (usuario,)
        ).fetchall()
        if filas:
            self.bd.execute("DELETE FROM buzon WHERE destinatario=?", (usuario,))
            self.bd.commit()
        return {"sobres": [json.loads(f[1]) for f in filas]}

    # ------------------------------------------------------------------ #
    # Utilidad para evidencias: lo que vería quien vuelque la base de datos
    # ------------------------------------------------------------------ #
    def volcado_bd(self) -> dict:
        return {
            "usuarios": [
                {"usuario": u, "sal": b64(s), "hash_argon2id": b64(h), "bundle": json.loads(b)}
                for u, s, h, b in self.bd.execute("SELECT * FROM usuarios")
            ],
            "buzon": [json.loads(r[0]) for r in self.bd.execute("SELECT sobre FROM buzon")],
        }
