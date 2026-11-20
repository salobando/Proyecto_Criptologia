"""
Cliente de consola (Cliente A / Cliente B del documento de diseño).

Implementa, del lado del cliente:
  * Registro: claves de identidad (Ed25519 + X25519), signed prekey firmada.
  * X3DH simplificado (identidad + signed prekey + clave efímera).
  * Ratchet simétrico (cadena KDF con HMAC-SHA256): una clave nueva por mensaje.
  * AEAD ChaCha20-Poly1305 con datos asociados (identidades + contador + sesión).
  * Safety numbers, directorio de contactos con indicador «verificado» y
    alerta visible ante cambio de clave de identidad.
  * Historial local de la conversación.
  * Cuenta persistente: bóveda local cifrada con la contraseña (almacen.py).

Las claves privadas nunca se envían; en disco solo existen dentro de la bóveda cifrada.
"""
from __future__ import annotations

import hmac
import time
from dataclasses import dataclass, field

from . import primitivas as P
from .almacen import Boveda, ErrorBoveda
from .red import CanalSimulado, b64, unb64
from .servidor import ErrorServidor

VERSION = b"E2EE-v1"
MAX_SALTO = 100  # máximo de mensajes que se pueden «saltar» en una cadena
MAX_CLAVES_SALTADAS = 200


class ErrorProtocolo(Exception):
    """Mensaje rechazado por el protocolo (replay, sesión desconocida, etc.)."""


class AlertaCambioDeClave(Exception):
    """La clave de identidad de un contacto cambió respecto a la fijada."""


# --------------------------------------------------------------------------- #
# Sesión con ratchet simétrico
# --------------------------------------------------------------------------- #
def _avanzar(cadena: bytearray) -> tuple[bytes, bytearray]:
    """Un paso del ratchet simétrico (cadena KDF con HMAC-SHA256).

        mk      = HMAC(CK, 0x01)   -> clave del mensaje actual
        CK_next = HMAC(CK, 0x02)   -> sustituye a CK, que se borra

    Como la función es unidireccional, conocer CK_next no permite recuperar
    las claves de mensajes anteriores (forward secrecy a nivel de mensaje).
    """
    mk = P.hmac_sha256(cadena, b"\x01")
    siguiente = bytearray(P.hmac_sha256(cadena, b"\x02"))
    P.borrar(cadena)
    return mk, siguiente


def _clave_y_nonce(mk: bytes) -> tuple[bytes, bytes]:
    """De la clave de mensaje (de un solo uso) se derivan clave AEAD y nonce.
    Como mk es única por mensaje, el par (clave, nonce) jamás se repite."""
    material = P.hkdf(mk, info=b"E2EE-msg-v1", longitud=P.CLAVE_BYTES + P.NONCE_BYTES)
    return material[: P.CLAVE_BYTES], material[P.CLAVE_BYTES:]


@dataclass
class Sesion:
    par: str
    sid: bytes  # identificador de sesión = clave efímera pública del iniciador
    rol: str  # "iniciador" | "respondedor"
    cadena_envio: bytearray
    cadena_recv: bytearray
    n_envio: int = 0
    n_recv: int = 0
    confirmada: bool = False  # el iniciador deja de mandar "init" al recibir respuesta
    saltadas: dict[int, bytes] = field(default_factory=dict)

    def cifrar(self, plano: bytes, ad_para) -> tuple[int, bytes]:
        ctr = self.n_envio
        mk, self.cadena_envio = _avanzar(self.cadena_envio)
        clave, nonce = _clave_y_nonce(mk)
        ct = P.aead_cifrar(clave, nonce, plano, ad_para(ctr))
        self.n_envio += 1
        return ctr, ct

    def descifrar(self, ctr: int, ct: bytes, ad: bytes) -> bytes:
        """Descifra; el estado de la sesión solo cambia si la autenticación pasa."""
        # 1) Mensaje fuera de orden cuya clave quedó guardada
        if ctr in self.saltadas:
            clave, nonce = _clave_y_nonce(self.saltadas[ctr])
            plano = P.aead_descifrar(clave, nonce, ct, ad)
            del self.saltadas[ctr]
            return plano
        # 2) Contador ya consumido => replay
        if ctr < self.n_recv:
            raise ErrorProtocolo(f"Replay detectado: contador {ctr} ya procesado (esperado ≥ {self.n_recv})")
        if ctr - self.n_recv > MAX_SALTO:
            raise ErrorProtocolo("Salto de contador excesivo")
        # 3) Avanzar sobre una COPIA de la cadena
        cadena = bytearray(self.cadena_recv)
        n = self.n_recv
        nuevas: dict[int, bytes] = {}
        while n < ctr:
            mk, cadena = _avanzar(cadena)
            nuevas[n] = mk
            n += 1
        mk, cadena = _avanzar(cadena)
        clave, nonce = _clave_y_nonce(mk)
        try:
            plano = P.aead_descifrar(clave, nonce, ct, ad)
        except P.AutenticacionFallida:
            P.borrar(cadena)  # estado real intacto: un atacante no puede desincronizarnos
            raise
        # 4) Confirmar estado
        P.borrar(self.cadena_recv)
        self.cadena_recv = cadena
        self.n_recv = ctr + 1
        self.saltadas.update(nuevas)
        while len(self.saltadas) > MAX_CLAVES_SALTADAS:
            self.saltadas.pop(min(self.saltadas))
        return plano


@dataclass
class Contacto:
    usuario: str
    ik_firma: bytes
    ik_dh: bytes
    verificado: bool = False
    alerta_cambio: bool = False


# --------------------------------------------------------------------------- #
# Cliente
# --------------------------------------------------------------------------- #
class Cliente:
    def __init__(self, usuario: str, canal: CanalSimulado, ruta_boveda: str | None = None):
        self.usuario = usuario
        self.canal = canal
        # Sin ruta, el cliente es efímero (todo en memoria), como en las pruebas.
        self._boveda = Boveda(ruta_boveda, usuario) if ruta_boveda else None
        self.token: str | None = None
        # Claves de larga duración (solo en memoria; no se envían privadas)
        self.ik_firma_priv = self.ik_firma_pub = None
        self.ik_dh_priv = self.ik_dh_pub = None
        self.spk_priv = self.spk_pub = None
        # Estado local
        self.contactos: dict[str, Contacto] = {}
        self.sesiones: dict[str, dict[bytes, Sesion]] = {}
        self.sesion_activa: dict[str, bytes] = {}
        self.sids_vistos: dict[str, set[bytes]] = {}
        self.historial: dict[str, list[dict]] = {}
        self.rechazados: list[dict] = []

    # ------------------------------------------------------------------ #
    # Paso 1: Registro
    # ------------------------------------------------------------------ #
    def _generar_claves(self) -> dict:
        self.ik_firma_priv, self.ik_firma_pub = P.ed25519_generar()
        self.ik_dh_priv, self.ik_dh_pub = P.x25519_generar()
        self.spk_priv, self.spk_pub = P.x25519_generar()
        firma = P.firmar(
            self.ik_firma_priv, P.datos_firmados_bundle(self.usuario, self.ik_dh_pub, self.spk_pub)
        )
        # Prekey bundle: SOLO claves públicas y la firma
        return {
            "usuario": self.usuario,
            "ik_firma": b64(self.ik_firma_pub),
            "ik_dh": b64(self.ik_dh_pub),
            "spk": b64(self.spk_pub),
            "spk_firma": b64(firma),
        }

    def registrar(self, contrasena: str) -> None:
        """Crea la cuenta: genera claves, las guarda en la bóveda local (si hay
        ruta) y publica solo el bundle público en el servidor."""
        if self._boveda and self._boveda.existe():
            raise ErrorProtocolo("Ya existe una cuenta local para este usuario: inicie sesión")
        bundle = self._generar_claves()
        if self._boveda:
            # Las claves privadas quedan a salvo en disco ANTES de publicar la pública
            self._boveda.crear(contrasena, self._exportar_estado())
        try:
            self.canal.llamar("registrar", usuario=self.usuario, contrasena=contrasena, bundle=bundle)
        except ErrorServidor:
            if self._boveda:
                self._boveda.eliminar()  # el servidor rechazó el registro: no dejar bóveda huérfana
            raise

    # ------------------------------------------------------------------ #
    # Paso 2: Autenticación ante el servidor
    # ------------------------------------------------------------------ #
    def login(self, contrasena: str) -> None:
        """Abre la bóveda local (si las claves aún no están en memoria) y luego
        se autentica ante el servidor. Una contraseña errónea falla primero en
        la bóveda (ContrasenaIncorrecta), sin tocar la red."""
        if self.ik_firma_priv is None:
            if self._boveda is None or not self._boveda.existe():
                raise ErrorProtocolo("Este cliente no tiene claves locales (registre primero)")
            self._importar_estado(self._boveda.abrir(contrasena))
        self.token = self.canal.llamar("login", usuario=self.usuario, contrasena=contrasena)["token"]
        self._verificar_bundle_propio()

    def login_nuevo_dispositivo(self, contrasena: str) -> None:
        """Cuenta que ya existe en el servidor pero este equipo no tiene sus
        claves (equipo nuevo o bóveda perdida). Se autentica con la contraseña,
        genera una identidad NUEVA y la publica. Los contactos verán la alerta
        de cambio de clave de identidad y deberán re-verificar el safety number."""
        if self.ik_firma_priv is not None or (self._boveda and self._boveda.existe()):
            raise ErrorProtocolo("Este equipo ya tiene claves locales: use el inicio de sesión normal")
        self.token = self.canal.llamar("login", usuario=self.usuario, contrasena=contrasena)["token"]
        bundle = self._generar_claves()
        if self._boveda:
            self._boveda.crear(contrasena, self._exportar_estado())
        try:
            self.canal.llamar("actualizar_bundle", token=self.token, bundle=bundle)
        except ErrorServidor:
            if self._boveda:
                self._boveda.eliminar()
            raise

    def _verificar_bundle_propio(self) -> None:
        """Las claves locales deben coincidir con las publicadas; si no (p. ej.
        se rotaron desde otro equipo) los mensajes entrantes no se podrían leer."""
        b = self.canal.llamar("obtener_bundle", token=self.token, usuario=self.usuario)
        if (unb64(b["ik_firma"]) != self.ik_firma_pub or unb64(b["ik_dh"]) != self.ik_dh_pub
                or unb64(b["spk"]) != self.spk_pub):
            self.logout()
            raise ErrorProtocolo(
                "Las claves locales NO coinciden con las publicadas en el servidor "
                "(¿se rotaron desde otro equipo?). Use el modo «claves nuevas»."
            )

    # ------------------------------------------------------------------ #
    # Persistencia local (bóveda cifrada)
    # ------------------------------------------------------------------ #
    def _exportar_estado(self) -> dict:
        return {
            "version": 1,
            "usuario": self.usuario,
            "ik_firma_priv": b64(P.ed25519_priv_bytes(self.ik_firma_priv)),
            "ik_dh_priv": b64(P.x25519_priv_bytes(self.ik_dh_priv)),
            "spk_priv": b64(P.x25519_priv_bytes(self.spk_priv)),
            "contactos": {
                u: {"ik_firma": b64(c.ik_firma), "ik_dh": b64(c.ik_dh),
                    "verificado": c.verificado, "alerta_cambio": c.alerta_cambio}
                for u, c in self.contactos.items()
            },
            "sids_vistos": {u: sorted(b64(x) for x in v) for u, v in self.sids_vistos.items()},
            "historial": self.historial,
        }

    def _importar_estado(self, e: dict) -> None:
        if e.get("usuario") != self.usuario:
            raise ErrorBoveda("La bóveda pertenece a otro usuario")
        self.ik_firma_priv, self.ik_firma_pub = P.ed25519_desde_bytes(unb64(e["ik_firma_priv"]))
        self.ik_dh_priv, self.ik_dh_pub = P.x25519_desde_bytes(unb64(e["ik_dh_priv"]))
        self.spk_priv, self.spk_pub = P.x25519_desde_bytes(unb64(e["spk_priv"]))
        self.contactos = {
            u: Contacto(u, unb64(c["ik_firma"]), unb64(c["ik_dh"]), c["verificado"], c["alerta_cambio"])
            for u, c in e["contactos"].items()
        }
        self.sids_vistos = {u: {unb64(x) for x in v} for u, v in e["sids_vistos"].items()}
        self.historial = e["historial"]

    def _persistir(self) -> None:
        if self._boveda is not None and self._boveda.abierta:
            self._boveda.guardar(self._exportar_estado())

    def cerrar(self) -> None:
        """Cierre ordenado: guarda el estado y borra la clave de la bóveda de memoria."""
        if self._boveda is not None and self._boveda.abierta:
            self._persistir()
            self._boveda.cerrar()

    def logout(self) -> None:
        if self.token:
            self.canal.llamar("logout", token=self.token)
            self.token = None

    def _exigir_sesion(self) -> str:
        if not self.token:
            raise ErrorProtocolo("Debe iniciar sesión")
        return self.token

    def rotar_claves(self) -> None:
        """Nueva identidad (p. ej. nuevo dispositivo). Los contactos recibirán
        la alerta de cambio de clave. Las sesiones previas se descartan."""
        bundle = self._generar_claves()
        self.canal.llamar("actualizar_bundle", token=self._exigir_sesion(), bundle=bundle)
        self.sesiones.clear()
        self.sesion_activa.clear()
        self._persistir()

    # ------------------------------------------------------------------ #
    # Directorio de contactos y verificación de identidad
    # ------------------------------------------------------------------ #
    def listar_usuarios(self) -> list[str]:
        return self.canal.llamar("listar_usuarios", token=self._exigir_sesion())["usuarios"]

    def _consultar_directorio(self, par: str) -> tuple[Contacto, dict]:
        """Descarga el bundle de `par`, lo compara con la identidad fijada
        (TOFU) y VERIFICA la firma Ed25519 antes de usar cualquier dato."""
        b = self.canal.llamar("obtener_bundle", token=self._exigir_sesion(), usuario=par)
        try:
            ik_f, ik_dh, spk, firma = (unb64(b[k]) for k in ("ik_firma", "ik_dh", "spk", "spk_firma"))
        except Exception as e:
            raise ErrorProtocolo("Bundle mal formado") from e
        if b.get("usuario") != par:
            raise ErrorProtocolo("El bundle no corresponde al usuario solicitado")

        c = self.contactos.get(par)
        if c is None:
            c = Contacto(par, ik_f, ik_dh)  # primer contacto: se fija la identidad
            self.contactos[par] = c
            self._persistir()
        elif c.ik_firma != ik_f or c.ik_dh != ik_dh:
            c.alerta_cambio = True
            c.verificado = False
            self._persistir()
            raise AlertaCambioDeClave(
                f"¡ALERTA! La clave de identidad de «{par}» cambió. Podría ser un "
                f"nuevo dispositivo o un ataque. Compare el safety number por un canal externo."
            )
        # Verificación obligatoria de la firma de la signed prekey
        P.verificar_firma(c.ik_firma, firma, P.datos_firmados_bundle(par, ik_dh, spk))
        return c, b

    def aceptar_cambio_de_clave(self, par: str) -> None:
        """El usuario acepta explícitamente la nueva identidad; vuelve a «no verificado»."""
        b = self.canal.llamar("obtener_bundle", token=self._exigir_sesion(), usuario=par)
        c = self.contactos[par]
        c.ik_firma, c.ik_dh = unb64(b["ik_firma"]), unb64(b["ik_dh"])
        c.verificado, c.alerta_cambio = False, False
        self.sesiones.pop(par, None)
        self.sesion_activa.pop(par, None)
        self._persistir()

    def safety_number(self, par: str) -> str:
        c = self.contactos[par]
        return P.safety_number(
            self.usuario, self.ik_firma_pub, self.ik_dh_pub, c.usuario, c.ik_firma, c.ik_dh
        )

    def marcar_verificado(self, par: str, numero_comparado: str) -> bool:
        """El usuario compara el número por un canal externo y lo teclea/escanea."""
        esperado = self.safety_number(par).replace(" ", "")
        recibido = numero_comparado.replace(" ", "")
        ok = hmac.compare_digest(esperado.encode(), recibido.encode())
        if ok:
            self.contactos[par].verificado = True
            self._persistir()
        return ok

    def directorio(self) -> list[dict]:
        return [
            {
                "usuario": c.usuario,
                "estado": "ALERTA: clave cambiada" if c.alerta_cambio
                else ("verificado" if c.verificado else "NO verificado"),
            }
            for c in self.contactos.values()
        ]

    # ------------------------------------------------------------------ #
    # Paso 3: Establecimiento de sesión (X3DH simplificado)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _derivar_sesion(par: str, sid: bytes, rol: str, dh1, dh2, dh3) -> Sesion:
        """SK = HKDF(0xFF*32 || DH1 || DH2 || DH3). Luego dos cadenas, una por
        sentido, para que ambos lados no compartan nunca una misma clave de mensaje."""
        ikm = bytearray(b"\xff" * 32) + dh1 + dh2 + dh3
        sk = P.hkdf(bytes(ikm), info=b"E2EE-X3DH-v1", sal=b"\x00" * 32)
        for b in (ikm, dh1, dh2, dh3):
            P.borrar(b)
        i2r = bytearray(P.hkdf(sk, info=b"E2EE-cadena-iniciador->respondedor"))
        r2i = bytearray(P.hkdf(sk, info=b"E2EE-cadena-respondedor->iniciador"))
        envio, recv = (i2r, r2i) if rol == "iniciador" else (r2i, i2r)
        return Sesion(par, sid, rol, envio, recv)

    def _x3dh_iniciador(self, c: Contacto, bundle: dict) -> Sesion:
        spk_b = unb64(bundle["spk"])
        ek_priv, ek_pub = P.x25519_generar()
        dh1 = P.x25519_dh(self.ik_dh_priv, spk_b)  # DH(IK_A, SPK_B)
        dh2 = P.x25519_dh(ek_priv, c.ik_dh)        # DH(EK_A, IK_B)
        dh3 = P.x25519_dh(ek_priv, spk_b)          # DH(EK_A, SPK_B)
        del ek_priv  # la efímera privada no se conserva
        return self._derivar_sesion(c.usuario, ek_pub, "iniciador", dh1, dh2, dh3)

    def _x3dh_respondedor(self, c: Contacto, ek_pub: bytes) -> Sesion:
        dh1 = P.x25519_dh(self.spk_priv, c.ik_dh)  # DH(SPK_B, IK_A)
        dh2 = P.x25519_dh(self.ik_dh_priv, ek_pub)  # DH(IK_B, EK_A)
        dh3 = P.x25519_dh(self.spk_priv, ek_pub)    # DH(SPK_B, EK_A)
        return self._derivar_sesion(c.usuario, ek_pub, "respondedor", dh1, dh2, dh3)

    # ------------------------------------------------------------------ #
    # Paso 4: Intercambio de mensajes
    # ------------------------------------------------------------------ #
    def _ad(self, emisor: str, receptor: str, ik_dh_emisor: bytes, ik_dh_receptor: bytes,
            ctr: int, sid: bytes) -> bytes:
        """Datos asociados: identidades de ambas partes, contador y sesión."""
        return P.lp(
            VERSION, emisor.encode(), receptor.encode(),
            ik_dh_emisor, ik_dh_receptor, ctr.to_bytes(8, "big"), sid,
        )

    def enviar(self, par: str, texto: str) -> int:
        self._exigir_sesion()
        c, bundle = self._consultar_directorio(par)  # puede lanzar AlertaCambioDeClave
        sesiones = self.sesiones.setdefault(par, {})
        sid = self.sesion_activa.get(par)
        if sid is None:
            ses = self._x3dh_iniciador(c, bundle)
            sesiones[ses.sid] = ses
            self.sesion_activa[par] = sid = ses.sid
            self.sids_vistos.setdefault(par, set()).add(sid)
        ses = sesiones[sid]

        ctr, ct = ses.cifrar(
            texto.encode("utf-8"),
            lambda n: self._ad(self.usuario, par, self.ik_dh_pub, c.ik_dh, n, ses.sid),
        )
        sobre = {
            "de": self.usuario,
            "para": par,
            "sid": b64(ses.sid),
            "init": ses.rol == "iniciador" and not ses.confirmada,
            "ctr": ctr,
            "ct": b64(ct),
        }
        self.canal.llamar("enviar", token=self.token, sobre=sobre)
        self._guardar(par, "enviado", texto, ctr)
        self._persistir()
        return ctr

    def recibir(self) -> list[dict]:
        """Descarga el buzón y procesa cada sobre. Los rechazados quedan en
        `self.rechazados` con el motivo; nunca se muestran como mensajes."""
        sobres = self.canal.llamar("recibir", token=self._exigir_sesion())["sobres"]
        recibidos = []
        for s in sobres:
            try:
                texto, ctr = self._procesar_sobre(s)
                recibidos.append({"de": s["de"], "texto": texto, "ctr": ctr})
            except (P.AutenticacionFallida, ErrorProtocolo, AlertaCambioDeClave, ErrorServidor,
                    KeyError, ValueError, TypeError) as e:
                self.rechazados.append({"de": s.get("de"), "motivo": f"{type(e).__name__}: {e}"})
        if sobres:
            self._persistir()
        return recibidos

    def _procesar_sobre(self, s: dict) -> tuple[str, int]:
        de, ctr = s["de"], s["ctr"]
        if s["para"] != self.usuario or not isinstance(ctr, int) or ctr < 0:
            raise ErrorProtocolo("Sobre mal dirigido o mal formado")
        c, _ = self._consultar_directorio(de)  # identidad del remitente: fijada + firma verificada
        sid, ct = unb64(s["sid"]), unb64(s["ct"])
        sesiones = self.sesiones.setdefault(de, {})
        vistos = self.sids_vistos.setdefault(de, set())

        nueva = None
        ses = sesiones.get(sid)
        if ses is None:
            if not s.get("init"):
                raise ErrorProtocolo("Mensaje de una sesión desconocida")
            if sid in vistos:
                raise ErrorProtocolo("Replay: sesión inicial ya vista/descartada")
            ses = nueva = self._x3dh_respondedor(c, sid)

        ad = self._ad(de, self.usuario, c.ik_dh, self.ik_dh_pub, ctr, sid)
        plano = ses.descifrar(ctr, ct, ad)  # lanza si la etiqueta Poly1305 no valida

        if nueva is not None:  # solo se registra la sesión si el primer mensaje autenticó
            sesiones[sid] = nueva
            vistos.add(sid)
            # La sesión nueva (autenticada) pasa a ser la activa: si el par reinició y
            # perdió su estado, nuestras respuestas deben ir por la sesión que él conoce.
            self.sesion_activa[de] = sid
        ses.confirmada = True
        texto = plano.decode("utf-8")
        self._guardar(de, "recibido", texto, ctr)
        return texto, ctr

    # ------------------------------------------------------------------ #
    # Historial local
    # ------------------------------------------------------------------ #
    def _guardar(self, par: str, sentido: str, texto: str, ctr: int) -> None:
        self.historial.setdefault(par, []).append(
            {"sentido": sentido, "texto": texto, "ctr": ctr, "ts": time.strftime("%H:%M:%S")}
        )

    def ver_historial(self, par: str) -> list[dict]:
        return list(self.historial.get(par, []))
