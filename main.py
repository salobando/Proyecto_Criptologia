"""
Simulación de la Alternativa A — Mensajería segura extremo a extremo (E2).

Uso:
    python main.py demo    # recorre los 5 pasos del flujo del enunciado (sec. 5.2)
    python main.py cli     # consola interactiva (varios usuarios en un proceso)
"""
from __future__ import annotations

import getpass
import json
import secrets
import sys

from e2ee.cliente import AlertaCambioDeClave, Cliente
from e2ee.red import CanalSimulado
from e2ee.servidor import ErrorServidor, Servidor


def titulo(txt: str) -> None:
    print(f"\n{'=' * 72}\n{txt}\n{'=' * 72}")


# --------------------------------------------------------------------------- #
# Demo: sigue el orden del enunciado (5.2) y del diagrama de secuencia (E1, §4)
# --------------------------------------------------------------------------- #
def demo() -> None:
    servidor = Servidor()
    canal = CanalSimulado(servidor)
    alice, bob = Cliente("alice", canal), Cliente("bob", canal)
    # Contraseñas efímeras: nunca hay secretos escritos en el código/repositorio
    pw = {"alice": secrets.token_urlsafe(12), "bob": secrets.token_urlsafe(12)}

    titulo("1. REGISTRO — claves de identidad + signed prekey (solo públicas al servidor)")
    for c in (alice, bob):
        c.registrar(pw[c.usuario])
    for u in servidor.volcado_bd()["usuarios"]:
        print(f"  servidor guarda: usuario={u['usuario']}  hash_argon2id={u['hash_argon2id'][:24]}…  "
              f"ik_firma={u['bundle']['ik_firma'][:16]}…  (sin claves privadas ni contraseñas)")

    titulo("2. AUTENTICACIÓN — Argon2id + token de sesión opaco con expiración")
    try:
        servidor.login("alice", "contraseña-incorrecta")
    except ErrorServidor as e:
        print(f"  login con contraseña errónea  -> rechazado: {e}")
    for c in (alice, bob):
        c.login(pw[c.usuario])
        print(f"  {c.usuario}: sesión iniciada, token={c.token[:10]}… (el servidor guarda solo su SHA-256)")

    titulo("3. ESTABLECIMIENTO DE SESIÓN — verificación de firma Ed25519 + X3DH + HKDF")
    print("  Alice descarga el bundle de Bob, VERIFICA la firma de la signed prekey,")
    print("  genera clave efímera X25519 y deriva SK = HKDF(DH1‖DH2‖DH3) (en el primer envío).")

    titulo("4. INTERCAMBIO DE MENSAJES — ChaCha20-Poly1305 + ratchet simétrico HMAC-SHA256")
    for texto in ("Hola Bob, ¿estás ahí?", "Este mensaje usa otra clave distinta."):
        ctr = alice.enviar("bob", texto)
        print(f"  alice -> bob [ctr={ctr}] {texto!r}")
    print("  Lo que ve el servidor en el buzón de Bob (solo cifrado):")
    for s in servidor.volcado_bd()["buzon"]:
        print(f"    de={s['de']} para={s['para']} ctr={s['ctr']} ct={s['ct'][:40]}…")
    for m in bob.recibir():
        print(f"  bob descifra   [ctr={m['ctr']}] {m['texto']!r}")
    bob.enviar("alice", "¡Te leo! Respuesta con la cadena de envío de Bob.")
    for m in alice.recibir():
        print(f"  alice descifra [ctr={m['ctr']}] {m['texto']!r}")

    print("\n  Mensaje a un usuario DESCONECTADO (el servidor retiene solo texto cifrado):")
    bob.logout()
    alice.enviar("bob", "Te escribo mientras estás offline.")
    print(f"    mensajes en el buzón del servidor: {len(servidor.volcado_bd()['buzon'])}")
    bob.login(pw["bob"])
    for m in bob.recibir():
        print(f"    bob se reconecta y recibe: {m['texto']!r}")

    titulo("5. VERIFICACIÓN DE IDENTIDAD — safety number (SHA-256, 60 dígitos)")
    sn_a, sn_b = alice.safety_number("bob"), bob.safety_number("alice")
    print(f"  Alice ve: {sn_a}\n  Bob ve:   {sn_b}\n  Coinciden: {sn_a == sn_b}")
    print(f"  Directorio de Alice ANTES:  {alice.directorio()}")
    alice.marcar_verificado("bob", sn_b)  # simula comparación por canal externo
    print(f"  Directorio de Alice DESPUÉS: {alice.directorio()}")

    titulo("EXTRA — alerta visible si cambia la clave de identidad de un contacto")
    bob.rotar_claves()
    try:
        alice.enviar("bob", "¿sigues siendo tú?")
    except AlertaCambioDeClave as e:
        print(f"  {e}")
        print(f"  Directorio de Alice: {alice.directorio()}")

    titulo("HISTORIAL LOCAL (Alice ↔ Bob) — solo existe en el cliente")
    for h in alice.ver_historial("bob"):
        flecha = "→" if h["sentido"] == "enviado" else "←"
        print(f"  [{h['ts']}] {flecha} (ctr {h['ctr']}) {h['texto']}")

    titulo("TRÁFICO OBSERVADO POR UN ATACANTE DE RED (muestra)")
    for metodo, resumen in canal.trafico:
        if metodo in ("enviar",):
            print(f"  {metodo}: {resumen[:110]}…")
            break
    print("\nSimulación E2 finalizada: registro, autenticación, cifrado y descifrado E2E OK.")


# --------------------------------------------------------------------------- #
# CLI interactivo
# --------------------------------------------------------------------------- #
AYUDA = """Comandos:
  registro <usuario>          crea la cuenta (pide contraseña) e inicia sesión
  login <usuario>             inicia sesión de un usuario ya registrado en esta ejecución
  usar <usuario>              cambia de usuario activo
  usuarios                    usuarios registrados en el servidor
  enviar <dest> <texto...>    envía un mensaje cifrado
  bandeja                     descarga y descifra mensajes pendientes
  historial <contacto>        historial local
  contactos                   directorio con estado de verificación
  safety <contacto>           muestra el safety number
  verificar <contacto> <n>    compara el safety number recibido por un canal externo
  aceptar <contacto>          acepta un cambio de clave de identidad
  rotar                       cambia las claves del usuario activo (simula nuevo dispositivo)
  servidor                    muestra lo que vería quien vuelque la BD del servidor
  salir"""


def cli() -> None:
    servidor = Servidor()
    canal = CanalSimulado(servidor)
    clientes: dict[str, Cliente] = {}
    activo: Cliente | None = None
    print("Mensajería E2EE (simulada). Escriba 'ayuda' para ver los comandos.")
    while True:
        try:
            linea = input(f"[{activo.usuario if activo else '-'}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not linea:
            continue
        cmd, *args = linea.split()
        try:
            if cmd == "salir":
                break
            elif cmd == "ayuda":
                print(AYUDA)
            elif cmd == "registro" and args:
                c = Cliente(args[0], canal)
                pw = getpass.getpass("Contraseña (mín. 8 caracteres): ")
                c.registrar(pw)
                c.login(pw)
                clientes[args[0]] = activo = c
                print("Registrado y con sesión iniciada.")
            elif cmd == "login" and args and args[0] in clientes:
                clientes[args[0]].login(getpass.getpass("Contraseña: "))
                activo = clientes[args[0]]
            elif cmd == "usar" and args and args[0] in clientes:
                activo = clientes[args[0]]
            elif activo is None:
                print("Primero use 'registro <usuario>'.")
            elif cmd == "usuarios":
                print(", ".join(activo.listar_usuarios()))
            elif cmd == "enviar" and len(args) >= 2:
                print(f"enviado (ctr={activo.enviar(args[0], ' '.join(args[1:]))})")
            elif cmd == "bandeja":
                msgs = activo.recibir()
                for m in msgs:
                    print(f"  <{m['de']}> {m['texto']}")
                print(f"({len(msgs)} mensajes, {len(activo.rechazados)} rechazados en total)")
                for r in activo.rechazados[-3:]:
                    print(f"  RECHAZADO de {r['de']}: {r['motivo']}")
            elif cmd == "historial" and args:
                for h in activo.ver_historial(args[0]):
                    print(f"  [{h['ts']}] {'→' if h['sentido'] == 'enviado' else '←'} {h['texto']}")
            elif cmd == "contactos":
                for d in activo.directorio():
                    print(f"  {d['usuario']:<15} {d['estado']}")
            elif cmd == "safety" and args:
                print(activo.safety_number(args[0]))
            elif cmd == "verificar" and len(args) >= 2:
                ok = activo.marcar_verificado(args[0], " ".join(args[1:]))
                print("Verificado." if ok else "NO COINCIDE: no confíe en esta identidad.")
            elif cmd == "aceptar" and args:
                activo.aceptar_cambio_de_clave(args[0])
                print("Nueva identidad aceptada (estado: NO verificado).")
            elif cmd == "rotar":
                activo.rotar_claves()
                print("Claves rotadas.")
            elif cmd == "servidor":
                print(json.dumps(servidor.volcado_bd(), indent=1)[:1800])
            else:
                print("Comando no reconocido. Escriba 'ayuda'.")
        except AlertaCambioDeClave as e:
            print(f"⚠ {e}\n  Use 'safety <contacto>' y compare; luego 'aceptar <contacto>' si es legítimo.")
        except Exception as e:  # el CLI nunca debe caerse por un error de usuario
            print(f"Error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    modo = sys.argv[1] if len(sys.argv) > 1 else "demo"
    {"demo": demo, "cli": cli}.get(modo, demo)()
