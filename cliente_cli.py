"""
TERMINALES 2 y 3 — Cliente de consola (uno por usuario: remitente / destinatario).

    python cliente_cli.py alice
    python cliente_cli.py bob

La cuenta es persistente: la primera vez se crea (contraseña + bóveda local cifrada
en datos_clientes/<usuario>.vault); las siguientes basta con iniciar sesión.

Muestra (en gris) todo lo que SE ENVÍA al servidor y todo lo que SE RECIBE de él,
y (en verde) el mensaje ya descifrado localmente. Los mensajes entrantes se
detectan solos: el cliente consulta el buzón cada segundo.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import threading
import time

from e2ee.almacen import ContrasenaIncorrecta, ErrorBoveda
from e2ee.cliente import AlertaCambioDeClave, Cliente, ErrorProtocolo
from e2ee.red_tcp import PUERTO_POR_DEFECTO, CanalTCP
from e2ee.servidor import ErrorServidor

os.system("")  # activa colores ANSI en Windows
G, V, R, A, X = "\033[90m", "\033[92m", "\033[91m", "\033[93m", "\033[0m"
SALIDA = threading.Lock()  # evita que el hilo de recepción pise la salida
USUARIO = ""
RE_USUARIO = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,31}$")  # igual de estricto que el servidor


def p(texto: str = "") -> None:
    with SALIDA:
        print(texto)
        print(f"[{USUARIO}]> ", end="", flush=True)


def recortar(v, n=70):
    """Acorta strings largos (claves, textos cifrados) para que se lea el JSON."""
    if isinstance(v, dict):
        return {k: recortar(x, n) for k, x in v.items()}
    if isinstance(v, list):
        return [recortar(x, n) for x in v]
    if isinstance(v, str) and len(v) > n:
        return v[:n] + f"…(+{len(v) - n})"
    return v


def al_enviar(metodo: str, args: dict) -> None:
    if metodo == "recibir":
        return  # sondeo periódico: solo se muestra si trae mensajes (ver al_recibir)
    a = json.loads(json.dumps(args))
    if "contrasena" in a:
        a["contrasena"] = "<oculta aquí; en red real viaja por TLS>"
    if "token" in a:
        a["token"] = a["token"][:8] + "…"
    p(f"{G}→ ENVIADO AL SERVIDOR  {metodo}\n   {json.dumps(recortar(a), ensure_ascii=False)}{X}")


def al_recibir(metodo: str, resultado) -> None:
    if metodo == "recibir" and isinstance(resultado, dict) and not resultado.get("sobres"):
        return  # sondeo vacío: no mostrar
    r = recortar(resultado)
    if metodo == "recibir":
        p(f"{G}→ ENVIADO AL SERVIDOR  recibir  (consulta del buzón){X}")
    if metodo == "login" and isinstance(resultado, dict):
        r = {"token": resultado["token"][:8] + "…"}
    p(f"{G}← RECIBIDO DEL SERVIDOR  {metodo}\n   {json.dumps(r, ensure_ascii=False)}{X}")


AYUDA = """Comandos:
  enviar <dest> <texto...>   cifra y envía un mensaje
  historial <contacto>       historial local descifrado
  contactos                  directorio y estado de verificación
  safety <contacto>          muestra tu safety number (compáralo con el del otro por otro canal)
  verificar <contacto> <n>   marca como verificado si el número coincide
  aceptar <contacto>         acepta un cambio de clave de identidad
  rotar                      cambia tus claves (simula un nuevo dispositivo)
  login                      vuelve a iniciar sesión (p. ej. si expiró la sesión)
  usuarios                   usuarios registrados
  salir"""


def autenticar(cli: Cliente, ruta: str) -> bool:
    """Cuenta nueva, inicio de sesión o recuperación en equipo nuevo."""
    try:
        if os.path.exists(ruta):
            print(f"Cuenta local encontrada para «{cli.usuario}».")
            cli.login(getpass.getpass("Contraseña: "))
            return True
        print(f"No hay cuenta local para «{cli.usuario}» en este equipo.")
        print("  [1] Crear cuenta nueva")
        print("  [2] La cuenta ya existe en el servidor: entrar aquí con claves NUEVAS")
        print("      (tus contactos verán una alerta de cambio de identidad)")
        op = input("Opción [1/2]: ").strip()
        if op == "1":
            pw = getpass.getpass("Elija una contraseña (mín. 8 caracteres): ")
            if pw != getpass.getpass("Repita la contraseña: "):
                print(f"{R}Las contraseñas no coinciden.{X}")
                return False
            cli.registrar(pw)
            cli.login(pw)
            print(f"{V}Cuenta creada. Claves guardadas cifradas en {ruta}{X}")
        elif op == "2":
            cli.login_nuevo_dispositivo(getpass.getpass("Contraseña de la cuenta: "))
            print(f"{A}Identidad nueva publicada. Re-verifique el safety number con sus contactos.{X}")
        else:
            return False
        return True
    except ContrasenaIncorrecta as e:
        print(f"{R}{e}{X}")
    except (ErrorServidor, ErrorProtocolo, ErrorBoveda) as e:
        print(f"{R}{e}{X}")
    return False


def main() -> None:
    global USUARIO
    ap = argparse.ArgumentParser()
    ap.add_argument("usuario")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--puerto", type=int, default=PUERTO_POR_DEFECTO)
    ap.add_argument("--datos", default="datos_clientes", help="carpeta de las bóvedas locales cifradas")
    a = ap.parse_args()
    USUARIO = a.usuario
    if not RE_USUARIO.match(a.usuario):
        print("Usuario inválido: 3-32 caracteres ASCII (letras, dígitos y «_», sin empezar por dígito).")
        return

    try:
        canal = CanalTCP(a.host, a.puerto, al_enviar, al_recibir)
    except OSError:
        print("No se pudo conectar. ¿Está corriendo 'python servidor_tcp.py'?")
        return
    ruta = os.path.join(a.datos, f"{a.usuario}.vault")
    cli = Cliente(a.usuario, canal, ruta_boveda=ruta)
    lock = threading.Lock()  # el Cliente no es seguro entre hilos

    if not autenticar(cli, ruta):
        canal.cerrar()
        return
    print(AYUDA)

    activo = True

    def sondeo() -> None:
        vistos = 0
        while activo:
            time.sleep(1)
            try:
                with lock:
                    if cli.token is None:
                        continue
                    msgs = cli.recibir()
                    rech = cli.rechazados[vistos:]
                    vistos = len(cli.rechazados)
            except ErrorServidor as e:
                if "Sesión" in str(e):  # token vencido (TTL 15 min): avisar una vez y pausar el sondeo
                    with lock:
                        cli.token = None
                    p(f"{A}⚠ Su sesión expiró. Escriba 'login' para volver a entrar.{X}")
                continue
            except Exception:
                continue
            for m in msgs:
                p(f"{V}📩 DESCIFRADO LOCALMENTE  de {m['de']} [ctr={m['ctr']}]: {m['texto']}{X}")
            for r in rech:
                p(f"{R}⛔ SOBRE RECHAZADO de {r['de']}: {r['motivo']}{X}")

    threading.Thread(target=sondeo, daemon=True).start()
    p()

    while True:
        try:
            linea = input().strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not linea:
            p()
            continue
        cmd, *args = linea.split()
        try:
            with lock:
                if cmd == "salir":
                    break
                elif cmd == "enviar" and len(args) >= 2:
                    texto = " ".join(args[1:])
                    ctr = cli.enviar(args[0], texto)
                    p(f"{V}✔ mensaje [ctr={ctr}] cifrado con ChaCha20-Poly1305 y enviado a {args[0]}: {texto!r}{X}")
                elif cmd == "historial" and args:
                    filas = [f"  [{h['ts']}] {'→' if h['sentido'] == 'enviado' else '←'} {h['texto']}"
                             for h in cli.ver_historial(args[0])]
                    p("\n".join(filas) or "  (vacío)")
                elif cmd == "contactos":
                    p("\n".join(f"  {d['usuario']:<15} {d['estado']}" for d in cli.directorio()) or "  (sin contactos aún)")
                elif cmd == "safety" and args:
                    cli._consultar_directorio(args[0])
                    p(f"Safety number con {args[0]}:\n  {cli.safety_number(args[0])}")
                elif cmd == "verificar" and len(args) >= 2:
                    ok = cli.marcar_verificado(args[0], " ".join(args[1:]))
                    p(f"{V}Identidad verificada.{X}" if ok else f"{R}NO COINCIDE: no confíe en esta identidad.{X}")
                elif cmd == "aceptar" and args:
                    cli.aceptar_cambio_de_clave(args[0])
                    p("Nueva identidad aceptada (estado: NO verificado).")
                elif cmd == "login":
                    cli.login(getpass.getpass("Contraseña: "))
                    p(f"{V}Sesión iniciada de nuevo.{X}")
                elif cmd == "rotar":
                    cli.rotar_claves()
                    p("Claves rotadas.")
                elif cmd == "usuarios":
                    p(", ".join(cli.listar_usuarios()))
                elif cmd == "ayuda":
                    p(AYUDA)
                else:
                    p("Comando no reconocido ('ayuda').")
        except AlertaCambioDeClave as e:
            p(f"{A}⚠ {e}{X}\n  Compare 'safety {args[0] if args else ''}' y use 'aceptar' si es legítimo.")
        except Exception as e:
            p(f"{R}Error: {type(e).__name__}: {e}{X}")
    activo = False
    with lock:
        cli.cerrar()  # guarda la bóveda y borra su clave de memoria
    canal.cerrar()


if __name__ == "__main__":
    main()
