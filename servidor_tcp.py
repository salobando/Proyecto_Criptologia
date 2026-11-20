"""
TERMINAL 1 — Servidor de retransmisión y directorio (escucha en localhost).

    python servidor_tcp.py [--puerto 8765] [--bd servidor.db]

Muestra cada petición recibida y lo que queda guardado en la base de datos.
Comandos en esta terminal:  bd  (volcado de la BD)   |   salir
"""
from __future__ import annotations

import argparse
import json
import os
import socketserver
import threading
import time

from e2ee.red_tcp import PUERTO_POR_DEFECTO
from e2ee.servidor import ErrorServidor, Servidor

os.system("")  # activa colores ANSI en la consola de Windows
C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "b": "\033[94m", "c": "\033[96m", "x": "\033[0m"}

SERVIDOR: Servidor
BLOQUEO = threading.Lock()  # serializa el acceso a SQLite y a la salida por consola


def hora() -> str:
    return time.strftime("%H:%M:%S")


def mostrar_peticion(metodo: str, args: dict) -> dict:
    """Copia de los argumentos apta para el log (sin contraseñas ni tokens completos)."""
    v = json.loads(json.dumps(args))
    if "contrasena" in v:
        v["contrasena"] = "<oculta en el log>"
    if isinstance(v.get("token"), str):
        v["token"] = v["token"][:8] + "…"
    return v


def mostrar_fila_usuario(usuario: str) -> None:
    for u in SERVIDOR.volcado_bd()["usuarios"]:
        if u["usuario"] == usuario:
            print(f"{C['g']}   BD ← usuarios:{C['x']}")
            print(f"      usuario       = {u['usuario']}")
            print(f"      sal (128 b)   = {u['sal']}")
            print(f"      hash Argon2id = {u['hash_argon2id']}   (NO se guarda la contraseña)")
            print(f"      bundle público= {json.dumps(u['bundle'])[:230]}…")


class Manejador(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        with BLOQUEO:
            print(f"{C['c']}[{hora()}] conexión abierta {peer}{C['x']}")
        for linea in self.rfile:
            try:
                msg = json.loads(linea.decode("utf-8"))
                metodo, args = msg["metodo"], msg["args"]
                if not isinstance(metodo, str) or not isinstance(args, dict):
                    raise ErrorServidor("Petición mal formada")
                if metodo.startswith("_") or metodo not in (
                    "registrar", "login", "logout", "obtener_bundle", "listar_usuarios",
                    "actualizar_bundle", "enviar", "recibir",
                ):
                    raise ErrorServidor("Método no permitido")
            except Exception:
                self.wfile.write(b'{"ok": false, "error": "peticion invalida"}\n')
                continue

            with BLOQUEO:
                # Usuario autenticado (si hay token válido), solo para el log
                quien = ""
                if isinstance(args, dict) and "token" in args:
                    try:
                        quien = f" ({SERVIDOR._usuario_de(args['token'])})"
                    except ErrorServidor:
                        quien = " (token inválido)"
                try:
                    resultado = getattr(SERVIDOR, metodo)(**args)
                    resp = {"ok": True, "resultado": resultado}
                except ErrorServidor as e:
                    resultado, resp = None, {"ok": False, "error": str(e)}
                except TypeError:
                    resultado, resp = None, {"ok": False, "error": "argumentos inválidos"}
                except Exception:  # una petición mal formada nunca debe tumbar al manejador
                    resultado, resp = None, {"ok": False, "error": "error interno"}

                # Evitar ruido: un `recibir` vacío (sondeo periódico) no se imprime
                vacio = metodo == "recibir" and resp["ok"] and not resultado["sobres"]
                if not vacio:
                    print(f"\n{C['y']}[{hora()}] ← RECIBIDO de {peer}{quien}: {metodo}{C['x']}")
                    print("   " + json.dumps(mostrar_peticion(metodo, args), ensure_ascii=False)[:600])
                    if resp["ok"]:
                        self._log_efecto(metodo, args, resultado)
                    else:
                        print(f"{C['r']}   → RECHAZADO: {resp['error']}{C['x']}")
            self.wfile.write((json.dumps(resp) + "\n").encode("utf-8"))

    @staticmethod
    def _log_efecto(metodo: str, args: dict, resultado: dict) -> None:
        if metodo == "registrar":
            mostrar_fila_usuario(args["usuario"])
        elif metodo == "login":
            print(f"{C['g']}   BD ← sesiones: guarda SHA-256 del token (el token en claro solo lo tiene el cliente){C['x']}")
        elif metodo == "enviar":
            n = len(SERVIDOR.volcado_bd()["buzon"])
            print(f"{C['g']}   BD ← buzon: sobre guardado SIN descifrar (solo cabecera + texto cifrado). "
                  f"Pendientes en total: {n}{C['x']}")
            print(f"   El servidor ve: de={args['sobre']['de']} para={args['sobre']['para']} "
                  f"ctr={args['sobre']['ctr']} ct={args['sobre']['ct'][:48]}…")
        elif metodo == "recibir":
            print(f"{C['g']}   BD → buzon: entrega {len(resultado['sobres'])} sobre(s) y los borra del buzón{C['x']}")
        elif metodo == "actualizar_bundle":
            print(f"{C['g']}   BD ← usuarios: bundle público actualizado (rotación de claves){C['x']}")


class ServidorTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    global SERVIDOR
    ap = argparse.ArgumentParser()
    ap.add_argument("--puerto", type=int, default=PUERTO_POR_DEFECTO)
    ap.add_argument("--bd", default="servidor.db",
                    help="archivo SQLite persistente (use ':memory:' para una BD volátil)")
    a = ap.parse_args()
    SERVIDOR = Servidor(a.bd)
    srv = ServidorTCP(("127.0.0.1", a.puerto), Manejador)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"{C['b']}Servidor E2EE escuchando en 127.0.0.1:{a.puerto}  (BD: {a.bd}){C['x']}")
    print("Comandos: 'bd' muestra lo almacenado | 'salir' termina.\n")
    while True:
        try:
            cmd = input().strip()
        except (EOFError, KeyboardInterrupt):
            break
        if cmd == "salir":
            break
        if cmd == "bd":
            with BLOQUEO:
                print(json.dumps(SERVIDOR.volcado_bd(), indent=1, ensure_ascii=False))
    srv.shutdown()


if __name__ == "__main__":
    main()
