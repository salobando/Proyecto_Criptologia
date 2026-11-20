"""
Transporte TCP real (localhost) para correr servidor y clientes en procesos
distintos. Protocolo de línea: un objeto JSON por línea.

    petición  -> {"metodo": "...", "args": {...}}
    respuesta <- {"ok": true,  "resultado": {...}}
              |  {"ok": false, "error": "..."}

`CanalTCP` tiene la misma interfaz que `CanalSimulado` (método `llamar`), así
que `Cliente` funciona sin cambios.
"""
from __future__ import annotations

import json
import socket
import threading
from typing import Any, Callable

from .servidor import ErrorServidor

PUERTO_POR_DEFECTO = 8765


class CanalTCP:
    def __init__(self, host: str = "127.0.0.1", puerto: int = PUERTO_POR_DEFECTO,
                 al_enviar: Callable[[str, dict], None] | None = None,
                 al_recibir: Callable[[str, Any], None] | None = None):
        self._sock = socket.create_connection((host, puerto), timeout=10)
        self._f = self._sock.makefile("rw", encoding="utf-8", newline="\n")
        self._lock = threading.Lock()  # un hilo a la vez usa el socket
        self.al_enviar = al_enviar
        self.al_recibir = al_recibir

    def llamar(self, metodo: str, **args: Any) -> Any:
        with self._lock:
            if self.al_enviar:
                self.al_enviar(metodo, args)
            self._f.write(json.dumps({"metodo": metodo, "args": args}) + "\n")
            self._f.flush()
            linea = self._f.readline()
            if not linea:
                raise ConnectionError("El servidor cerró la conexión")
            resp = json.loads(linea)
            if self.al_recibir:
                self.al_recibir(metodo, resp.get("resultado") if resp["ok"] else resp["error"])
            if not resp["ok"]:
                raise ErrorServidor(resp["error"])
            return resp["resultado"]

    def cerrar(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass
