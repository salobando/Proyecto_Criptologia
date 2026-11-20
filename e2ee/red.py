"""
Canal de red simulado entre clientes y servidor.

Todo lo que cruza este canal se serializa a JSON (como en una red real), de
modo que cliente y servidor nunca comparten objetos por referencia. El campo
`interceptor` deja un punto de enganche para el atacante activo de red del
modelo de amenazas (sección 6 del diseño); los scripts de ataque de la
entrega E5 podrán usarlo sin modificar cliente ni servidor.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Callable


def b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def unb64(texto: str) -> bytes:
    return base64.b64decode(texto.encode("ascii"), validate=True)


class CanalSimulado:
    """Equivalente a una conexión TLS cliente-servidor (el contenido E2EE no
    depende de ella)."""

    def __init__(self, servidor, interceptor: Callable[[str, dict], dict] | None = None):
        self._servidor = servidor
        # interceptor(metodo, argumentos) -> argumentos (posiblemente alterados)
        self.interceptor = interceptor
        self.trafico: list[tuple[str, str]] = []  # registro "tipo Wireshark"

    def llamar(self, metodo: str, **args: Any) -> Any:
        peticion = json.loads(json.dumps(args))
        if self.interceptor:
            peticion = self.interceptor(metodo, peticion)
        self.trafico.append((metodo, json.dumps(peticion)[:200]))
        respuesta = getattr(self._servidor, metodo)(**peticion)
        return json.loads(json.dumps(respuesta))
