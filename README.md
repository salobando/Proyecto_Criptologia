# Alternativa A — Mensajería segura extremo a extremo (entregas E1–E2)

Simulación en Python (sin dependencias fuera de `cryptography`) del servicio descrito
en la sección 5 del enunciado y en el Documento de Diseño E1. Clientes de consola y
servidor de retransmisión/directorio que **no puede leer** las conversaciones.

## Ejecución
```bash
pip install -r requirements.txt
python main.py demo      # recorre los 5 pasos del flujo (5.2) con salida explicada
python main.py cli       # consola interactiva (varios usuarios en un proceso)
python pruebas_e2.py     # 27 pruebas automáticas (flujo, primitivas y cuenta persistente)
```
Las contraseñas del demo y de las pruebas se generan aleatoriamente en cada ejecución:
no hay secretos en el código ni en el repositorio.

## Correspondencia con el Documento de Diseño (E1)
| Sección E1 | Dónde está |
|---|---|
| 3. Arquitectura (Cliente A/B, servidor) | `e2ee/cliente.py`, `e2ee/servidor.py`, `e2ee/red.py` |
| 4. Secuencia X3DH simplificado | `Cliente._x3dh_iniciador / _x3dh_respondedor` |
| 5. Tabla de primitivas y parámetros | `e2ee/primitivas.py` (todas de `cryptography`) |
| 6. Modelo de amenazas | Verificación de firma, AEAD con AD, contador/replay, safety numbers |
| 7. Hito 2 (E2): registro, Argon2id, cifrado/descifrado E2E por CLI | `main.py demo` / `main.py cli` |

| Rol (E1 §2) | Módulo |
|---|---|
| Arquitecto criptográfico / Especialista en criptografía | `primitivas.py`, protocolo en `cliente.py` |
| Desarrollador del servidor | `servidor.py` (SQLite: usuarios, sesiones, buzón) |
| Desarrollador del cliente | `cliente.py`, `main.py cli` |
| Red team | `red.py` (`interceptor`) y `pruebas_e2.py`; scripts completos → E5 |
| Integrador | `main.py`, `README.md` |

## Modo interactivo con 3 terminales (TCP en localhost)
Abra tres terminales en la carpeta del proyecto:
```bash
python servidor_tcp.py          # Terminal 1: servidor (BD persistente servidor.db; comando 'bd')
python cliente_cli.py alice     # Terminal 2: remitente
python cliente_cli.py bob       # Terminal 3: destinatario
```
En cada cliente: `enviar bob Hola` (o `enviar alice ...`). El cliente muestra en gris lo que
**envía al servidor** y lo que **recibe de él**, y en verde el mensaje **descifrado localmente**.
Los mensajes entrantes aparecen solos (el cliente consulta el buzón cada segundo).
Otros comandos: `safety`, `verificar`, `contactos`, `historial`, `rotar`, `aceptar`, `usuarios`.

### Cuentas persistentes (registro, almacenamiento y login)
* **Servidor**: usuarios (sal + Argon2id), bundle público y sesiones en SQLite (`servidor.db`, o `--bd :memory:`).
  Nombres de usuario: 3-32 caracteres ASCII (letras, dígitos, `_`). Tras 5 contraseñas erróneas seguidas el
  login se bloquea con espera creciente (30 s ... 15 min), igual para cuentas existentes e inexistentes.
* **Cliente**: la primera vez `python cliente_cli.py alice` ofrece crear la cuenta (contraseña repetida dos
  veces). Las claves privadas, los contactos fijados (TOFU), los `sid` ya vistos (anti-replay) y el historial
  se guardan en `datos_clientes/alice.vault`, cifrados con ChaCha20-Poly1305 con una clave derivada de la
  contraseña (Argon2id + HKDF, sal propia distinta de la del servidor). Las siguientes veces solo se pide la contraseña.
* **Cuenta en servidor pero sin bóveda** (equipo nuevo / bóveda perdida): opción `[2]`, entra con la contraseña y
  publica una identidad nueva; los contactos reciben la alerta de cambio de clave y deben re-verificar el safety number.
* Las cadenas del ratchet **no** se guardan: tras un reinicio se negocia una sesión X3DH nueva (conserva el secreto hacia adelante).
* La carpeta `datos_clientes/` y `*.db` no deben subirse al repositorio (ver `.gitignore`).

## Protocolo
1. **Registro**: cada cliente genera Ed25519 (identidad/firma), X25519 (identidad DH) y una
   *signed prekey* X25519. La firma cubre `usuario ‖ IK_dh ‖ SPK`. El servidor recibe solo claves públicas.
2. **Autenticación**: Argon2id (64 MiB, t=3, p=4, sal 128 b); token de sesión aleatorio de 256 b
   con expiración (el servidor guarda su SHA-256). Hash señuelo para usuarios inexistentes.
3. **Sesión (X3DH)**: Alice verifica la firma del bundle de Bob (obligatorio), genera EK y calcula
   `SK = HKDF(0xFF*32 ‖ DH(IK_A,SPK_B) ‖ DH(EK_A,IK_B) ‖ DH(EK_A,SPK_B))`. Se derivan dos cadenas (una por sentido).
4. **Mensajes**: ratchet simétrico `mk = HMAC(CK,0x01)`, `CK' = HMAC(CK,0x02)`; de `mk` se derivan
   clave y nonce de ChaCha20-Poly1305 (único por mensaje). AD = versión, emisor, receptor, IK_dh de
   ambos, contador y sesión. Contador ya visto ⇒ replay rechazado; el estado solo avanza si el tag autentica.
5. **Verificación**: safety number de 60 dígitos (SHA-256) idéntico en ambos lados; estado
   «verificado / no verificado» y alerta si cambia la identidad de un contacto.

## Limitaciones conocidas (para el informe)
* Sin Double Ratchet completo (extensión opcional): si se filtra la cadena actual, los mensajes
  futuros de esa sesión quedan expuestos; los anteriores siguen protegidos (forward secrecy simétrico).
* Sin *one-time prekeys* ni rotación de la signed prekey (opcional en 5.4).
* Las claves privadas en disco solo existen dentro de la bóveda cifrada; en memoria el borrado en Python es de mejor esfuerzo.
* Contraseña olvidada = bóveda irrecuperable (no hay recuperación de claves); solo queda el modo «claves nuevas».
* El login envía la contraseña al servidor: en red real exige TLS (el transporte TCP actual no lo implementa).
* El bloqueo por intentos permite que quien conozca un nombre de usuario lo bloquee temporalmente (DoS acotado a 15 min).
* Metadatos (quién, a quién, cuándo, contador) visibles para el servidor.
* El canal es simulado (JSON en proceso); en una red real iría sobre TLS/WSS.
* Pendiente para E3–E7: scripts de ataque completos (E5), Docker, informe y video.
