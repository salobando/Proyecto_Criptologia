"""
Pruebas de humo de la entrega E2 (flujo básico + propiedades criptográficas
mínimas). Los scripts de ataque completos pertenecen a la entrega E5.

Ejecutar:  python pruebas_e2.py
"""
import os
import secrets
import tempfile
import unittest

from e2ee import primitivas as P
from e2ee.almacen import ContrasenaIncorrecta
from e2ee.cliente import AlertaCambioDeClave, Cliente, ErrorProtocolo
from e2ee.red import CanalSimulado, b64, unb64
from e2ee.servidor import ErrorServidor, Servidor

# Contraseñas aleatorias por ejecución: nunca se escriben secretos en el repo
PW = {u: secrets.token_urlsafe(12) for u in ("alice", "bob", "carol")}


def montar(*usuarios):
    srv = Servidor()
    canal = CanalSimulado(srv)
    cs = {}
    for u in usuarios:
        c = Cliente(u, canal)
        c.registrar(PW[u])
        c.login(PW[u])
        cs[u] = c
    return srv, canal, cs


class PruebasPrimitivas(unittest.TestCase):
    def test_aead_rechaza_alteracion_y_ad_distinto(self):
        k, n = secrets.token_bytes(32), secrets.token_bytes(12)
        ct = P.aead_cifrar(k, n, b"hola", b"ad")
        self.assertEqual(P.aead_descifrar(k, n, ct, b"ad"), b"hola")
        malo = bytearray(ct); malo[0] ^= 1
        with self.assertRaises(P.AutenticacionFallida):
            P.aead_descifrar(k, n, bytes(malo), b"ad")
        with self.assertRaises(P.AutenticacionFallida):
            P.aead_descifrar(k, n, ct, b"otro")

    def test_firma_invalida_se_rechaza(self):
        priv, pub = P.ed25519_generar()
        f = P.firmar(priv, b"datos")
        P.verificar_firma(pub, f, b"datos")
        with self.assertRaises(P.AutenticacionFallida):
            P.verificar_firma(pub, f, b"datos2")

    def test_argon2id(self):
        sal, h = P.argon2_hash("contraseña-de-prueba")
        self.assertTrue(P.argon2_verificar("contraseña-de-prueba", sal, h))
        self.assertFalse(P.argon2_verificar("otra", sal, h))

    def test_safety_number_simetrico_60_digitos(self):
        a = (P.ed25519_generar()[1], P.x25519_generar()[1])
        b = (P.ed25519_generar()[1], P.x25519_generar()[1])
        s1 = P.safety_number("alice", *a, "bob", *b)
        s2 = P.safety_number("bob", *b, "alice", *a)
        self.assertEqual(s1, s2)
        self.assertEqual(len(s1.replace(" ", "")), 60)


class PruebasFlujo(unittest.TestCase):
    def test_ida_y_vuelta_y_orden(self):
        _, _, c = montar("alice", "bob")
        c["alice"].enviar("bob", "uno"); c["alice"].enviar("bob", "dos")
        self.assertEqual([m["texto"] for m in c["bob"].recibir()], ["uno", "dos"])
        c["bob"].enviar("alice", "respuesta")
        self.assertEqual([m["texto"] for m in c["alice"].recibir()], ["respuesta"])
        c["alice"].enviar("bob", "tres")
        self.assertEqual([m["texto"] for m in c["bob"].recibir()], ["tres"])

    def test_entrega_a_usuario_desconectado(self):
        srv, _, c = montar("alice", "bob")
        c["bob"].logout()
        c["alice"].enviar("bob", "mensaje offline")
        c["bob"].login(PW["bob"])
        self.assertEqual(c["bob"].recibir()[0]["texto"], "mensaje offline")

    def test_servidor_solo_ve_texto_cifrado(self):
        srv, _, c = montar("alice", "bob")
        c["alice"].enviar("bob", "SECRETO-123")
        self.assertNotIn(b"SECRETO-123", repr(srv.volcado_bd()).encode())

    def test_clave_de_mensaje_distinta_cada_vez(self):
        _, canal, c = montar("alice", "bob")
        c["alice"].enviar("bob", "igual"); c["alice"].enviar("bob", "igual")
        cts = [m for m in canal.trafico if m[0] == "enviar"]
        self.assertNotEqual(cts[0][1].split('"ct"')[1], cts[1][1].split('"ct"')[1])

    def test_texto_cifrado_alterado_se_rechaza(self):
        srv, canal, c = montar("alice", "bob")
        def alterar(metodo, args):
            if metodo == "enviar":
                ct = bytearray(unb64(args["sobre"]["ct"])); ct[0] ^= 1
                args["sobre"]["ct"] = b64(bytes(ct))
            return args
        canal.interceptor = alterar
        c["alice"].enviar("bob", "hola")
        canal.interceptor = None
        self.assertEqual(c["bob"].recibir(), [])
        self.assertIn("AutenticacionFallida", c["bob"].rechazados[0]["motivo"])

    def test_replay_rechazado(self):
        srv, canal, c = montar("alice", "bob")
        copias = []
        def copiar(metodo, args):
            if metodo == "enviar": copias.append(args["sobre"])
            return args
        canal.interceptor = copiar
        c["alice"].enviar("bob", "pago de 10")
        canal.interceptor = None
        self.assertEqual(len(c["bob"].recibir()), 1)
        srv.enviar(c["alice"].token, copias[0])  # el atacante reenvía el sobre
        self.assertEqual(c["bob"].recibir(), [])
        self.assertIn("Replay", c["bob"].rechazados[-1]["motivo"])

    def test_mitm_signed_prekey_sustituida(self):
        srv, canal, c = montar("alice", "bob")
        atacante_priv, atacante_pub = P.x25519_generar()
        # El servidor malicioso devuelve el bundle de Bob con su propia SPK
        orig = srv.obtener_bundle
        def malicioso(token, usuario):
            b = orig(token, usuario)
            if usuario == "bob": b["spk"] = b64(atacante_pub)
            return b
        srv.obtener_bundle = malicioso
        from e2ee.primitivas import AutenticacionFallida
        with self.assertRaises(AutenticacionFallida):
            c["alice"].enviar("bob", "hola")

    def test_cambio_de_identidad_genera_alerta(self):
        _, _, c = montar("alice", "bob")
        c["alice"].enviar("bob", "hola")
        c["bob"].rotar_claves()
        with self.assertRaises(AlertaCambioDeClave):
            c["alice"].enviar("bob", "otra vez")
        self.assertIn("ALERTA", c["alice"].directorio()[0]["estado"])
        c["alice"].aceptar_cambio_de_clave("bob")
        c["alice"].enviar("bob", "con nueva identidad")
        self.assertEqual(c["bob"].recibir()[-1]["texto"], "con nueva identidad")

    def test_verificacion_safety_number(self):
        _, _, c = montar("alice", "bob")
        c["alice"].enviar("bob", "hola"); c["bob"].recibir()
        self.assertFalse(c["alice"].contactos["bob"].verificado)
        self.assertEqual(c["alice"].safety_number("bob"), c["bob"].safety_number("alice"))
        self.assertFalse(c["alice"].marcar_verificado("bob", "0" * 60))
        self.assertTrue(c["alice"].marcar_verificado("bob", c["bob"].safety_number("alice")))

    def test_login_incorrecto_y_usuario_duplicado(self):
        srv, canal, c = montar("alice")
        with self.assertRaises(ErrorServidor):
            srv.login("alice", "contraseña-mala-1")
        with self.assertRaises(ErrorServidor):
            srv.login("noexiste", "contraseña-mala-1")
        with self.assertRaises(ErrorServidor):
            Cliente("alice", canal).registrar(PW["alice"])

    def test_token_invalido(self):
        srv, _, _ = montar("alice")
        with self.assertRaises(ErrorServidor):
            srv.recibir("token-falso")


class PruebasCuentaPersistente(unittest.TestCase):
    """Registro, almacenamiento de la cuenta y reinicio de sesión (autenticación)."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.bd = os.path.join(self.dir.name, "servidor.db")
        self.srv = Servidor(self.bd)
        self.canal = CanalSimulado(self.srv)

    def ruta(self, u):
        return os.path.join(self.dir.name, f"{u}.vault")

    def nuevo(self, u, pw=None):
        pw = pw or PW[u]
        c = Cliente(u, self.canal, ruta_boveda=self.ruta(u))
        c.registrar(pw)
        c.login(pw)
        return c

    def test_reinicio_conserva_identidad_contactos_e_historial(self):
        alice = self.nuevo("alice")
        bob = Cliente("bob", self.canal); bob.registrar(PW["bob"]); bob.login(PW["bob"])
        alice.enviar("bob", "antes del reinicio"); bob.recibir()
        pub = alice.ik_firma_pub
        alice.cerrar()
        # «Reinicio»: instancia nueva sin nada en memoria; solo existe el archivo de la bóveda
        alice2 = Cliente("alice", self.canal, ruta_boveda=self.ruta("alice"))
        alice2.login(PW["alice"])
        self.assertEqual(alice2.ik_firma_pub, pub)
        self.assertIn("bob", alice2.contactos)
        self.assertEqual(alice2.ver_historial("bob")[0]["texto"], "antes del reinicio")
        # Y la conversación sigue funcionando en ambos sentidos
        alice2.enviar("bob", "después del reinicio")
        self.assertEqual(bob.recibir()[0]["texto"], "después del reinicio")
        bob.enviar("alice", "te leo")
        self.assertEqual(alice2.recibir()[0]["texto"], "te leo")

    def test_reinicio_del_receptor_y_replay_del_mensaje_inicial(self):
        copias = []
        def copiar(metodo, args):
            if metodo == "enviar": copias.append(args["sobre"])
            return args
        alice = Cliente("alice", self.canal); alice.registrar(PW["alice"]); alice.login(PW["alice"])
        bob = self.nuevo("bob")
        self.canal.interceptor = copiar
        alice.enviar("bob", "pago de 10")
        self.canal.interceptor = None
        self.assertEqual(len(bob.recibir()), 1)
        bob.cerrar()
        bob2 = Cliente("bob", self.canal, ruta_boveda=self.ruta("bob"))
        bob2.login(PW["bob"])
        self.srv.enviar(alice.token, copias[0])  # el atacante reenvía el sobre inicial
        self.assertEqual(bob2.recibir(), [])  # los sid vistos sobreviven al reinicio
        self.assertIn("Replay", bob2.rechazados[-1]["motivo"])

    def test_contrasena_incorrecta_no_abre_la_boveda(self):
        self.nuevo("alice").cerrar()
        c = Cliente("alice", self.canal, ruta_boveda=self.ruta("alice"))
        with self.assertRaises(ContrasenaIncorrecta):
            c.login("contraseña-equivocada")
        self.assertIsNone(c.token)

    def test_boveda_alterada_se_detecta(self):
        self.nuevo("alice").cerrar()
        with open(self.ruta("alice"), "r+b") as f:
            f.seek(-5, os.SEEK_END); b = f.read(1); f.seek(-5, os.SEEK_END); f.write(bytes([b[0] ^ 1]))
        with self.assertRaises(ContrasenaIncorrecta):
            Cliente("alice", self.canal, ruta_boveda=self.ruta("alice")).login(PW["alice"])

    def test_boveda_en_disco_no_contiene_secretos(self):
        alice = self.nuevo("alice")
        bob = Cliente("bob", self.canal); bob.registrar(PW["bob"]); bob.login(PW["bob"])
        alice.enviar("bob", "TEXTO-SECRETO-XYZ")
        alice.cerrar()
        with open(self.ruta("alice"), "rb") as f:
            crudo = f.read()
        self.assertNotIn(b"TEXTO-SECRETO-XYZ", crudo)
        self.assertNotIn(P.ed25519_priv_bytes(alice.ik_firma_priv), crudo)
        self.assertNotIn(P.x25519_priv_bytes(alice.ik_dh_priv), crudo)
        self.assertNotIn(b64(P.x25519_priv_bytes(alice.ik_dh_priv)).encode(), crudo)

    def test_registro_no_sobrescribe_bóveda_existente(self):
        self.nuevo("alice").cerrar()
        with self.assertRaises(ErrorProtocolo):
            Cliente("alice", self.canal, ruta_boveda=self.ruta("alice")).registrar(PW["alice"])

    def test_registro_rechazado_no_deja_boveda_huerfana(self):
        self.nuevo("alice").cerrar()
        c = Cliente("alice", self.canal, ruta_boveda=os.path.join(self.dir.name, "otra.vault"))
        with self.assertRaises(ErrorServidor):  # el usuario ya existe en el servidor
            c.registrar(PW["alice"])
        self.assertFalse(os.path.exists(os.path.join(self.dir.name, "otra.vault")))

    def test_servidor_persiste_usuarios_en_disco(self):
        self.nuevo("alice").cerrar()
        srv2 = Servidor(self.bd)  # el servidor «reinicia» sobre el mismo archivo
        self.assertIn("token", srv2.login("alice", PW["alice"]))
        with self.assertRaises(ErrorServidor):
            srv2.login("alice", "contraseña-mala-1")

    def test_bloqueo_tras_intentos_fallidos(self):
        self.nuevo("alice").cerrar()
        for _ in range(5):
            with self.assertRaises(ErrorServidor):
                self.srv.login("alice", "contraseña-mala-1")
        with self.assertRaises(ErrorServidor) as cm:
            self.srv.login("alice", PW["alice"])  # ni con la contraseña correcta
        self.assertIn("Demasiados intentos", str(cm.exception))
        # Un usuario inexistente se bloquea igual (no se puede enumerar cuentas)
        for _ in range(5):
            with self.assertRaises(ErrorServidor):
                self.srv.login("fantasma", "contraseña-mala-1")
        with self.assertRaises(ErrorServidor) as cm:
            self.srv.login("fantasma", "contraseña-mala-1")
        self.assertIn("Demasiados intentos", str(cm.exception))

    def test_nombres_de_usuario_estrictos(self):
        bundle = Cliente("zzz", self.canal)._generar_claves()
        for malo in ("аlice", "ab", "a" * 33, "1alice", "al ice", "../x"):  # 1.º: 'а' cirílica
            with self.assertRaises(ErrorServidor, msg=malo):
                self.srv.registrar(malo, "contraseña-larga-1", bundle)

    def test_nuevo_dispositivo_genera_alerta_en_contactos(self):
        self.nuevo("alice").cerrar()
        bob = Cliente("bob", self.canal); bob.registrar(PW["bob"]); bob.login(PW["bob"])
        bob.enviar("alice", "hola")
        otro_pc = Cliente("alice", self.canal, ruta_boveda=os.path.join(self.dir.name, "pc2.vault"))
        otro_pc.login_nuevo_dispositivo(PW["alice"])
        with self.assertRaises(AlertaCambioDeClave):
            bob.enviar("alice", "¿eres tú?")
        # y la identidad nueva queda guardada: puede volver a entrar sin repetir el proceso
        otro_pc.cerrar()
        Cliente("alice", self.canal, ruta_boveda=os.path.join(self.dir.name, "pc2.vault")).login(PW["alice"])

    def test_bovedas_obsoleta_frente_al_servidor_se_detecta(self):
        a = self.nuevo("alice"); a.cerrar()
        otro_pc = Cliente("alice", self.canal, ruta_boveda=os.path.join(self.dir.name, "pc2.vault"))
        otro_pc.login_nuevo_dispositivo(PW["alice"])  # rota las claves publicadas
        vieja = Cliente("alice", self.canal, ruta_boveda=self.ruta("alice"))
        with self.assertRaises(ErrorProtocolo):
            vieja.login(PW["alice"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
