import pytest

from protocolo.cliente import Cliente as ClienteTsaiLo
from protocolo.servidor import Servidor as ServidorTsaiLo
from protocolo.sgc import SGC
from protocolo_irshad.cliente import ClienteIrshad
from protocolo_irshad.cliente_puf import ClienteIrshadPUF
from protocolo_irshad.servidor import ServidorIrshad
from protocolo_jia.cliente import Usuario as UsuarioJia
from protocolo_jia.cliente_puf import UsuarioPUF as UsuarioJiaPUF
from protocolo_jia.rc import CentroRegistro as CentroRegistroJia
from protocolo_jia.servidor import ServidorMEC as ServidorMECJia
from protocolo_kaur.cliente import Usuario as UsuarioKaur
from protocolo_kaur.cliente_puf import UsuarioPUF as UsuarioKaurPUF
from protocolo_kaur.rc import CentroRegistro as CentroRegistroKaur
from protocolo_kaur.servidor import ServidorMEC as ServidorMECKaur
from protocolo_kaur.tipos import DadosPublicosServidor, DadosPublicosUsuario
from protocolo_tsailo.cliente_puf import ClienteTsaiLoPUF
from puf.credential_protector import CredentialProtector

PUF = [False, True]


def _preparar(cliente):
    if hasattr(cliente, "preparar_autenticacao"):
        cliente.preparar_autenticacao()


def _finalizar(cliente):
    if hasattr(cliente, "finalizar_sessao"):
        cliente.finalizar_sessao()


def _fluxo_tsailo(cliente, servidor):
    sgc = SGC()
    parametros = sgc.configurar_sistema()
    cliente.receber_parametros(parametros)
    servidor.receber_parametros(parametros)
    cliente.receber_registro(sgc.registrar_cliente(cliente.identidade))
    servidor.receber_registro(sgc.registrar_servidor(servidor.identidade))

    _preparar(cliente)
    desafio = servidor.gerar_desafio(cliente.criar_solicitacao(servidor.identidade))
    resultado = servidor.autenticar_cliente(cliente.responder_desafio(desafio))
    assert resultado.autenticado is True
    assert cliente.autenticar_servidor(resultado.confirmacao) is True
    assert cliente.chave_sessao == servidor.chave_sessao
    _finalizar(cliente)


@pytest.mark.parametrize("puf", PUF)
def test_tsailo(puf):
    cliente = ClienteTsaiLoPUF("c01") if puf else ClienteTsaiLo("c01", "senha")
    _fluxo_tsailo(cliente, ServidorTsaiLo("s01"))


@pytest.mark.parametrize("puf", PUF)
def test_irshad(puf):
    cliente = ClienteIrshadPUF("c01") if puf else ClienteIrshad("c01", "senha", "digital")
    _fluxo_tsailo(cliente, ServidorIrshad("s01"))


@pytest.mark.parametrize("puf", PUF)
def test_jia(puf):
    rc = CentroRegistroJia()
    parametros = rc.configurar_sistema()
    usuario = UsuarioJiaPUF("u01") if puf else UsuarioJia("u01")
    servidor = ServidorMECJia("s01")
    usuario.receber_parametros(parametros)
    servidor.receber_parametros(parametros)
    usuario.receber_registro(rc.registrar_usuario("u01"))
    servidor.receber_registro(rc.registrar_servidor("s01"))

    _preparar(usuario)
    resultado = servidor.autenticar_usuario(usuario.criar_mensagem_autenticacao("s01"))
    assert resultado.autenticado is True
    assert usuario.verificar_resposta(resultado.resposta) is True
    assert usuario.chave_sessao == servidor.chave_sessao
    _finalizar(usuario)


@pytest.mark.parametrize("puf", PUF)
def test_kaur(puf):
    rc = CentroRegistroKaur()
    parametros = rc.configurar_sistema()
    usuario = UsuarioKaurPUF("u01") if puf else UsuarioKaur("u01")
    servidor = ServidorMECKaur("s01")
    reg_u, reg_s = rc.registrar_usuario("u01"), rc.registrar_servidor("s01")
    usuario.receber_parametros(parametros)
    servidor.receber_parametros(parametros)
    usuario.receber_registro(reg_u)
    servidor.receber_registro(reg_s)
    servidor.registrar_usuario_publico(DadosPublicosUsuario(reg_u.sid_u, reg_u.r_u_ponto, reg_u.p_u))
    usuario.definir_servidor(DadosPublicosServidor(reg_s.sid_ms, reg_s.p_ms, reg_s.r_ms_ponto))

    _preparar(usuario)
    resultado = servidor.autenticar_usuario(usuario.criar_mensagem_autenticacao())
    assert resultado.autenticado is True
    confirmacao = usuario.verificar_resposta(resultado.resposta)
    assert confirmacao is not None
    assert servidor.verificar_confirmacao(confirmacao) is True
    assert usuario.chave_sessao == servidor.chave_sessao
    _finalizar(usuario)


def test_camada_puf_protege_e_recupera():
    protector = CredentialProtector.criar("TESTE", "c01")
    segredos = {"KEY": b"k" * 128, "SID": b"s" * 32}
    protector.registrar(segredos)
    assert protector.recuperar() == segredos
