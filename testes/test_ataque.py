from ataque.atacante import Atacante

from protocolo.cliente import Cliente
from protocolo.servidor import Servidor
from protocolo.sgc import SGC


def preparar_cenario_ataque():
    sgc = SGC()
    parametros = sgc.configurar_sistema()

    cliente = Cliente(
        identidade="cliente01",
        senha="senha123",
        impressao_digital="digital01",
    )

    servidor = Servidor(
        identidade="servidor01"
    )

    cliente.receber_parametros(parametros)
    servidor.receber_parametros(parametros)

    cliente.receber_registro(
        sgc.registrar_cliente(
            cliente.identidade
        )
    )

    servidor.receber_registro(
        sgc.registrar_servidor(
            servidor.identidade
        )
    )

    atacante = Atacante(
        parametros=parametros
    )

    return cliente, servidor, atacante


def test_atacante_calcula_mesma_chave_do_cliente():
    cliente, servidor, atacante = (
        preparar_cenario_ataque()
    )

    solicitacao = cliente.criar_solicitacao(
        servidor.identidade
    )

    desafio_falso = atacante.interceptar_solicitacao(
        solicitacao
    )

    resposta_cliente = cliente.responder_desafio(
        desafio_falso
    )

    atacante.interceptar_resposta(
        resposta_cliente
    )

    assert cliente.chave_sessao is not None
    assert atacante.chave_sessao is not None

    assert (
        cliente.chave_sessao
        == atacante.chave_sessao
    )


def test_cliente_aceita_atacante_como_servidor():
    cliente, servidor, atacante = (
        preparar_cenario_ataque()
    )

    solicitacao = cliente.criar_solicitacao(
        servidor.identidade
    )

    desafio_falso = atacante.interceptar_solicitacao(
        solicitacao
    )

    resposta_cliente = cliente.responder_desafio(
        desafio_falso
    )

    confirmacao_falsa = atacante.interceptar_resposta(
        resposta_cliente
    )

    atacante_aceito = cliente.autenticar_servidor(
        confirmacao_falsa
    )

    assert atacante_aceito is True


def test_servidor_legitimo_nao_participa_do_ataque():
    cliente, servidor, atacante = (
        preparar_cenario_ataque()
    )

    solicitacao = cliente.criar_solicitacao(
        servidor.identidade
    )

    desafio_falso = atacante.interceptar_solicitacao(
        solicitacao
    )

    resposta_cliente = cliente.responder_desafio(
        desafio_falso
    )

    atacante.interceptar_resposta(
        resposta_cliente
    )

    assert servidor.chave_sessao is None


def test_atacante_recupera_identidade_cliente():
    cliente, servidor, atacante = (
        preparar_cenario_ataque()
    )

    solicitacao = cliente.criar_solicitacao(
        servidor.identidade
    )

    desafio_falso = atacante.interceptar_solicitacao(
        solicitacao
    )

    resposta_cliente = cliente.responder_desafio(
        desafio_falso
    )

    atacante.interceptar_resposta(
        resposta_cliente
    )

    assert (
        atacante.identidade_cliente
        == cliente.identidade
    )