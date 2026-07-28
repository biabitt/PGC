from protocolo.cliente import Cliente
from protocolo.servidor import Servidor
from protocolo.sgc import SGC


def preparar_protocolo():
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

    registro_cliente = sgc.registrar_cliente(
        cliente.identidade
    )

    registro_servidor = sgc.registrar_servidor(
        servidor.identidade
    )

    cliente.receber_registro(
        registro_cliente
    )

    servidor.receber_registro(
        registro_servidor
    )

    return cliente, servidor


def test_autenticacao_legitima():
    cliente, servidor = preparar_protocolo()

    solicitacao = cliente.criar_solicitacao(
        servidor.identidade
    )

    desafio = servidor.gerar_desafio(
        solicitacao
    )

    resposta = cliente.responder_desafio(
        desafio
    )

    resultado = servidor.autenticar_cliente(
        resposta
    )

    assert resultado.autenticado is True
    assert resultado.confirmacao is not None

    servidor_valido = cliente.autenticar_servidor(
        resultado.confirmacao
    )

    assert servidor_valido is True


def test_chaves_de_sessao_iguais():
    cliente, servidor = preparar_protocolo()

    solicitacao = cliente.criar_solicitacao(
        servidor.identidade
    )

    desafio = servidor.gerar_desafio(
        solicitacao
    )

    resposta = cliente.responder_desafio(
        desafio
    )

    resultado = servidor.autenticar_cliente(
        resposta
    )

    assert resultado.autenticado is True

    assert cliente.chave_sessao is not None
    assert servidor.chave_sessao is not None

    assert (
        cliente.chave_sessao
        == servidor.chave_sessao
    )


def test_identidade_cliente_recuperada():
    cliente, servidor = preparar_protocolo()

    solicitacao = cliente.criar_solicitacao(
        servidor.identidade
    )

    desafio = servidor.gerar_desafio(
        solicitacao
    )

    resposta = cliente.responder_desafio(
        desafio
    )

    resultado = servidor.autenticar_cliente(
        resposta
    )

    assert resultado.autenticado is True
    assert (
        resultado.identidade_cliente
        == cliente.identidade
    )