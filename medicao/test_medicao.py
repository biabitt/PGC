"""
Testes da infraestrutura de medição.

Rodam o protocolo completo (normal e ataque) passando TODAS as mensagens
pelo codec, como acontece entre processos separados, e conferem a contagem
de operações.

    pytest medicao/
"""

import pytest
from py_ecc.optimized_bn128 import G1, G2, pairing

from ataque.atacante import Atacante
from criptografia.serializacao import (
    serializar_elemento_gt,
    serializar_ponto_g1,
    serializar_ponto_g2,
)
from medicao import codec, contadores
from medicao.config import (
    IDENTIDADE_CLIENTE,
    IDENTIDADE_SERVIDOR,
    IMPRESSAO_DIGITAL,
    SENHA_CLIENTE,
)
from medicao.provisionar import provisionar
from protocolo.cliente import Cliente
from protocolo.servidor import Servidor


@pytest.fixture(scope="module")
def dados(tmp_path_factory):
    pasta = tmp_path_factory.mktemp("dados")
    provisionar(pasta)
    return pasta


def novo_cliente(dados):
    cliente = Cliente(
        identidade=IDENTIDADE_CLIENTE,
        senha=SENHA_CLIENTE,
        impressao_digital=IMPRESSAO_DIGITAL,
    )
    cliente.receber_parametros(codec.carregar_parametros(dados))
    cliente.receber_registro(codec.carregar_registro_cliente(dados))
    return cliente


def novo_servidor(dados):
    servidor = Servidor(IDENTIDADE_SERVIDOR)
    servidor.receber_parametros(codec.carregar_parametros(dados))
    servidor.receber_registro(codec.carregar_registro_servidor(dados))
    return servidor


# ----------------------------------------------------------------------
# Codec
# ----------------------------------------------------------------------

def test_gt_ida_e_volta(dados):
    base = pairing(G2, G1)
    dados_gt = serializar_elemento_gt(base)

    assert len(dados_gt) == codec.TAMANHO_GT
    assert codec.desserializar_elemento_gt(dados_gt) == base


def test_parametros_ida_e_volta(dados):
    parametros = codec.carregar_parametros(dados)

    assert parametros.emparelhamento_base == pairing(G2, G1)
    assert serializar_ponto_g1(parametros.gerador_g1) == serializar_ponto_g1(G1)
    assert serializar_ponto_g2(parametros.gerador_g2) == serializar_ponto_g2(G2)


def test_gt_com_tamanho_errado_e_rejeitado():
    with pytest.raises(ValueError):
        codec.desserializar_elemento_gt(b"\x00" * 10)


# ----------------------------------------------------------------------
# Protocolo com mensagens em bytes
# ----------------------------------------------------------------------

def test_autenticacao_normal_com_mensagens_em_bytes(dados):
    cliente = novo_cliente(dados)
    servidor = novo_servidor(dados)

    m1 = codec.codificar_solicitacao(
        cliente.criar_solicitacao(IDENTIDADE_SERVIDOR)
    )
    m2 = codec.codificar_desafio(
        servidor.gerar_desafio(codec.decodificar_solicitacao(m1))
    )
    m3 = codec.codificar_resposta(
        cliente.responder_desafio(codec.decodificar_desafio(m2))
    )
    resultado = servidor.autenticar_cliente(codec.decodificar_resposta(m3))

    assert resultado.autenticado

    m4 = codec.codificar_confirmacao(resultado.confirmacao)

    assert cliente.autenticar_servidor(codec.decodificar_confirmacao(m4))
    assert cliente.chave_sessao == servidor.chave_sessao

    assert len(m2) == codec.TAMANHO_GT
    assert len(m4) == 32


def test_ataque_com_mensagens_em_bytes(dados):
    cliente = novo_cliente(dados)
    atacante = Atacante(parametros=codec.carregar_parametros(dados))

    m1 = codec.codificar_solicitacao(
        cliente.criar_solicitacao(IDENTIDADE_SERVIDOR)
    )
    m2 = codec.codificar_desafio(
        atacante.interceptar_solicitacao(codec.decodificar_solicitacao(m1))
    )
    m3 = codec.codificar_resposta(
        cliente.responder_desafio(codec.decodificar_desafio(m2))
    )
    m4 = codec.codificar_confirmacao(
        atacante.interceptar_resposta(codec.decodificar_resposta(m3))
    )

    assert cliente.autenticar_servidor(codec.decodificar_confirmacao(m4))
    assert cliente.chave_sessao == atacante.chave_sessao
    assert atacante.identidade_cliente == IDENTIDADE_CLIENTE


# ----------------------------------------------------------------------
# Contagem de operações
# ----------------------------------------------------------------------

def test_contagem_de_operacoes(dados):
    contadores.instalar()

    cliente = novo_cliente(dados)
    servidor = novo_servidor(dados)
    registro = {}

    solicitacao = cliente.criar_solicitacao(IDENTIDADE_SERVIDOR)

    with contadores.etapa(registro, "gerar_desafio"):
        desafio = servidor.gerar_desafio(solicitacao)

    with contadores.etapa(registro, "responder_desafio"):
        resposta = cliente.responder_desafio(desafio)

    with contadores.etapa(registro, "autenticar_cliente"):
        resultado = servidor.autenticar_cliente(resposta)

    assert resultado.autenticado

    # O pairing() da py_ecc faz exponenciações internas; elas não podem
    # aparecer na contagem.
    assert registro["gerar_desafio"]["operacoes"] == {"exp_gt": 1}

    cliente_ops = registro["responder_desafio"]["operacoes"]
    assert cliente_ops.get("emparelhamento", 0) == 0
    assert cliente_ops["exp_gt"] == 1
    assert cliente_ops["mult_g1"] == 2
    assert cliente_ops["mult_g2"] == 3

    servidor_ops = registro["autenticar_cliente"]["operacoes"]
    assert servidor_ops["emparelhamento"] == 2
    assert servidor_ops["exp_gt"] == 1
    assert servidor_ops["mult_g1"] == 2
