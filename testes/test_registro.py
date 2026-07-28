import pytest

from protocolo.sgc import SGC

from py_ecc.optimized_bn128 import (
    is_on_curve,
    b,
    b2,
)


def test_configuracao_sistema():
    sgc = SGC()

    parametros = sgc.configurar_sistema()

    assert parametros is not None
    assert parametros.gerador_g1 is not None
    assert parametros.gerador_g2 is not None
    assert parametros.chave_publica_g1 is not None
    assert parametros.chave_publica_g2 is not None
    assert parametros.emparelhamento_base is not None


def test_registro_cliente():
    sgc = SGC()
    sgc.configurar_sistema()

    registro = sgc.registrar_cliente(
        "cliente01"
    )

    assert registro.identidade == "cliente01"
    assert registro.chave_privada_g2 is not None
    assert is_on_curve(
        registro.chave_privada_g2,
        b2,
    )


def test_registro_servidor():
    sgc = SGC()
    sgc.configurar_sistema()

    registro = sgc.registrar_servidor(
        "servidor01"
    )

    assert registro.identidade == "servidor01"
    assert registro.chave_privada_g1 is not None
    assert is_on_curve(
        registro.chave_privada_g1,
        b,
    )


def test_cliente_nao_pode_ser_registrado_duas_vezes():
    sgc = SGC()
    sgc.configurar_sistema()

    sgc.registrar_cliente("cliente01")

    with pytest.raises(ValueError):
        sgc.registrar_cliente("cliente01")


def test_servidor_nao_pode_ser_registrado_duas_vezes():
    sgc = SGC()
    sgc.configurar_sistema()

    sgc.registrar_servidor("servidor01")

    with pytest.raises(ValueError):
        sgc.registrar_servidor("servidor01")


def test_registro_exige_configuracao():
    sgc = SGC()

    with pytest.raises(RuntimeError):
        sgc.registrar_cliente("cliente01")