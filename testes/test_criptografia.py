from py_ecc.optimized_bn128 import (
    curve_order,
    normalize,
)

from criptografia.curva import (
    emparelhar,
    gerador_g1,
    gerador_g2,
    multiplicar_ponto,
)

from criptografia.hashes import (
    gerar_aleatorio,
    hash_para_inteiro,
    inverso_modular,
)

from criptografia.serializacao import (
    desserializar_ponto_g1,
    desserializar_ponto_g2,
    serializar_ponto_g1,
    serializar_ponto_g2,
    serializar_valor,
)


def test_serializar_valor_com_ponto_g1():
    ponto = multiplicar_ponto(
        gerador_g1(),
        5,
    )

    dados = serializar_valor(ponto)

    assert isinstance(dados, bytes)
    assert len(dados) == 64


def test_serializar_valor_com_ponto_g2():
    ponto = multiplicar_ponto(
        gerador_g2(),
        5,
    )

    dados = serializar_valor(ponto)

    assert isinstance(dados, bytes)
    assert len(dados) == 128


def test_gerar_aleatorio():
    valor = gerar_aleatorio()

    assert isinstance(valor, int)
    assert 1 <= valor < curve_order


def test_hash_para_inteiro():
    resultado_1 = hash_para_inteiro("cliente01")
    resultado_2 = hash_para_inteiro("cliente01")
    resultado_3 = hash_para_inteiro("cliente02")

    assert resultado_1 == resultado_2
    assert resultado_1 != resultado_3
    assert 0 <= resultado_1 < curve_order


def test_inverso_modular():
    valor = 15
    inverso = inverso_modular(valor)

    assert (valor * inverso) % curve_order == 1


def test_bilinearidade():
    """
    Verifica:

        e(aQ, bP) = e(Q, P)^(ab)
    """

    p = gerador_g1()
    q = gerador_g2()

    a = 3
    b = 5

    lado_esquerdo = emparelhar(
        multiplicar_ponto(q, a),
        multiplicar_ponto(p, b),
    )

    lado_direito = (
        emparelhar(q, p) ** (a * b)
    )

    assert lado_esquerdo == lado_direito


def test_serializacao_g1():
    ponto_original = gerador_g1()

    dados = serializar_ponto_g1(
        ponto_original
    )

    ponto_recuperado = desserializar_ponto_g1(
        dados
    )

    assert (
        normalize(ponto_recuperado)
        == normalize(ponto_original)
    )


def test_serializacao_g2():
    ponto_original = gerador_g2()

    dados = serializar_ponto_g2(
        ponto_original
    )

    ponto_recuperado = desserializar_ponto_g2(
        dados
    )

    assert (
        normalize(ponto_recuperado)
        == normalize(ponto_original)
    )