from py_ecc.optimized_bn128 import (
    G1,
    G2,
    Z1,
    Z2,
    add,
    multiply,
    neg,
    normalize,
    pairing,
    curve_order,
)


def gerador_g1():
    return G1


def gerador_g2():
    return G2


def ponto_neutro_g1():
    return Z1


def ponto_neutro_g2():
    return Z2


def multiplicar_ponto(ponto, escalar: int):
    return multiply(
        ponto,
        escalar % curve_order,
    )


def somar_pontos(ponto_a, ponto_b):
    return add(ponto_a, ponto_b)


def negar_ponto(ponto):
    return neg(ponto)


def normalizar_ponto(ponto):
    return normalize(ponto)


def emparelhar(ponto_g2, ponto_g1):
    """
    Calcula e(Q, P), em que:

    Q pertence a G2
    P pertence a G1
    """
    return pairing(
        ponto_g2,
        ponto_g1,
    )


def emparelhamento_base():
    return pairing(G2, G1)