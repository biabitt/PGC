import hashlib
import secrets
from typing import Any

from py_ecc.optimized_bn128 import curve_order

from criptografia.serializacao import (
    serializar_elemento_gt,
    serializar_valor,
)


def gerar_aleatorio() -> int:
    """
    Gera um escalar entre 1 e q - 1.

    Usado para:
    - chave mestra s;
    - valor a do servidor;
    - valor b do cliente.
    """
    return secrets.randbelow(curve_order - 1) + 1


def hash_para_inteiro(texto: str) -> int:
    """
    H1: {0,1}* -> Zq
    """
    digest = hashlib.sha256(
        texto.encode("utf-8")
    ).digest()

    return int.from_bytes(
        digest,
        byteorder="big",
    ) % curve_order


def hash_chave_sessao(elemento_gt) -> bytes:
    """
    H2: GT -> {0,1}^256
    """
    dados = serializar_elemento_gt(
        elemento_gt
    )

    return hashlib.sha256(dados).digest()


def hash_autenticacao(*valores: Any) -> int:
    """
    H3: produz um escalar em Zq.
    """
    dados = concatenar_para_hash(*valores)

    digest = hashlib.sha256(
        dados
    ).digest()

    return int.from_bytes(
        digest,
        byteorder="big",
    ) % curve_order


def hash_confirmacao(
    kij: bytes,
    z,
    identidade_cliente: str,
    identidade_servidor: str,
) -> bytes:
    """
    H4(Kij || Z || IDi || IDj)
    """
    dados = concatenar_para_hash(
        kij,
        z,
        identidade_cliente,
        identidade_servidor,
    )

    return hashlib.sha256(dados).digest()


def inverso_modular(valor: int) -> int:
    """
    Calcula valor^(-1) mod q.
    """
    valor %= curve_order

    if valor == 0:
        raise ValueError(
            "Zero não possui inverso modular."
        )

    return pow(
        valor,
        -1,
        curve_order,
    )


def concatenar_para_hash(*valores: Any) -> bytes:
    """
    Concatena campos com seus respectivos tamanhos.

    Evita ambiguidades como:
        ab || c
        a || bc
    """
    resultado = bytearray()

    for valor in valores:
        dados = serializar_valor(valor)

        resultado.extend(
            len(dados).to_bytes(
                4,
                byteorder="big",
            )
        )

        resultado.extend(dados)

    return bytes(resultado)