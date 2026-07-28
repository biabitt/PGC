from typing import Any

from py_ecc.optimized_bn128 import (
    FQ,
    FQ2,
    normalize,
)


TAMANHO_CAMPO = 32
TAMANHO_G1 = 64
TAMANHO_G2 = 128


def inteiro_para_bytes(valor: int) -> bytes:
    """
    Converte um inteiro em 32 bytes.
    """
    return int(valor).to_bytes(
        TAMANHO_CAMPO,
        byteorder="big",
    )


def bytes_para_inteiro(dados: bytes) -> int:
    """
    Converte bytes em inteiro.
    """
    return int.from_bytes(
        dados,
        byteorder="big",
    )


def serializar_ponto_g1(ponto) -> bytes:
    """
    Serializa um ponto de G1.

    Na optimized_bn128, o ponto costuma aparecer em forma
    projetiva (X, Y, Z). normalize() converte para (x, y).
    """
    x, y = normalize(ponto)

    return (
        inteiro_para_bytes(int(x))
        + inteiro_para_bytes(int(y))
    )


def desserializar_ponto_g1(dados: bytes):
    """
    Reconstrói um ponto de G1 a partir de 64 bytes.
    """
    if len(dados) != TAMANHO_G1:
        raise ValueError(
            "Um ponto de G1 deve possuir exatamente 64 bytes."
        )

    x = bytes_para_inteiro(dados[:32])
    y = bytes_para_inteiro(dados[32:64])

    return (
        FQ(x),
        FQ(y),
        FQ(1),
    )


def serializar_ponto_g2(ponto) -> bytes:
    """
    Serializa um ponto de G2.

    Cada coordenada de G2 possui dois componentes:
        x = (x0, x1)
        y = (y0, y1)
    """
    x, y = normalize(ponto)

    x0, x1 = x.coeffs
    y0, y1 = y.coeffs

    return b"".join(
        [
            inteiro_para_bytes(int(x0)),
            inteiro_para_bytes(int(x1)),
            inteiro_para_bytes(int(y0)),
            inteiro_para_bytes(int(y1)),
        ]
    )


def desserializar_ponto_g2(dados: bytes):
    """
    Reconstrói um ponto de G2 a partir de 128 bytes.
    """
    if len(dados) != TAMANHO_G2:
        raise ValueError(
            "Um ponto de G2 deve possuir exatamente 128 bytes."
        )

    x0 = bytes_para_inteiro(dados[0:32])
    x1 = bytes_para_inteiro(dados[32:64])
    y0 = bytes_para_inteiro(dados[64:96])
    y1 = bytes_para_inteiro(dados[96:128])

    return (
        FQ2([x0, x1]),
        FQ2([y0, y1]),
        FQ2.one(),
    )


def serializar_elemento_gt(elemento) -> bytes:
    """
    Serializa um elemento de GT de forma recursiva.

    Isso funciona bem para o resultado do emparelhamento,
    que costuma vir como uma estrutura com coeffs aninhados.
    """
    if isinstance(elemento, bytes):
        return elemento

    if isinstance(elemento, str):
        return elemento.encode("utf-8")

    if isinstance(elemento, int):
        return inteiro_para_bytes(elemento)

    if hasattr(elemento, "coeffs"):
        resultado = bytearray()
        for coeficiente in elemento.coeffs:
            resultado.extend(
                serializar_elemento_gt(coeficiente)
            )
        return bytes(resultado)

    if isinstance(elemento, (tuple, list)):
        resultado = bytearray()
        for item in elemento:
            resultado.extend(
                serializar_elemento_gt(item)
            )
        return bytes(resultado)

    return inteiro_para_bytes(int(elemento))


def serializar_valor(valor: Any) -> bytes:
    """
    Serializa os tipos utilizados pelo protocolo:
    - bytes;
    - texto;
    - inteiro;
    - ponto de G1;
    - ponto de G2;
    - elemento de GT.
    """
    if isinstance(valor, bytes):
        return valor

    if isinstance(valor, str):
        return valor.encode("utf-8")

    if isinstance(valor, int):
        return inteiro_para_bytes(valor)

    # Pontos da optimized_bn128 aparecem como tupla (X, Y, Z)
    if isinstance(valor, tuple) and len(valor) == 3:
        coordenada_x = valor[0]

        # G2: coordenada em FQ2
        if isinstance(coordenada_x, FQ2):
            return serializar_ponto_g2(valor)

        # G1: coordenada em FQ
        if isinstance(coordenada_x, FQ):
            return serializar_ponto_g1(valor)

        raise TypeError(
            "Ponto com formato desconhecido para serialização."
        )

    # Elementos de GT (FQ12 ou estrutura semelhante)
    if hasattr(valor, "coeffs"):
        return serializar_elemento_gt(valor)

    raise TypeError(
        f"Tipo não suportado para serialização: {type(valor).__name__}"
    )

def codificar_dados_cliente(
    identidade: str,
    si_g2,
    w_g1,
) -> bytes:
    """
    Codifica o bloco protegido usado em C1:

        IDi || si || w
    """
    if not isinstance(identidade, str):
        raise TypeError(
            "A identidade deve ser uma string."
        )

    identidade_bytes = identidade.encode("utf-8")

    if len(identidade_bytes) > 65535:
        raise ValueError(
            "A identidade é grande demais para o formato adotado."
        )

    si_bytes = serializar_ponto_g2(si_g2)
    w_bytes = serializar_ponto_g1(w_g1)

    tamanho_identidade = len(identidade_bytes).to_bytes(
        2,
        byteorder="big",
    )

    return (
        tamanho_identidade
        + identidade_bytes
        + si_bytes
        + w_bytes
    )


def decodificar_dados_cliente(dados: bytes):
    """
    Recupera:

        identidade, si_g2, w_g1
    """
    if not isinstance(dados, bytes):
        raise TypeError(
            "Os dados devem estar em bytes."
        )

    if len(dados) < 2:
        raise ValueError(
            "Dados do cliente incompletos."
        )

    tamanho_identidade = int.from_bytes(
        dados[:2],
        byteorder="big",
    )

    inicio_identidade = 2
    fim_identidade = inicio_identidade + tamanho_identidade

    inicio_si = fim_identidade
    fim_si = inicio_si + TAMANHO_G2

    inicio_w = fim_si
    fim_w = inicio_w + TAMANHO_G1

    if len(dados) != fim_w:
        raise ValueError(
            "O tamanho da mensagem serializada é inválido."
        )

    identidade_bytes = dados[inicio_identidade:fim_identidade]
    si_bytes = dados[inicio_si:fim_si]
    w_bytes = dados[inicio_w:fim_w]

    identidade = identidade_bytes.decode("utf-8")
    si_g2 = desserializar_ponto_g2(si_bytes)
    w_g1 = desserializar_ponto_g1(w_bytes)

    return identidade, si_g2, w_g1