from criptografia.serializacao import (
    TAMANHO_G1,
    TAMANHO_G2,
    desserializar_ponto_g1,
    desserializar_ponto_g2,
    serializar_ponto_g1,
    serializar_ponto_g2,
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
