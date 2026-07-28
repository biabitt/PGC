import hashlib
import hmac


def xor_bytes(
    valor: bytes,
    mascara: bytes,
) -> bytes:
    if len(valor) != len(mascara):
        raise ValueError(
            "O valor e a máscara devem possuir "
            "o mesmo tamanho."
        )

    return bytes(
        byte_valor ^ byte_mascara
        for byte_valor, byte_mascara
        in zip(valor, mascara)
    )


def gerar_mascara(
    chave: bytes,
    tamanho: int,
) -> bytes:
    """
    Expande Kij para o tamanho necessário ao XOR.

    O artigo apresenta diretamente:

        C1 = Kij XOR dados

    Como Kij tem 32 bytes e os dados são maiores,
    usamos uma função de expansão baseada em SHA-256.
    """
    if tamanho < 0:
        raise ValueError(
            "O tamanho não pode ser negativo."
        )

    resultado = bytearray()
    contador = 0

    while len(resultado) < tamanho:
        bloco = hashlib.sha256(
            chave
            + contador.to_bytes(
                4,
                byteorder="big",
            )
        ).digest()

        resultado.extend(bloco)
        contador += 1

    return bytes(
        resultado[:tamanho]
    )


def comparar_seguro(
    valor_a: bytes,
    valor_b: bytes,
) -> bool:
    return hmac.compare_digest(
        valor_a,
        valor_b,
    )