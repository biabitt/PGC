from criptografia.hashes import hash_chave_sessao
from criptografia.serializacao import (
    TAMANHO_G1,
    desserializar_ponto_g1,
    serializar_ponto_g1,
)
from criptografia.utilitarios import gerar_mascara

from shared.util import hash_para_zq, hash_rotulado_32


def h0(identidade, r_u_g1) -> int:
    return hash_para_zq("JIA-H0", identidade, r_u_g1)


def h1(identidade_servidor) -> int:
    return hash_para_zq("JIA-H1", identidade_servidor)


def h2_mascara(g_x, tamanho: int) -> bytes:
    return gerar_mascara(chave=hash_chave_sessao(g_x), tamanho=tamanho)


def h3(identidade, r_u_g1, x_g1, timestamp) -> int:
    return hash_para_zq("JIA-H3", identidade, r_u_g1, x_g1, timestamp)


def h4(identidade_usuario, identidade_servidor, x_g1, y_g1, timestamp) -> int:
    return hash_para_zq("JIA-H4", identidade_usuario, identidade_servidor, x_g1, y_g1, timestamp)


def h5(chave_bruta_g1, identidade_usuario, identidade_servidor, x_g1, y_g1) -> bytes:
    return hash_rotulado_32("JIA-H5", chave_bruta_g1, identidade_usuario, identidade_servidor, x_g1, y_g1)


def codificar_identidade_pontos(identidade: str, r_u_g1, x_g1) -> bytes:
    """len(IDu) || IDu || R_u || X (identidade com prefixo de 2 bytes)."""
    identidade_bytes = identidade.encode("utf-8")
    if len(identidade_bytes) > 65535:
        raise ValueError("A identidade é grande demais para o formato adotado.")
    return (len(identidade_bytes).to_bytes(2, "big") + identidade_bytes
            + serializar_ponto_g1(r_u_g1) + serializar_ponto_g1(x_g1))


def decodificar_identidade_pontos(dados: bytes):
    if not isinstance(dados, bytes) or len(dados) < 2:
        raise ValueError("Bloco codificado incompleto.")
    fim_id = 2 + int.from_bytes(dados[:2], "big")
    fim_ru = fim_id + TAMANHO_G1
    fim_x = fim_ru + TAMANHO_G1
    if len(dados) != fim_x:
        raise ValueError("O tamanho do bloco serializado é inválido.")
    return (dados[2:fim_id].decode("utf-8"),
            desserializar_ponto_g1(dados[fim_id:fim_ru]),
            desserializar_ponto_g1(dados[fim_ru:fim_x]))
