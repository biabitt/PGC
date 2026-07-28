import hashlib
import secrets

from py_ecc.bn128 import curve_order
from py_ecc.optimized_bn128.optimized_curve import curve_order

def gerar_aleatorio():
    """
    Gera um número aleatório dentro da ordem do grupo.
    No protocolo, é usado para valores como a, b e a chave mestra s.
    """
    return secrets.randbelow(curve_order - 1) + 1


def hash_para_inteiro(texto):
    """
    Simula a função H1 do artigo.
    Recebe uma identidade e transforma em um inteiro no grupo.
    """
    digest = hashlib.sha256(texto.encode()).digest()
    return int.from_bytes(digest, "big") % curve_order


def hash_chave_sessao(valor):
    """
    Simula a função H2 do artigo.
    Transforma o resultado do emparelhamento em uma chave de sessão.
    """
    return hashlib.sha256(str(valor).encode()).hexdigest()


def hash_confirmacao(kij, z, idi, idj):
    """
    Simula a função H4 do artigo.
    Calcula Di = H4(Kij || Z || IDi || IDj).
    """
    dados = kij + str(z) + idi + idj
    return hashlib.sha256(dados.encode()).hexdigest()


def inverso_modular(valor):
    """
    Calcula o inverso modular de um valor.
    Usado nas chaves privadas:
    Si = 1 / (s + H1(IDi)) P
    Sj = 1 / (s + H1(IDj)) P
    """
    return pow(valor, -1, curve_order)
