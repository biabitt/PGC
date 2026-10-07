import hashlib
import sys
import time
from functools import reduce

from criptografia.hashes import concatenar_para_hash, hash_autenticacao
from criptografia.serializacao import serializar_ponto_g1


# --- tempo -------------------------------------------------------------------

def agora() -> int:
    return int(time.time())


def dentro_da_tolerancia(timestamp: int, tolerancia: int) -> bool:
    return abs(agora() - int(timestamp)) <= tolerancia


# --- hashes rotulados --------------------------------------------------------

def hash_para_zq(rotulo: str, *valores) -> int:
    """H(rotulo || valores) -> Zq."""
    return hash_autenticacao(rotulo, *valores)


def hash_rotulado_32(rotulo: str, *valores) -> bytes:
    """H(rotulo || valores) -> 32 bytes."""
    return hashlib.sha256(concatenar_para_hash(rotulo, *valores)).digest()


# --- codificação -------------------------------------------------------------

def mascara_de_ponto(ponto) -> bytes:
    """Codificação de 32 bytes de um ponto, para uso como máscara XOR."""
    return hashlib.sha256(serializar_ponto_g1(ponto)).digest()


def xor_multiplo(*blocos: bytes) -> bytes:
    if not blocos:
        raise ValueError("É necessário pelo menos um bloco.")
    if any(len(b) != len(blocos[0]) for b in blocos):
        raise ValueError("Todos os blocos devem ter o mesmo tamanho.")
    return bytes(reduce(lambda a, b: a ^ b, coluna) for coluna in zip(*blocos))


# --- demos -------------------------------------------------------------------

def exibir_secao(titulo: str) -> None:
    print()
    print("=" * 70)
    print(titulo)
    print("=" * 70)


def flag_puf() -> bool:
    return "--puf" in sys.argv[1:]
