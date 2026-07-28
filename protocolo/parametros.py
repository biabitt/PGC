from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParametrosPublicos:
    """
    Parâmetros publicados pelo SGC durante a configuração.

    Como py_ecc utiliza emparelhamento assimétrico, são
    mantidas representações em G1 e G2.
    """

    gerador_g1: Any
    gerador_g2: Any

    chave_publica_g1: Any
    chave_publica_g2: Any

    emparelhamento_base: Any
    ordem_grupo: int


@dataclass(frozen=True)
class RegistroCliente:
    """
    Dados entregues pelo SGC ao cliente por um canal seguro.
    """

    identidade: str
    chave_privada_g2: Any


@dataclass(frozen=True)
class RegistroServidor:
    """
    Dados entregues pelo SGC ao servidor por um canal seguro.
    """

    identidade: str
    chave_privada_g1: Any