from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ParametrosPublicos:
    gerador_g1: Any
    gerador_g2: Any
    chave_publica_g1: Any      # Ppub  = s  P  (G1)
    chave_publica_g2: Any      # P^pub = s^ P  (G2)
    emparelhamento_base: Any   # g = e(P, P)
    ordem_grupo: int


@dataclass(frozen=True)
class RegistroUsuario:
    identidade: str
    r_u_ponto: Any     # R_u = r_u P
    sid_u: int         # SID_u = (r_u + s h0(IDu || R_u)) mod q


@dataclass(frozen=True)
class RegistroServidor:
    identidade: str
    sid_ms: Any        # SID_ms = 1/(s^ + h1(IDms)) P


@dataclass(frozen=True)
class MensagemUsuario:
    """Ui -> SPj: <M, N, sigma, T_u>"""
    m: Any
    n: bytes
    sigma: int
    timestamp: int


@dataclass(frozen=True)
class RespostaServidor:
    """SPj -> Ui: <t, Y, T_ms>"""
    t: int
    y_ponto: Any
    timestamp: int


@dataclass(frozen=True)
class ResultadoAutenticacao:
    autenticado: bool
    identidade_usuario: Optional[str] = None
    resposta: Optional[RespostaServidor] = None
    motivo: Optional[str] = None
