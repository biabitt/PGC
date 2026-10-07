from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ParametrosPublicos:
    gerador_g1: Any
    chave_publica_rc: Any   # P_RC = d_RC P
    ordem_grupo: int


@dataclass(frozen=True)
class RegistroUsuario:
    """Privados: SID_u, d_u, r_u. Públicos: R_u = r_u P, P_u = d_u P."""
    identidade: str
    sid_u: int
    d_u: int
    r_u: int
    r_u_ponto: Any
    p_u: Any


@dataclass(frozen=True)
class RegistroServidor:
    """Registro estático, análogo ao do usuário. Privados: d_ms, r_ms. Públicos: SID_ms, P_ms, R_ms."""
    identidade: str
    sid_ms: int
    d_ms: int
    r_ms: int
    r_ms_ponto: Any
    p_ms: Any


@dataclass(frozen=True)
class DadosPublicosUsuario:
    """O que o servidor guarda por usuário, indexado por SID_u."""
    sid_u: int
    r_u_ponto: Any
    p_u: Any


@dataclass(frozen=True)
class DadosPublicosServidor:
    """O que o sensor precisa conhecer do servidor."""
    sid_ms: int
    p_ms: Any
    r_ms_ponto: Any


@dataclass(frozen=True)
class MensagemUsuario:
    """Ui -> SPj: <TK_u, T_u, R_1>"""
    tk_u: bytes
    timestamp: int
    r1_ponto: Any


@dataclass(frozen=True)
class RespostaServidor:
    """SPj -> Ui: <T_ms, Auth_ms>  (R_ms é público estático; não viaja)"""
    timestamp: int
    auth_ms: bytes


@dataclass(frozen=True)
class ConfirmacaoUsuario:
    """Ui -> SPj: Auth_u"""
    auth_u: bytes


@dataclass(frozen=True)
class ResultadoAutenticacao:
    autenticado: bool
    sid_u: Optional[int] = None
    resposta: Optional[RespostaServidor] = None
    motivo: Optional[str] = None
