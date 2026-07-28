from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class SolicitacaoServico:
    """
    Mensagem 1:

        Ui -> SPj: solicitação de serviço
    """

    identidade_servidor: str


@dataclass(frozen=True)
class DesafioServidor:
    """
    Mensagem 2:

        SPj -> Ui: Z
    """

    z: Any


@dataclass(frozen=True)
class RespostaCliente:
    """
    Mensagem 3:

        Ui -> SPj: (K2, C1)
    """

    k2: Any
    c1: bytes


@dataclass(frozen=True)
class ConfirmacaoServidor:
    """
    Mensagem 4:

        SPj -> Ui: Di
    """

    di: bytes


@dataclass(frozen=True)
class ResultadoAutenticacao:
    """
    Resultado da validação realizada pelo servidor.
    """

    autenticado: bool
    identidade_cliente: Optional[str] = None
    confirmacao: Optional[ConfirmacaoServidor] = None
    motivo: Optional[str] = None