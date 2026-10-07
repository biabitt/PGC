from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ConfirmacaoServidorIrshad:
    """SPj -> Ui: <R3, Zi>.  Zi = H4(Mij || A || IDi || IDj); R3 = x Ppub + H1(IDi) x P."""
    zi: bytes
    r3: Any
