from dataclasses import dataclass
from typing import Any, Callable

from puf.credential_protector import CredentialProtector
from puf.simulacao import PUFConfig


@dataclass(frozen=True)
class EspecCredencial:
    rotulo: str                          # ex.: KEY, SID, DU, RU
    atributo: str                        # atributo em claro no cliente
    origem: Callable[[Any], Any]         # registro -> valor
    serializar: Callable[[Any], bytes]
    desserializar: Callable[[bytes], Any]


class PUFClientMixin:
    PID: str = ""
    CREDENCIAIS: tuple[EspecCredencial, ...] = ()

    def _configurar_puf(self, identidade, seed_puf=2026, ruido_puf=0.01, config=None):
        config = config or PUFConfig(device_seed=seed_puf, ruido=ruido_puf)
        self._protector = CredentialProtector.criar(self.PID, identidade, config)

    def _registrar_credenciais(self, registro) -> None:
        if registro.identidade != self.identidade:
            raise ValueError("O registro recebido pertence a outra entidade.")
        self._protector.registrar({
            c.rotulo: c.serializar(c.origem(registro)) for c in self.CREDENCIAIS
        })
        self._limpar_credenciais()

    def preparar_autenticacao(self) -> None:
        recuperadas = self._protector.recuperar()
        for c in self.CREDENCIAIS:
            setattr(self, c.atributo, c.desserializar(recuperadas[c.rotulo]))

    def finalizar_sessao(self) -> None:
        self._limpar_credenciais()

    def _limpar_credenciais(self) -> None:
        for c in self.CREDENCIAIS:
            setattr(self, c.atributo, None)

    def _recuperar_se_necessario(self) -> None:
        if any(getattr(self, c.atributo) is None for c in self.CREDENCIAIS):
            self.preparar_autenticacao()
