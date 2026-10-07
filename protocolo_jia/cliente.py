from typing import Any

from py_ecc.optimized_bn128 import (
    G1,
    G2,
    add,
    curve_order,
    multiply,
)

from criptografia.hashes import gerar_aleatorio
from criptografia.utilitarios import xor_bytes

from protocolo_jia.funcoes import codificar_identidade_pontos, h1, h2_mascara, h3, h4, h5
from protocolo_jia.tipos import (
    MensagemUsuario,
    ParametrosPublicos,
    RegistroUsuario,
    RespostaServidor,
)

from shared.util import agora, dentro_da_tolerancia


class Usuario:
    """
    Usuário móvel Ui do protocolo de Jia et al.
    """

    def __init__(
        self,
        identidade: str,
        tolerancia_tempo: int = 300,
    ) -> None:
        if not identidade.strip():
            raise ValueError(
                "A identidade do usuário não pode estar vazia."
            )

        self.identidade = identidade
        self._tolerancia_tempo = tolerancia_tempo

        self._parametros: ParametrosPublicos | None = None
        self._r_u: Any | None = None
        self._sid_u: int | None = None

        self._identidade_servidor: str | None = None
        self._x: int | None = None
        self._x_ponto: Any | None = None
        self._timestamp_envio: int | None = None
        self._chave_sessao: bytes | None = None

    def receber_parametros(
        self,
        parametros: ParametrosPublicos,
    ) -> None:
        self._parametros = parametros

    def receber_registro(
        self,
        registro: RegistroUsuario,
    ) -> None:
        if registro.identidade != self.identidade:
            raise ValueError(
                "O registro recebido pertence a outro usuário."
            )

        self._r_u = registro.r_u_ponto
        self._sid_u = registro.sid_u

    def criar_mensagem_autenticacao(
        self,
        identidade_servidor: str,
    ) -> MensagemUsuario:
        """
        g_x   = g^x
        X     = x P
        M     = x (P^pub + h1(IDms) P)
        N     = h2(g_x) XOR (IDu || R_u || X)
        sigma = SID_u + x * h3(IDu || R_u || X || T_u) mod q
        """
        self._validar_pronto()

        if not identidade_servidor.strip():
            raise ValueError(
                "A identidade do servidor não pode estar vazia."
            )

        self._identidade_servidor = identidade_servidor

        x = gerar_aleatorio()
        x_ponto = multiply(G1, x)

        g_x = self._parametros.emparelhamento_base ** x

        # M = x (P^pub + h1(IDms) P), com P^pub e P em G2.
        ponto_servidor_g2 = add(
            self._parametros.chave_publica_g2,
            multiply(G2, h1(identidade_servidor)),
        )
        m = multiply(ponto_servidor_g2, x)

        bloco = codificar_identidade_pontos(
            self.identidade,
            self._r_u,
            x_ponto,
        )
        mascara = h2_mascara(g_x, len(bloco))
        n = xor_bytes(bloco, mascara)

        timestamp = agora()

        sigma = (
            self._sid_u
            + x * h3(self.identidade, self._r_u, x_ponto, timestamp)
        ) % curve_order

        self._x = x
        self._x_ponto = x_ponto
        self._timestamp_envio = timestamp

        return MensagemUsuario(
            m=m,
            n=n,
            sigma=sigma,
            timestamp=timestamp,
        )

    def verificar_resposta(
        self,
        resposta: RespostaServidor,
    ) -> bool:
        """
        Verifica t e calcula a chave de sessão:

            K_{u-ms} = (SID_u + x t) Y
            SK       = h5(K || IDu || IDms || X || Y)
        """
        if self._x is None or self._x_ponto is None:
            raise RuntimeError(
                "O usuário ainda não enviou uma mensagem de autenticação."
            )

        if not self._timestamp_valido(resposta.timestamp):
            return False

        t_calculado = h4(
            self.identidade,
            self._identidade_servidor,
            self._x_ponto,
            resposta.y_ponto,
            resposta.timestamp,
        )

        if t_calculado != resposta.t:
            return False

        escalar = (
            self._sid_u
            + self._x * resposta.t
        ) % curve_order

        chave_bruta = multiply(resposta.y_ponto, escalar)

        self._chave_sessao = h5(
            chave_bruta,
            self.identidade,
            self._identidade_servidor,
            self._x_ponto,
            resposta.y_ponto,
        )

        return True

    @property
    def chave_sessao(self) -> bytes | None:
        return self._chave_sessao

    def _timestamp_valido(self, timestamp: int) -> bool:
        return dentro_da_tolerancia(timestamp, self._tolerancia_tempo)

    def _validar_pronto(self) -> None:
        if self._parametros is None:
            raise RuntimeError(
                "O usuário ainda não recebeu os parâmetros públicos."
            )

        if self._sid_u is None or self._r_u is None:
            raise RuntimeError(
                "O usuário ainda não recebeu sua credencial."
            )
