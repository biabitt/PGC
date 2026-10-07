from typing import Any

from py_ecc.optimized_bn128 import (
    G1,
    multiply,
)

from criptografia.hashes import gerar_aleatorio
from criptografia.serializacao import inteiro_para_bytes

from protocolo_kaur.funcoes import h2, kdf
from protocolo_kaur.tipos import (
    ConfirmacaoUsuario,
    DadosPublicosServidor,
    MensagemUsuario,
    ParametrosPublicos,
    RegistroUsuario,
    RespostaServidor,
)

from shared.util import agora, dentro_da_tolerancia, mascara_de_ponto, xor_multiplo


class Usuario:
    """
    Usuário/sensor Ui do protocolo de Kaur et al.
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
        self._sid_u: int | None = None
        self._d_u: int | None = None
        self._r_u: int | None = None

        self._servidor: DadosPublicosServidor | None = None

        self._r1: int | None = None
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

        self._sid_u = registro.sid_u
        self._d_u = registro.d_u
        self._r_u = registro.r_u

    def definir_servidor(
        self,
        dados_servidor: DadosPublicosServidor,
    ) -> None:
        """
        O sensor precisa conhecer os valores públicos do servidor (SID_ms e
        P_ms) para iniciar a sessão.
        """
        self._servidor = dados_servidor

    def criar_mensagem_autenticacao(self) -> MensagemUsuario:
        """
        R_1      = r_1 P
        R_{1-ms} = r_1 P_ms
        TK_u     = Enc(SID_u) XOR Enc(T_u) XOR Enc(R_{1-ms})
        """
        self._validar_pronto()

        r1 = gerar_aleatorio()
        r1_ponto = multiply(G1, r1)
        r1_ms = multiply(self._servidor.p_ms, r1)

        timestamp = agora()

        tk_u = xor_multiplo(
            inteiro_para_bytes(self._sid_u),
            inteiro_para_bytes(timestamp),
            mascara_de_ponto(r1_ms),
        )

        self._r1 = r1
        self._timestamp_envio = timestamp

        return MensagemUsuario(
            tk_u=tk_u,
            timestamp=timestamp,
            r1_ponto=r1_ponto,
        )

    def verificar_resposta(
        self,
        resposta: RespostaServidor,
    ) -> ConfirmacaoUsuario | None:
        """
        Verifica Auth_ms, calcula a chave de sessão e produz Auth_u.

        Retorna None se a autenticação do servidor falhar.
        """
        if self._r1 is None or self._timestamp_envio is None:
            raise RuntimeError(
                "O usuário ainda não enviou a primeira mensagem."
            )

        if not self._timestamp_valido(resposta.timestamp):
            return None

        r_u_ms = multiply(self._servidor.p_ms, self._r_u)  # r_u P_ms

        auth_ms_esperado = xor_multiplo(
            h2(self._sid_u, self._timestamp_envio, resposta.timestamp),
            h2(self._sid_u, r_u_ms),
        )

        if auth_ms_esperado != resposta.auth_ms:
            return None

        r_ms_u = multiply(self._servidor.r_ms_ponto, self._d_u)  # d_u R_ms

        auth_u = xor_multiplo(
            h2(
                self._sid_u,
                self._servidor.sid_ms,
                self._timestamp_envio,
                resposta.timestamp,
            ),
            h2(self._sid_u, r_ms_u),
        )

        r1_ms = multiply(self._servidor.p_ms, self._r1)  # r_1 P_ms

        self._chave_sessao = kdf(
            self._sid_u,
            r1_ms,
            r_u_ms,
            r_ms_u,
            self._timestamp_envio,
            resposta.timestamp,
        )

        return ConfirmacaoUsuario(auth_u=auth_u)

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

        if (
            self._sid_u is None
            or self._d_u is None
            or self._r_u is None
        ):
            raise RuntimeError(
                "O usuário ainda não recebeu suas credenciais."
            )

        if self._servidor is None:
            raise RuntimeError(
                "O usuário ainda não conhece os dados do servidor."
            )
