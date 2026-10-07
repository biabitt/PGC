from typing import Any

from py_ecc.optimized_bn128 import multiply

from criptografia.serializacao import bytes_para_inteiro, inteiro_para_bytes
from criptografia.utilitarios import comparar_seguro

from protocolo_kaur.funcoes import h2, kdf
from protocolo_kaur.tipos import (
    ConfirmacaoUsuario,
    DadosPublicosUsuario,
    MensagemUsuario,
    ParametrosPublicos,
    RegistroServidor,
    RespostaServidor,
    ResultadoAutenticacao,
)

from shared.util import agora, dentro_da_tolerancia, mascara_de_ponto, xor_multiplo


class ServidorMEC:
    """
    Servidor MEC do protocolo de Kaur et al.
    """

    def __init__(
        self,
        identidade: str,
        tolerancia_tempo: int = 300,
    ) -> None:
        if not identidade.strip():
            raise ValueError(
                "A identidade do servidor não pode estar vazia."
            )

        self.identidade = identidade
        self._tolerancia_tempo = tolerancia_tempo

        self._parametros: ParametrosPublicos | None = None
        self._sid_ms: int | None = None
        self._d_ms: int | None = None
        self._r_ms: int | None = None
        self._r_ms_ponto: Any | None = None
        self._p_ms: Any | None = None

        self._usuarios: dict[int, DadosPublicosUsuario] = {}

        self._sessao: dict[str, Any] | None = None
        self._chave_sessao: bytes | None = None

    def receber_parametros(
        self,
        parametros: ParametrosPublicos,
    ) -> None:
        self._parametros = parametros

    def receber_registro(
        self,
        registro: RegistroServidor,
    ) -> None:
        if registro.identidade != self.identidade:
            raise ValueError(
                "O registro recebido pertence a outro servidor."
            )

        self._sid_ms = registro.sid_ms
        self._d_ms = registro.d_ms
        self._r_ms = registro.r_ms
        self._r_ms_ponto = registro.r_ms_ponto
        self._p_ms = registro.p_ms

    def registrar_usuario_publico(
        self,
        dados: DadosPublicosUsuario,
    ) -> None:
        """
        O servidor mantém, por SID_u, os valores públicos <R_u, P_u>.
        """
        self._usuarios[dados.sid_u] = dados

    def autenticar_usuario(
        self,
        mensagem: MensagemUsuario,
    ) -> ResultadoAutenticacao:
        """
        R_{1-ms}* = d_ms R_1
        SID_u     = TK_u XOR Enc(T_u) XOR Enc(R_{1-ms}*)
        R_{u-ms}  = d_ms R_u
        Auth_ms   = H2(SID_u || T_u || T_ms) XOR H2(SID_u || R_{u-ms})
        """
        self._validar_pronto()

        if not self._timestamp_valido(mensagem.timestamp):
            return ResultadoAutenticacao(
                autenticado=False,
                motivo="Marca de tempo do usuário fora da tolerância.",
            )

        r1_ms = multiply(mensagem.r1_ponto, self._d_ms)  # d_ms R_1

        bloco_sid = xor_multiplo(
            mensagem.tk_u,
            inteiro_para_bytes(mensagem.timestamp),
            mascara_de_ponto(r1_ms),
        )
        sid_u = bytes_para_inteiro(bloco_sid)

        dados_usuario = self._usuarios.get(sid_u)
        if dados_usuario is None:
            return ResultadoAutenticacao(
                autenticado=False,
                motivo="SID_u desconhecido pelo servidor.",
            )

        r_u_ms = multiply(dados_usuario.r_u_ponto, self._d_ms)  # d_ms R_u

        timestamp = agora()

        auth_ms = xor_multiplo(
            h2(sid_u, mensagem.timestamp, timestamp),
            h2(sid_u, r_u_ms),
        )

        self._sessao = {
            "sid_u": sid_u,
            "p_u": dados_usuario.p_u,
            "r1_ms": r1_ms,
            "r_u_ms": r_u_ms,
            "t_u": mensagem.timestamp,
            "t_ms": timestamp,
        }

        return ResultadoAutenticacao(
            autenticado=True,
            sid_u=sid_u,
            resposta=RespostaServidor(
                timestamp=timestamp,
                auth_ms=auth_ms,
            ),
        )

    def verificar_confirmacao(
        self,
        confirmacao: ConfirmacaoUsuario,
    ) -> bool:
        """
        R_{ms-u}* = r_ms P_u
        Auth_u    = H2(SID_u || SID_ms || T_u || T_ms) XOR H2(SID_u || R_{ms-u}*)
        SK        = KDF(SID_u || R_{1-ms} || R_{u-ms} || R_{ms-u} || T_u || T_ms)
        """
        if self._sessao is None:
            raise RuntimeError(
                "Nenhuma sessão pendente para confirmar."
            )

        sessao = self._sessao
        r_ms_u = multiply(sessao["p_u"], self._r_ms)  # r_ms P_u (r_ms estático)

        auth_u_esperado = xor_multiplo(
            h2(
                sessao["sid_u"],
                self._sid_ms,
                sessao["t_u"],
                sessao["t_ms"],
            ),
            h2(sessao["sid_u"], r_ms_u),
        )

        if not comparar_seguro(auth_u_esperado, confirmacao.auth_u):
            return False

        self._chave_sessao = kdf(
            sessao["sid_u"],
            sessao["r1_ms"],
            sessao["r_u_ms"],
            r_ms_u,
            sessao["t_u"],
            sessao["t_ms"],
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
                "O servidor ainda não recebeu os parâmetros públicos."
            )

        if self._d_ms is None:
            raise RuntimeError(
                "O servidor ainda não recebeu sua chave privada."
            )
