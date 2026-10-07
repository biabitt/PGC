from typing import Any

from py_ecc.optimized_bn128 import (
    G1,
    add,
    curve_order,
    multiply,
    normalize,
    pairing,
)

from criptografia.hashes import gerar_aleatorio
from criptografia.utilitarios import xor_bytes

from protocolo_jia.funcoes import decodificar_identidade_pontos, h0, h2_mascara, h3, h4, h5
from protocolo_jia.tipos import (
    MensagemUsuario,
    ParametrosPublicos,
    RegistroServidor,
    RespostaServidor,
    ResultadoAutenticacao,
)

from shared.util import agora, dentro_da_tolerancia


class ServidorMEC:
    """
    Servidor MEC SPj do protocolo de Jia et al.
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
        self._sid_ms: Any | None = None
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

    def autenticar_usuario(
        self,
        mensagem: MensagemUsuario,
    ) -> ResultadoAutenticacao:
        """
        g_x        = e(M, SID_ms)
        (IDu,R_u,X) = N XOR h2(g_x)
        W          = R_u + h0(IDu || R_u) Ppub
        aceita se  sigma P = W + h3(IDu || R_u || X || T_u) X
        t          = h4(IDu || IDms || X || Y || T_ms)
        K_{ms-u}   = y (t X + W)
        SK         = h5(K || IDu || IDms || X || Y)
        """
        self._validar_pronto()

        if not self._timestamp_valido(mensagem.timestamp):
            return ResultadoAutenticacao(
                autenticado=False,
                motivo="Marca de tempo do usuário fora da tolerância.",
            )

        # g_x = e(M, SID_ms), com M em G2 e SID_ms em G1.
        g_x = pairing(mensagem.m, self._sid_ms)

        mascara = h2_mascara(g_x, len(mensagem.n))
        bloco = xor_bytes(mensagem.n, mascara)

        try:
            identidade_usuario, r_u, x_ponto = (
                decodificar_identidade_pontos(bloco)
            )
        except (ValueError, TypeError) as erro:
            return ResultadoAutenticacao(
                autenticado=False,
                motivo=f"Falha ao recuperar o bloco do usuário: {erro}",
            )

        # W = R_u + h0(IDu || R_u) Ppub  (equivale a SID_u * P)
        w = add(
            r_u,
            multiply(
                self._parametros.chave_publica_g1,
                h0(identidade_usuario, r_u),
            ),
        )

        # Verificação: sigma P == W + h3 X
        h3_valor = h3(
            identidade_usuario,
            r_u,
            x_ponto,
            mensagem.timestamp,
        )

        lado_esquerdo = multiply(G1, mensagem.sigma)
        lado_direito = add(w, multiply(x_ponto, h3_valor))

        if normalize(lado_esquerdo) != normalize(lado_direito):
            return ResultadoAutenticacao(
                autenticado=False,
                identidade_usuario=identidade_usuario,
                motivo="A equação de verificação do usuário falhou.",
            )

        # Resposta do servidor e chave de sessão.
        y = gerar_aleatorio()
        y_ponto = multiply(G1, y)
        timestamp = agora()

        t_valor = h4(
            identidade_usuario,
            self.identidade,
            x_ponto,
            y_ponto,
            timestamp,
        )

        chave_bruta = multiply(
            add(multiply(x_ponto, t_valor), w),
            y,
        )

        self._chave_sessao = h5(
            chave_bruta,
            identidade_usuario,
            self.identidade,
            x_ponto,
            y_ponto,
        )

        return ResultadoAutenticacao(
            autenticado=True,
            identidade_usuario=identidade_usuario,
            resposta=RespostaServidor(
                t=t_valor,
                y_ponto=y_ponto,
                timestamp=timestamp,
            ),
        )

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

        if self._sid_ms is None:
            raise RuntimeError(
                "O servidor ainda não recebeu sua chave privada."
            )
