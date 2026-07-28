from typing import Any

from py_ecc.optimized_bn128 import (
    add,
    multiply,
    pairing,
)

from criptografia.hashes import (
    gerar_aleatorio,
    hash_para_inteiro,
    hash_chave_sessao,
    hash_autenticacao,
    hash_confirmacao,
)

from criptografia.utilitarios import (
    gerar_mascara,
    xor_bytes,
)

from protocolo.codificacao import (
    decodificar_dados_cliente,
)

from protocolo.mensagens import (
    ConfirmacaoServidor,
    DesafioServidor,
    RespostaCliente,
    ResultadoAutenticacao,
    SolicitacaoServico,
)

from protocolo.parametros import (
    ParametrosPublicos,
    RegistroServidor,
)


class Servidor:
    """
    Representa o provedor de serviço SPj.
    """

    def __init__(self, identidade: str) -> None:
        if not identidade.strip():
            raise ValueError(
                "A identidade do servidor não pode estar vazia."
            )

        self.identidade = identidade

        self._parametros: ParametrosPublicos | None = None
        self._chave_privada_g1: Any | None = None

        self._a: int | None = None
        self._z: Any | None = None
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

        self._chave_privada_g1 = (
            registro.chave_privada_g1
        )

    def gerar_desafio(
        self,
        solicitacao: SolicitacaoServico,
    ) -> DesafioServidor:
        """
        Calcula:

            Z = e(P2, P1)^a
        """

        self._validar_pronto()

        if solicitacao.identidade_servidor != self.identidade:
            raise ValueError(
                "A solicitação foi enviada ao servidor incorreto."
            )

        self._a = gerar_aleatorio()

        self._z = (
            self._parametros.emparelhamento_base
            ** self._a
        )

        return DesafioServidor(
            z=self._z,
        )

    def autenticar_cliente(
        self,
        resposta: RespostaCliente,
    ) -> ResultadoAutenticacao:
        """
        Executa os cálculos do servidor:

            Kij = H2(e(K2, Sj)^a)

            (IDi, si, w) = Kij XOR C1

            Qi = Ppub1 + H1(IDi)P1

            e(si, w + H3(...)Qi) == e(P2, P1)

            Di = H4(Kij || Z || IDi || IDj)
        """

        self._validar_sessao_iniciada()

        # --------------------------------------------------
        # Kij = H2(e(K2, Sj)^a)
        # --------------------------------------------------

        emparelhamento = pairing(
            resposta.k2,
            self._chave_privada_g1,
        )

        elemento_sessao = emparelhamento ** self._a

        chave_sessao = hash_chave_sessao(
            elemento_sessao
        )

        # --------------------------------------------------
        # Recuperação de IDi, si e w
        # --------------------------------------------------

        mascara = gerar_mascara(
            chave=chave_sessao,
            tamanho=len(resposta.c1),
        )

        dados_cliente = xor_bytes(
            resposta.c1,
            mascara,
        )

        try:
            identidade_cliente, si_g2, w_g1 = (
                decodificar_dados_cliente(
                    dados_cliente
                )
            )
        except (ValueError, TypeError) as erro:
            return ResultadoAutenticacao(
                autenticado=False,
                motivo=(
                    "Não foi possível recuperar os dados "
                    f"do cliente: {erro}"
                ),
            )

        # --------------------------------------------------
        # Qi = Ppub1 + H1(IDi)P1
        # --------------------------------------------------

        h1_cliente = hash_para_inteiro(
            identidade_cliente
        )

        qi = add(
            self._parametros.chave_publica_g1,
            multiply(
                self._parametros.gerador_g1,
                h1_cliente,
            ),
        )

        # --------------------------------------------------
        # H3(IDi || Z || IDj || w || Kij)
        # --------------------------------------------------

        h3 = hash_autenticacao(
            identidade_cliente,
            self._z,
            self.identidade,
            w_g1,
            chave_sessao,
        )

        # w + H3(...)Qi
        ponto_verificacao_g1 = add(
            w_g1,
            multiply(
                qi,
                h3,
            ),
        )

        # --------------------------------------------------
        # e(si, w + H3(...)Qi) == e(P2, P1)
        # --------------------------------------------------

        lado_esquerdo = pairing(
            si_g2,
            ponto_verificacao_g1,
        )

        lado_direito = (
            self._parametros.emparelhamento_base
        )

        if lado_esquerdo != lado_direito:
            return ResultadoAutenticacao(
                autenticado=False,
                identidade_cliente=identidade_cliente,
                motivo=(
                    "A equação de autenticação do cliente "
                    "não foi satisfeita."
                ),
            )

        # --------------------------------------------------
        # Di = H4(Kij || Z || IDi || IDj)
        # --------------------------------------------------

        di = hash_confirmacao(
            chave_sessao,
            self._z,
            identidade_cliente,
            self.identidade,
        )

        self._chave_sessao = chave_sessao

        return ResultadoAutenticacao(
            autenticado=True,
            identidade_cliente=identidade_cliente,
            confirmacao=ConfirmacaoServidor(
                di=di
            ),
        )

    @property
    def chave_sessao(self) -> bytes | None:
        return self._chave_sessao

    def _validar_pronto(self) -> None:
        if self._parametros is None:
            raise RuntimeError(
                "O servidor ainda não recebeu os parâmetros públicos."
            )

        if self._chave_privada_g1 is None:
            raise RuntimeError(
                "O servidor ainda não recebeu sua chave privada."
            )

    def _validar_sessao_iniciada(self) -> None:
        self._validar_pronto()

        if self._a is None or self._z is None:
            raise RuntimeError(
                "O servidor ainda não iniciou uma autenticação."
            )