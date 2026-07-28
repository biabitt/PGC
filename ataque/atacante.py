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
    SolicitacaoServico,
)

from protocolo.parametros import ParametrosPublicos


class Atacante:
    """
    Implementa o ataque de personificação do provedor de serviço.

    O atacante não conhece:
    - a chave mestra do SGC;
    - a chave privada do servidor;
    - a chave privada do cliente.

    Ele utiliza apenas:
    - os parâmetros públicos;
    - a identidade pública do servidor;
    - as mensagens interceptadas.
    """

    def __init__(self, parametros: ParametrosPublicos) -> None:
        self._parametros = parametros

        self._identidade_servidor: str | None = None
        self._a: int | None = None
        self._z: Any | None = None
        self._chave_sessao: bytes | None = None

        self._identidade_cliente: str | None = None
        self._si_interceptado: Any | None = None
        self._w_interceptado: Any | None = None

    def interceptar_solicitacao(
        self,
        solicitacao: SolicitacaoServico,
    ) -> DesafioServidor:
        """
        Intercepta a solicitação destinada ao servidor legítimo.

        O atacante calcula:

            Z = e(Ppub2 + H1(IDj)P2, P1)^a

        Na adaptação para py_ecc:
        - o primeiro argumento do pairing pertence a G2;
        - o segundo pertence a G1.
        """

        self._identidade_servidor = (
            solicitacao.identidade_servidor
        )

        self._a = gerar_aleatorio()

        h1_servidor = hash_para_inteiro(
            self._identidade_servidor
        )

        ponto_servidor_g2 = add(
            self._parametros.chave_publica_g2,
            multiply(
                self._parametros.gerador_g2,
                h1_servidor,
            ),
        )

        emparelhamento = pairing(
            ponto_servidor_g2,
            self._parametros.gerador_g1,
        )

        self._z = emparelhamento ** self._a

        return DesafioServidor(
            z=self._z,
        )

    def interceptar_resposta(
        self,
        resposta: RespostaCliente,
    ) -> ConfirmacaoServidor:
        """
        Intercepta (K2, C1) e calcula a mesma chave do cliente:

            Kij = H2(e(K2, P1)^a)

        Depois recupera os dados protegidos em C1 e gera Di.
        """

        if self._a is None or self._z is None:
            raise RuntimeError(
                "O atacante ainda não gerou o desafio Z."
            )

        if self._identidade_servidor is None:
            raise RuntimeError(
                "A identidade do servidor não foi interceptada."
            )

        emparelhamento = pairing(
            resposta.k2,
            self._parametros.gerador_g1,
        )

        elemento_sessao = emparelhamento ** self._a

        chave_sessao = hash_chave_sessao(
            elemento_sessao
        )

        mascara = gerar_mascara(
            chave=chave_sessao,
            tamanho=len(resposta.c1),
        )

        dados_cliente = xor_bytes(
            resposta.c1,
            mascara,
        )

        identidade_cliente, si, w = (
            decodificar_dados_cliente(
                dados_cliente
            )
        )

        di = hash_confirmacao(
            chave_sessao,
            self._z,
            identidade_cliente,
            self._identidade_servidor,
        )

        self._chave_sessao = chave_sessao
        self._identidade_cliente = identidade_cliente
        self._si_interceptado = si
        self._w_interceptado = w

        return ConfirmacaoServidor(
            di=di,
        )

    @property
    def chave_sessao(self) -> bytes | None:
        return self._chave_sessao

    @property
    def identidade_cliente(self) -> str | None:
        return self._identidade_cliente