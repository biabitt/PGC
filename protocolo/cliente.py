import hmac
from typing import Any

from py_ecc.optimized_bn128 import (
    add,
    curve_order,
    multiply,
)

from criptografia.hashes import (
    gerar_aleatorio,
    hash_para_inteiro,
    hash_chave_sessao,
    hash_autenticacao,
    hash_confirmacao,
    inverso_modular,
)

from criptografia.utilitarios import (
    gerar_mascara,
    xor_bytes,
)

from protocolo.codificacao import (
    codificar_dados_cliente,
)

from protocolo.mensagens import (
    ConfirmacaoServidor,
    DesafioServidor,
    RespostaCliente,
    SolicitacaoServico,
)

from protocolo.parametros import (
    ParametrosPublicos,
    RegistroCliente,
)


class Cliente:
    """
    Representa o usuário móvel Ui.
    """

    def __init__(
        self,
        identidade: str,
        senha: str,
        impressao_digital: str = "impressao-teste",
    ) -> None:
        if not identidade.strip():
            raise ValueError(
                "A identidade do cliente não pode estar vazia."
            )

        if not senha:
            raise ValueError(
                "A senha do cliente não pode estar vazia."
            )

        self.identidade = identidade
        self._senha = senha
        self._impressao_digital = impressao_digital

        self._parametros: ParametrosPublicos | None = None
        self._chave_privada_g2: Any | None = None

        self._identidade_servidor: str | None = None
        self._ultimo_z: Any | None = None
        self._chave_sessao: bytes | None = None

    def receber_parametros(
        self,
        parametros: ParametrosPublicos,
    ) -> None:
        self._parametros = parametros

    def receber_registro(
        self,
        registro: RegistroCliente,
    ) -> None:
        """
        Recebe a chave privada por um canal seguro.

        Em uma etapa posterior, esta chave poderá ser
        protegida com senha e biometria, conforme o artigo.
        """

        if registro.identidade != self.identidade:
            raise ValueError(
                "O registro recebido pertence a outro cliente."
            )

        self._chave_privada_g2 = (
            registro.chave_privada_g2
        )

    def criar_solicitacao(
        self,
        identidade_servidor: str,
    ) -> SolicitacaoServico:
        self._validar_pronto()

        if not identidade_servidor.strip():
            raise ValueError(
                "A identidade do servidor não pode estar vazia."
            )

        self._identidade_servidor = identidade_servidor

        return SolicitacaoServico(
            identidade_servidor=identidade_servidor,
        )

    def responder_desafio(
        self,
        desafio: DesafioServidor,
    ) -> RespostaCliente:
        """
        Executa os cálculos do cliente:

            Kij = H2(Z^b)

            K2 = bPpub2 + H1(IDj)bP2

            w = bPpub1 + H1(IDi)bP1

            si = 1 / (b + H3(...)) Si2

            C1 = Kij XOR (IDi || si || w)
        """

        self._validar_pronto()

        if self._identidade_servidor is None:
            raise RuntimeError(
                "O cliente ainda não criou uma solicitação."
            )

        b = gerar_aleatorio()
        z = desafio.z

        # --------------------------------------------------
        # Kij = H2(Z^b)
        # --------------------------------------------------

        elemento_sessao = z ** b
        chave_sessao = hash_chave_sessao(
            elemento_sessao
        )

        # --------------------------------------------------
        # K2 = bPpub2 + H1(IDj)bP2
        #    = b(Ppub2 + H1(IDj)P2)
        # --------------------------------------------------

        h1_servidor = hash_para_inteiro(
            self._identidade_servidor
        )

        parte_publica_g2 = add(
            self._parametros.chave_publica_g2,
            multiply(
                self._parametros.gerador_g2,
                h1_servidor,
            ),
        )

        k2 = multiply(
            parte_publica_g2,
            b,
        )

        # --------------------------------------------------
        # w = bPpub1 + H1(IDi)bP1
        #   = b(Ppub1 + H1(IDi)P1)
        # --------------------------------------------------

        h1_cliente = hash_para_inteiro(
            self.identidade
        )

        qi = add(
            self._parametros.chave_publica_g1,
            multiply(
                self._parametros.gerador_g1,
                h1_cliente,
            ),
        )

        w = multiply(
            qi,
            b,
        )

        # --------------------------------------------------
        # H3(IDi || Z || IDj || w || Kij)
        # --------------------------------------------------

        h3 = hash_autenticacao(
            self.identidade,
            z,
            self._identidade_servidor,
            w,
            chave_sessao,
        )

        denominador = (b + h3) % curve_order
        inverso = inverso_modular(denominador)

        # si = inverso * Si2
        si_temporario = multiply(
            self._chave_privada_g2,
            inverso,
        )

        # --------------------------------------------------
        # C1 = Kij XOR (IDi || si || w)
        # --------------------------------------------------

        dados_cliente = codificar_dados_cliente(
            identidade=self.identidade,
            si_g2=si_temporario,
            w_g1=w,
        )

        mascara = gerar_mascara(
            chave=chave_sessao,
            tamanho=len(dados_cliente),
        )

        c1 = xor_bytes(
            dados_cliente,
            mascara,
        )

        self._ultimo_z = z
        self._chave_sessao = chave_sessao

        return RespostaCliente(
            k2=k2,
            c1=c1,
        )

    def autenticar_servidor(
        self,
        confirmacao: ConfirmacaoServidor,
    ) -> bool:
        """
        Verifica:

            Di' = H4(Kij || Z || IDi || IDj)

            Di' == Di
        """

        if self._chave_sessao is None:
            raise RuntimeError(
                "O cliente ainda não possui uma chave de sessão."
            )

        if self._ultimo_z is None:
            raise RuntimeError(
                "O cliente não possui o último desafio Z."
            )

        if self._identidade_servidor is None:
            raise RuntimeError(
                "A identidade do servidor não foi definida."
            )

        di_calculado = hash_confirmacao(
            self._chave_sessao,
            self._ultimo_z,
            self.identidade,
            self._identidade_servidor,
        )

        return hmac.compare_digest(
            di_calculado,
            confirmacao.di,
        )

    @property
    def chave_sessao(self) -> bytes | None:
        return self._chave_sessao

    def _validar_pronto(self) -> None:
        if self._parametros is None:
            raise RuntimeError(
                "O cliente ainda não recebeu os parâmetros públicos."
            )

        if self._chave_privada_g2 is None:
            raise RuntimeError(
                "O cliente ainda não recebeu sua chave privada."
            )