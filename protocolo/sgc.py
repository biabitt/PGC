from py_ecc.optimized_bn128 import (
    G1,
    G2,
    curve_order,
    multiply,
    pairing,
)

from criptografia.hashes import (
    gerar_aleatorio,
    hash_para_inteiro,
    inverso_modular,
)

from protocolo.parametros import (
    ParametrosPublicos,
    RegistroCliente,
    RegistroServidor,
)


class SGC:
    """
    Smart Card Generator.

    Responsabilidades:
    - configurar o sistema;
    - gerar a chave mestra s;
    - publicar os parâmetros;
    - registrar clientes;
    - registrar servidores;
    - emitir as respectivas chaves privadas.
    """

    def __init__(self) -> None:
        self._chave_mestra: int | None = None
        self._parametros: ParametrosPublicos | None = None

        self._clientes_registrados: set[str] = set()
        self._servidores_registrados: set[str] = set()

    def configurar_sistema(self) -> ParametrosPublicos:
        """
        Executa a configuração inicial.

        No artigo:

            Ppub = sP

        Na adaptação:

            Ppub1 = sP1
            Ppub2 = sP2
        """

        if self._parametros is not None:
            raise RuntimeError(
                "O sistema já foi configurado."
            )

        chave_mestra = gerar_aleatorio()

        chave_publica_g1 = multiply(
            G1,
            chave_mestra,
        )

        chave_publica_g2 = multiply(
            G2,
            chave_mestra,
        )

        emparelhamento_base = pairing(
            G2,
            G1,
        )

        self._chave_mestra = chave_mestra

        self._parametros = ParametrosPublicos(
            gerador_g1=G1,
            gerador_g2=G2,
            chave_publica_g1=chave_publica_g1,
            chave_publica_g2=chave_publica_g2,
            emparelhamento_base=emparelhamento_base,
            ordem_grupo=curve_order,
        )

        return self._parametros

    def registrar_cliente(
        self,
        identidade: str,
    ) -> RegistroCliente:
        """
        Calcula a chave privada do cliente em G2:

            Si2 = 1 / (s + H1(IDi)) P2

        Ela ficará em G2 porque será usada como primeiro
        argumento na verificação por emparelhamento.
        """

        self._validar_configuracao()
        self._validar_identidade(identidade)

        if identidade in self._clientes_registrados:
            raise ValueError(
                f"O cliente '{identidade}' já está registrado."
            )

        denominador = (
            self._chave_mestra
            + hash_para_inteiro(identidade)
        ) % curve_order

        inverso = inverso_modular(denominador)

        chave_privada_g2 = multiply(
            self._parametros.gerador_g2,
            inverso,
        )

        self._clientes_registrados.add(identidade)

        return RegistroCliente(
            identidade=identidade,
            chave_privada_g2=chave_privada_g2,
        )

    def registrar_servidor(
        self,
        identidade: str,
    ) -> RegistroServidor:
        """
        Calcula a chave privada do servidor em G1:

            Sj1 = 1 / (s + H1(IDj)) P1

        Ela ficará em G1 porque o servidor calculará:

            e(K2, Sj1)
        """

        self._validar_configuracao()
        self._validar_identidade(identidade)

        if identidade in self._servidores_registrados:
            raise ValueError(
                f"O servidor '{identidade}' já está registrado."
            )

        denominador = (
            self._chave_mestra
            + hash_para_inteiro(identidade)
        ) % curve_order

        inverso = inverso_modular(denominador)

        chave_privada_g1 = multiply(
            self._parametros.gerador_g1,
            inverso,
        )

        self._servidores_registrados.add(identidade)

        return RegistroServidor(
            identidade=identidade,
            chave_privada_g1=chave_privada_g1,
        )

    @property
    def parametros_publicos(self) -> ParametrosPublicos:
        self._validar_configuracao()
        return self._parametros

    def _validar_configuracao(self) -> None:
        if (
            self._chave_mestra is None
            or self._parametros is None
        ):
            raise RuntimeError(
                "O SGC ainda não configurou o sistema."
            )

    @staticmethod
    def _validar_identidade(identidade: str) -> None:
        if not isinstance(identidade, str):
            raise TypeError(
                "A identidade deve ser uma string."
            )

        if not identidade.strip():
            raise ValueError(
                "A identidade não pode estar vazia."
            )