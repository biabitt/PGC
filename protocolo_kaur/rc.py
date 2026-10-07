from py_ecc.optimized_bn128 import (
    G1,
    curve_order,
    multiply,
)

from criptografia.hashes import gerar_aleatorio

from protocolo_kaur.funcoes import h1
from protocolo_kaur.tipos import (
    ParametrosPublicos,
    RegistroServidor,
    RegistroUsuario,
)


class CentroRegistro:
    """
    Centro de Registro (RC) do protocolo de Kaur et al.

    Mantém a chave privada d_RC e publica P_RC = d_RC P.
    """

    def __init__(self) -> None:
        self._d_rc: int | None = None
        self._parametros: ParametrosPublicos | None = None

        self._usuarios_registrados: set[str] = set()
        self._servidores_registrados: set[str] = set()

    def configurar_sistema(self) -> ParametrosPublicos:
        if self._parametros is not None:
            raise RuntimeError(
                "O sistema já foi configurado."
            )

        self._d_rc = gerar_aleatorio()

        self._parametros = ParametrosPublicos(
            gerador_g1=G1,
            chave_publica_rc=multiply(G1, self._d_rc),
            ordem_grupo=curve_order,
        )

        return self._parametros

    def registrar_usuario(
        self,
        identidade: str,
    ) -> RegistroUsuario:
        """
        R_u   = r_u P
        SID_u = (r_u + d_RC * H1(IDu || R_u)) mod q
        P_u   = d_u P
        """
        self._validar_configuracao()
        self._validar_identidade(identidade)

        if identidade in self._usuarios_registrados:
            raise ValueError(
                f"O usuário '{identidade}' já está registrado."
            )

        r_u = gerar_aleatorio()
        d_u = gerar_aleatorio()

        r_u_ponto = multiply(G1, r_u)

        sid_u = (
            r_u
            + self._d_rc * h1(identidade, r_u_ponto)
        ) % curve_order

        self._usuarios_registrados.add(identidade)

        return RegistroUsuario(
            identidade=identidade,
            sid_u=sid_u,
            d_u=d_u,
            r_u=r_u,
            r_u_ponto=r_u_ponto,
            p_u=multiply(G1, d_u),
        )

    def registrar_servidor(
        self,
        identidade: str,
    ) -> RegistroServidor:
        """
        R_ms   = r_ms P
        SID_ms = (r_ms + d_RC * H1(IDms || R_ms)) mod q
        P_ms   = d_ms P
        """
        self._validar_configuracao()
        self._validar_identidade(identidade)

        if identidade in self._servidores_registrados:
            raise ValueError(
                f"O servidor '{identidade}' já está registrado."
            )

        r_ms = gerar_aleatorio()
        d_ms = gerar_aleatorio()

        r_ms_ponto = multiply(G1, r_ms)

        sid_ms = (
            r_ms
            + self._d_rc * h1(identidade, r_ms_ponto)
        ) % curve_order

        self._servidores_registrados.add(identidade)

        return RegistroServidor(
            identidade=identidade,
            sid_ms=sid_ms,
            d_ms=d_ms,
            r_ms=r_ms,
            r_ms_ponto=r_ms_ponto,
            p_ms=multiply(G1, d_ms),
        )

    @property
    def parametros_publicos(self) -> ParametrosPublicos:
        self._validar_configuracao()
        return self._parametros

    def _validar_configuracao(self) -> None:
        if self._d_rc is None or self._parametros is None:
            raise RuntimeError(
                "O RC ainda não configurou o sistema."
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
