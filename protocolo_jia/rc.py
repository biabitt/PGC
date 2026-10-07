from py_ecc.optimized_bn128 import (
    G1,
    G2,
    add,
    curve_order,
    multiply,
    pairing,
)

from criptografia.hashes import (
    gerar_aleatorio,
    inverso_modular,
)

from protocolo_jia.funcoes import h0, h1
from protocolo_jia.tipos import (
    ParametrosPublicos,
    RegistroServidor,
    RegistroUsuario,
)


class CentroRegistro:
    """
    Centro de Registro (RC) do protocolo de Jia et al.

    Responsabilidades:
    - configurar o sistema e gerar as duas chaves mestras (s e s^);
    - publicar os parâmetros;
    - registrar usuários (credencial (R_u, SID_u));
    - registrar servidores (chave privada SID_ms).
    """

    def __init__(self) -> None:
        self._s: int | None = None       # chave mestra do usuário
        self._s_hat: int | None = None   # chave mestra do servidor
        self._parametros: ParametrosPublicos | None = None

        self._usuarios_registrados: set[str] = set()
        self._servidores_registrados: set[str] = set()

    def configurar_sistema(self) -> ParametrosPublicos:
        if self._parametros is not None:
            raise RuntimeError(
                "O sistema já foi configurado."
            )

        self._s = gerar_aleatorio()
        self._s_hat = gerar_aleatorio()

        chave_publica_g1 = multiply(G1, self._s)       # Ppub  = s  P
        chave_publica_g2 = multiply(G2, self._s_hat)   # P^pub = s^ P

        self._parametros = ParametrosPublicos(
            gerador_g1=G1,
            gerador_g2=G2,
            chave_publica_g1=chave_publica_g1,
            chave_publica_g2=chave_publica_g2,
            emparelhamento_base=pairing(G2, G1),
            ordem_grupo=curve_order,
        )

        return self._parametros

    def registrar_usuario(
        self,
        identidade: str,
    ) -> RegistroUsuario:
        """
        R_u   = r_u P
        SID_u = (r_u + s * h0(IDu || R_u)) mod q
        """
        self._validar_configuracao()
        self._validar_identidade(identidade)

        if identidade in self._usuarios_registrados:
            raise ValueError(
                f"O usuário '{identidade}' já está registrado."
            )

        r_u = gerar_aleatorio()
        r_u_ponto = multiply(G1, r_u)

        sid_u = (
            r_u
            + self._s * h0(identidade, r_u_ponto)
        ) % curve_order

        self._usuarios_registrados.add(identidade)

        return RegistroUsuario(
            identidade=identidade,
            r_u_ponto=r_u_ponto,
            sid_u=sid_u,
        )

    def registrar_servidor(
        self,
        identidade: str,
    ) -> RegistroServidor:
        """
        SID_ms = 1 / (s^ + h1(IDms)) P
        """
        self._validar_configuracao()
        self._validar_identidade(identidade)

        if identidade in self._servidores_registrados:
            raise ValueError(
                f"O servidor '{identidade}' já está registrado."
            )

        denominador = (
            self._s_hat
            + h1(identidade)
        ) % curve_order

        sid_ms = multiply(
            G1,
            inverso_modular(denominador),
        )

        self._servidores_registrados.add(identidade)

        return RegistroServidor(
            identidade=identidade,
            sid_ms=sid_ms,
        )

    @property
    def parametros_publicos(self) -> ParametrosPublicos:
        self._validar_configuracao()
        return self._parametros

    def _validar_configuracao(self) -> None:
        if (
            self._s is None
            or self._s_hat is None
            or self._parametros is None
        ):
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
