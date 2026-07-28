from dataclasses import dataclass
from typing import Optional

from ataque.atacante import Atacante

from protocolo.cliente import Cliente
from protocolo.parametros import ParametrosPublicos
from protocolo.servidor import Servidor
from protocolo.sgc import SGC


@dataclass(frozen=True)
class ResultadoCenarioNormal:
    """
    Resultado estruturado do cenário de autenticação legítima,
    sem nenhuma dependência de apresentação (print).
    """

    cliente_autenticado_pelo_servidor: bool
    motivo_rejeicao: Optional[str] = None
    servidor_autenticado_pelo_cliente: Optional[bool] = None
    chaves_iguais: Optional[bool] = None
    chave_sessao: Optional[bytes] = None


@dataclass(frozen=True)
class ResultadoCenarioAtaque:
    """
    Resultado estruturado do cenário de ataque de personificação
    do provedor de serviço.
    """

    atacante_aceito_como_servidor: bool
    chaves_iguais: bool
    servidor_legitimo_participou: bool
    identidade_recuperada: Optional[str]
    chave_obtida_pelo_atacante: Optional[bytes]


def preparar_ambiente() -> tuple[
    ParametrosPublicos,
    Cliente,
    Servidor,
]:
    """
    Configura o sistema, cria as entidades e realiza os registros.
    """

    sgc = SGC()
    parametros = sgc.configurar_sistema()

    cliente = Cliente(
        identidade="cliente01",
        senha="senha123",
        impressao_digital="digital01",
    )

    servidor = Servidor(
        identidade="servidor01",
    )

    cliente.receber_parametros(parametros)
    servidor.receber_parametros(parametros)

    registro_cliente = sgc.registrar_cliente(
        cliente.identidade
    )

    registro_servidor = sgc.registrar_servidor(
        servidor.identidade
    )

    cliente.receber_registro(
        registro_cliente
    )

    servidor.receber_registro(
        registro_servidor
    )

    return parametros, cliente, servidor


def executar_cenario_autenticacao_normal() -> ResultadoCenarioNormal:
    """
    Executa o protocolo sem atacante.
    """

    _, cliente, servidor = preparar_ambiente()

    solicitacao = cliente.criar_solicitacao(
        servidor.identidade
    )

    desafio = servidor.gerar_desafio(
        solicitacao
    )

    resposta_cliente = cliente.responder_desafio(
        desafio
    )

    resultado = servidor.autenticar_cliente(
        resposta_cliente
    )

    if not resultado.autenticado:
        return ResultadoCenarioNormal(
            cliente_autenticado_pelo_servidor=False,
            motivo_rejeicao=resultado.motivo,
        )

    servidor_aceito = cliente.autenticar_servidor(
        resultado.confirmacao
    )

    chaves_iguais = (
        cliente.chave_sessao
        == servidor.chave_sessao
    )

    return ResultadoCenarioNormal(
        cliente_autenticado_pelo_servidor=True,
        servidor_autenticado_pelo_cliente=servidor_aceito,
        chaves_iguais=chaves_iguais,
        chave_sessao=(
            cliente.chave_sessao
            if chaves_iguais
            else None
        ),
    )


def executar_cenario_ataque() -> ResultadoCenarioAtaque:
    """
    Executa o ataque de personificação do servidor.
    """

    parametros, cliente, servidor = (
        preparar_ambiente()
    )

    atacante = Atacante(
        parametros=parametros
    )

    # O cliente acredita estar falando com o servidor legítimo.
    solicitacao = cliente.criar_solicitacao(
        servidor.identidade
    )

    # O atacante intercepta a solicitação e gera Z.
    desafio_falso = atacante.interceptar_solicitacao(
        solicitacao
    )

    # O cliente responde ao atacante.
    resposta_cliente = cliente.responder_desafio(
        desafio_falso
    )

    # O atacante recupera os dados e gera Di.
    confirmacao_falsa = atacante.interceptar_resposta(
        resposta_cliente
    )

    # O cliente verifica Di acreditando que veio do servidor.
    atacante_aceito = cliente.autenticar_servidor(
        confirmacao_falsa
    )

    chaves_iguais = (
        cliente.chave_sessao
        == atacante.chave_sessao
    )

    servidor_participou = (
        servidor.chave_sessao is not None
    )

    return ResultadoCenarioAtaque(
        atacante_aceito_como_servidor=atacante_aceito,
        chaves_iguais=chaves_iguais,
        servidor_legitimo_participou=servidor_participou,
        identidade_recuperada=atacante.identidade_cliente,
        chave_obtida_pelo_atacante=atacante.chave_sessao,
    )
