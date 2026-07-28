from ataque.atacante import Atacante

from protocolo.cliente import Cliente
from protocolo.servidor import Servidor
from protocolo.sgc import SGC


def exibir_secao(titulo: str) -> None:
    print()
    print("=" * 70)
    print(titulo)
    print("=" * 70)


def preparar_ambiente():
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


def executar_autenticacao_normal() -> None:
    """
    Executa o protocolo sem atacante.
    """

    exibir_secao(
        "CENÁRIO 1 - AUTENTICAÇÃO NORMAL"
    )

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
        print(
            "O servidor rejeitou o cliente."
        )
        print(
            "Motivo:",
            resultado.motivo,
        )
        return

    servidor_aceito = cliente.autenticar_servidor(
        resultado.confirmacao
    )

    chaves_iguais = (
        cliente.chave_sessao
        == servidor.chave_sessao
    )

    print(
        "Cliente autenticado pelo servidor:",
        resultado.autenticado,
    )

    print(
        "Servidor autenticado pelo cliente:",
        servidor_aceito,
    )

    print(
        "Chaves de sessão iguais:",
        chaves_iguais,
    )

    if chaves_iguais:
        print(
            "Chave de sessão:",
            cliente.chave_sessao.hex(),
        )


def executar_ataque() -> None:
    """
    Executa o ataque de personificação do servidor.
    """

    exibir_secao(
        "CENÁRIO 2 - ATAQUE DE PERSONIFICAÇÃO"
    )

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

    print(
        "Cliente aceitou o atacante:",
        atacante_aceito,
    )

    print(
        "Cliente e atacante calcularam a mesma chave:",
        chaves_iguais,
    )

    print(
        "Servidor legítimo participou:",
        servidor_participou,
    )

    print(
        "Identidade recuperada pelo atacante:",
        atacante.identidade_cliente,
    )

    if atacante.chave_sessao is not None:
        print(
            "Chave obtida pelo atacante:",
            atacante.chave_sessao.hex(),
        )


def main() -> None:
    """
    Ponto de entrada do projeto.
    """

    exibir_secao(
        "IMPLEMENTAÇÃO DO PROTOCOLO DE AUTENTICAÇÃO"
    )

    try:
        executar_autenticacao_normal()
        executar_ataque()

    except ValueError as erro:
        print()
        print(
            "Erro de validação:",
            erro,
        )

    except RuntimeError as erro:
        print()
        print(
            "Erro de execução:",
            erro,
        )

    except Exception as erro:
        print()
        print(
            "Erro inesperado:",
            type(erro).__name__,
            "-",
            erro,
        )


if __name__ == "__main__":
    main()