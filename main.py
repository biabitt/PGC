from cenarios import (
    ResultadoCenarioAtaque,
    ResultadoCenarioNormal,
    executar_cenario_ataque,
    executar_cenario_autenticacao_normal,
)


def exibir_secao(titulo: str) -> None:
    print()
    print("=" * 70)
    print(titulo)
    print("=" * 70)


def exibir_resultado_cenario_normal(
    resultado: ResultadoCenarioNormal,
) -> None:
    if not resultado.cliente_autenticado_pelo_servidor:
        print(
            "O servidor rejeitou o cliente."
        )
        print(
            "Motivo:",
            resultado.motivo_rejeicao,
        )
        return

    print(
        "Cliente autenticado pelo servidor:",
        resultado.cliente_autenticado_pelo_servidor,
    )

    print(
        "Servidor autenticado pelo cliente:",
        resultado.servidor_autenticado_pelo_cliente,
    )

    print(
        "Chaves de sessão iguais:",
        resultado.chaves_iguais,
    )

    if resultado.chave_sessao is not None:
        print(
            "Chave de sessão:",
            resultado.chave_sessao.hex(),
        )


def exibir_resultado_cenario_ataque(
    resultado: ResultadoCenarioAtaque,
) -> None:
    print(
        "Cliente aceitou o atacante:",
        resultado.atacante_aceito_como_servidor,
    )

    print(
        "Cliente e atacante calcularam a mesma chave:",
        resultado.chaves_iguais,
    )

    print(
        "Servidor legítimo participou:",
        resultado.servidor_legitimo_participou,
    )

    print(
        "Identidade recuperada pelo atacante:",
        resultado.identidade_recuperada,
    )

    if resultado.chave_obtida_pelo_atacante is not None:
        print(
            "Chave obtida pelo atacante:",
            resultado.chave_obtida_pelo_atacante.hex(),
        )


def main() -> None:
    """
    Ponto de entrada do projeto.
    """

    exibir_secao(
        "IMPLEMENTAÇÃO DO PROTOCOLO DE AUTENTICAÇÃO"
    )

    try:
        exibir_secao(
            "CENÁRIO 1 - AUTENTICAÇÃO NORMAL"
        )
        exibir_resultado_cenario_normal(
            executar_cenario_autenticacao_normal()
        )

        exibir_secao(
            "CENÁRIO 2 - ATAQUE DE PERSONIFICAÇÃO"
        )
        exibir_resultado_cenario_ataque(
            executar_cenario_ataque()
        )

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
