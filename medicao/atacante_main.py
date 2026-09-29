"""
Processo do atacante (personificação do provedor de serviço).

Ocupa o lugar do servidor: escuta na porta para a qual o cliente aponta e
completa o protocolo usando somente os parâmetros públicos (não carrega
nenhuma chave privada). O servidor legítimo não é iniciado neste cenário.
"""

import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parents[1]
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from multiprocessing.connection import Listener  # noqa: E402

from ataque.atacante import Atacante  # noqa: E402
from medicao import contadores  # noqa: E402
from medicao.codec import (  # noqa: E402
    carregar_parametros,
    codificar_confirmacao,
    codificar_desafio,
    decodificar_resposta,
    decodificar_solicitacao,
)
from medicao.comum import Sessao, ler_argumentos, sha256_curto  # noqa: E402
from medicao.config import HOST  # noqa: E402


def main() -> None:
    args = ler_argumentos(
        "Processo do atacante (personificação do servidor).",
        servidor=True,
    )

    if args.contar:
        contadores.instalar()

    sessao = Sessao("atacante")

    with sessao.etapa("inicializacao"):
        # Somente informação pública.
        atacante = Atacante(parametros=carregar_parametros(args.dados))

    with Listener((HOST, args.porta)) as escuta:
        if args.pronto:
            args.pronto.write_text("ok", encoding="utf-8")

        with sessao.etapa("espera_conexao"):
            conexao = escuta.accept()

        with conexao:
            # Mensagem 1: Ui -> (atacante)
            with sessao.etapa("espera_msg1"):
                dados = conexao.recv_bytes()
            sessao.registrar_mensagem(1, "recebida", dados)

            with sessao.etapa("codec_msg1"):
                solicitacao = decodificar_solicitacao(dados)

            with sessao.etapa("interceptar_solicitacao"):
                desafio = atacante.interceptar_solicitacao(solicitacao)

            # Mensagem 2: (atacante) -> Ui
            with sessao.etapa("codec_msg2"):
                dados = codificar_desafio(desafio)
            conexao.send_bytes(dados)
            sessao.registrar_mensagem(2, "enviada", dados)

            # Mensagem 3: Ui -> (atacante)
            with sessao.etapa("espera_msg3"):
                dados = conexao.recv_bytes()
            sessao.registrar_mensagem(3, "recebida", dados)

            with sessao.etapa("codec_msg3"):
                resposta = decodificar_resposta(dados)

            with sessao.etapa("interceptar_resposta"):
                confirmacao = atacante.interceptar_resposta(resposta)

            # Mensagem 4: (atacante) -> Ui
            with sessao.etapa("codec_msg4"):
                dados = codificar_confirmacao(confirmacao)
            conexao.send_bytes(dados)
            sessao.registrar_mensagem(4, "enviada", dados)

    sessao.finalizar(
        args.saida,
        chave_sha256=sha256_curto(atacante.chave_sessao),
        identidade_recuperada=atacante.identidade_cliente,
    )


if __name__ == "__main__":
    main()
