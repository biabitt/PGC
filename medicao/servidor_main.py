"""
Processo do servidor legítimo (SPj).

Escuta em localhost, atende UMA sessão de autenticação e encerra, gravando
suas métricas em --saida. Normalmente é iniciado por rodar.py.
"""

import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parents[1]
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from multiprocessing.connection import Listener  # noqa: E402

from medicao import contadores  # noqa: E402
from medicao.codec import (  # noqa: E402
    carregar_parametros,
    carregar_registro_servidor,
    codificar_confirmacao,
    codificar_desafio,
    decodificar_resposta,
    decodificar_solicitacao,
)
from medicao.comum import Sessao, ler_argumentos, sha256_curto  # noqa: E402
from medicao.config import HOST, IDENTIDADE_SERVIDOR  # noqa: E402
from protocolo.servidor import Servidor  # noqa: E402


def main() -> None:
    args = ler_argumentos(
        "Processo do servidor legítimo (SPj).", servidor=True
    )

    if args.contar:
        contadores.instalar()

    sessao = Sessao("servidor")

    with sessao.etapa("inicializacao"):
        servidor = Servidor(IDENTIDADE_SERVIDOR)
        servidor.receber_parametros(carregar_parametros(args.dados))
        servidor.receber_registro(
            carregar_registro_servidor(args.dados)
        )

    autenticado = False

    with Listener((HOST, args.porta)) as escuta:
        if args.pronto:
            args.pronto.write_text("ok", encoding="utf-8")

        with sessao.etapa("espera_conexao"):
            conexao = escuta.accept()

        with conexao:
            # Mensagem 1: Ui -> SPj
            with sessao.etapa("espera_msg1"):
                dados = conexao.recv_bytes()
            sessao.registrar_mensagem(1, "recebida", dados)

            with sessao.etapa("codec_msg1"):
                solicitacao = decodificar_solicitacao(dados)

            with sessao.etapa("gerar_desafio"):
                desafio = servidor.gerar_desafio(solicitacao)

            # Mensagem 2: SPj -> Ui
            with sessao.etapa("codec_msg2"):
                dados = codificar_desafio(desafio)
            conexao.send_bytes(dados)
            sessao.registrar_mensagem(2, "enviada", dados)

            # Mensagem 3: Ui -> SPj
            with sessao.etapa("espera_msg3"):
                dados = conexao.recv_bytes()
            sessao.registrar_mensagem(3, "recebida", dados)

            with sessao.etapa("codec_msg3"):
                resposta = decodificar_resposta(dados)

            with sessao.etapa("autenticar_cliente"):
                resultado = servidor.autenticar_cliente(resposta)

            autenticado = resultado.autenticado

            # Mensagem 4: SPj -> Ui (só se o cliente foi aceito)
            if autenticado:
                with sessao.etapa("codec_msg4"):
                    dados = codificar_confirmacao(resultado.confirmacao)
                conexao.send_bytes(dados)
                sessao.registrar_mensagem(4, "enviada", dados)

    sessao.finalizar(
        args.saida,
        autenticado=autenticado,
        chave_sha256=sha256_curto(servidor.chave_sessao),
    )


if __name__ == "__main__":
    main()
