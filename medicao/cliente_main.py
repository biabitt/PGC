"""
Processo do cliente (Ui).

Conecta em localhost, executa UMA sessão de autenticação e encerra,
gravando suas métricas em --saida. Serve tanto para o cenário normal
(servidor legítimo do outro lado) quanto para o ataque (atacante do outro
lado): o cliente não sabe a diferença, e o código é o mesmo.
"""

import sys
import time
from pathlib import Path

_RAIZ = Path(__file__).resolve().parents[1]
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from multiprocessing.connection import Client  # noqa: E402

from medicao import contadores  # noqa: E402
from medicao.codec import (  # noqa: E402
    carregar_parametros,
    carregar_registro_cliente,
    codificar_resposta,
    codificar_solicitacao,
    decodificar_confirmacao,
    decodificar_desafio,
)
from medicao.comum import Sessao, ler_argumentos, sha256_curto  # noqa: E402
from medicao.config import (  # noqa: E402
    HOST,
    IDENTIDADE_CLIENTE,
    IDENTIDADE_SERVIDOR,
    IMPRESSAO_DIGITAL,
    SENHA_CLIENTE,
)
from protocolo.cliente import Cliente  # noqa: E402


def conectar(porta: int, tentativas: int = 200):
    """Conecta ao servidor, tentando de novo se ele ainda não escuta."""

    for tentativa in range(tentativas):
        try:
            return Client((HOST, porta))
        except ConnectionRefusedError:
            if tentativa == tentativas - 1:
                raise
            time.sleep(0.025)


def main() -> None:
    args = ler_argumentos("Processo do cliente (Ui).")

    if args.contar:
        contadores.instalar()

    sessao = Sessao("cliente")

    with sessao.etapa("inicializacao"):
        cliente = Cliente(
            identidade=IDENTIDADE_CLIENTE,
            senha=SENHA_CLIENTE,
            impressao_digital=IMPRESSAO_DIGITAL,
        )
        cliente.receber_parametros(carregar_parametros(args.dados))
        cliente.receber_registro(carregar_registro_cliente(args.dados))

    autenticado = False

    with sessao.etapa("espera_conexao"):
        conexao = conectar(args.porta)

    with conexao:
        # Mensagem 1: Ui -> SPj
        with sessao.etapa("criar_solicitacao"):
            solicitacao = cliente.criar_solicitacao(IDENTIDADE_SERVIDOR)

        with sessao.etapa("codec_msg1"):
            dados = codificar_solicitacao(solicitacao)
        conexao.send_bytes(dados)
        sessao.registrar_mensagem(1, "enviada", dados)

        # Mensagem 2: SPj -> Ui
        with sessao.etapa("espera_msg2"):
            dados = conexao.recv_bytes()
        sessao.registrar_mensagem(2, "recebida", dados)

        with sessao.etapa("codec_msg2"):
            desafio = decodificar_desafio(dados)

        with sessao.etapa("responder_desafio"):
            resposta = cliente.responder_desafio(desafio)

        # Mensagem 3: Ui -> SPj
        with sessao.etapa("codec_msg3"):
            dados = codificar_resposta(resposta)
        conexao.send_bytes(dados)
        sessao.registrar_mensagem(3, "enviada", dados)

        # Mensagem 4: SPj -> Ui (ausente se o servidor rejeitou o cliente)
        try:
            with sessao.etapa("espera_msg4"):
                dados = conexao.recv_bytes()
        except EOFError:
            dados = None

        if dados is not None:
            sessao.registrar_mensagem(4, "recebida", dados)

            with sessao.etapa("codec_msg4"):
                confirmacao = decodificar_confirmacao(dados)

            with sessao.etapa("autenticar_servidor"):
                autenticado = cliente.autenticar_servidor(confirmacao)

    sessao.finalizar(
        args.saida,
        autenticado=autenticado,
        chave_sha256=sha256_curto(cliente.chave_sessao),
    )


if __name__ == "__main__":
    main()
