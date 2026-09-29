"""Utilitários comuns aos processos servidor, cliente e atacante."""

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

from medicao.config import PASTA_DADOS
from medicao.contadores import etapa


def ler_argumentos(descricao: str, servidor: bool = False):
    parser = argparse.ArgumentParser(description=descricao)

    parser.add_argument("--porta", type=int, required=True)
    parser.add_argument("--dados", type=Path, default=PASTA_DADOS)
    parser.add_argument(
        "--saida",
        type=Path,
        required=True,
        help="Arquivo JSON onde o processo grava suas métricas.",
    )
    parser.add_argument(
        "--contar",
        action="store_true",
        help="Ativa a contagem de operações criptográficas.",
    )

    if servidor:
        parser.add_argument(
            "--pronto",
            type=Path,
            help="Arquivo criado quando o processo já está escutando.",
        )

    return parser.parse_args()


def sha256_curto(dados) -> str | None:
    if dados is None:
        return None
    return hashlib.sha256(dados).hexdigest()[:16]


class Sessao:
    """Acumula as métricas de um processo e as grava ao final."""

    def __init__(self, papel: str) -> None:
        self.papel = papel
        self.etapas: dict = {}
        self.mensagens: list = []
        self._inicio = time.perf_counter_ns()

    def etapa(self, nome: str):
        return etapa(self.etapas, nome)

    def registrar_mensagem(
        self, numero: int, sentido: str, dados: bytes
    ) -> None:
        self.mensagens.append(
            {
                "mensagem": numero,
                "sentido": sentido,
                "bytes": len(dados),
            }
        )

    def finalizar(self, saida: Path, **extra) -> None:
        tempos = os.times()

        registro = {
            "papel": self.papel,
            # user e system do processo inteiro, incluindo a
            # inicialização do Python e os imports.
            "cpu_user_s": tempos.user,
            "cpu_sys_s": tempos.system,
            "real_interno_s": (
                time.perf_counter_ns() - self._inicio
            ) / 1e9,
            "etapas": self.etapas,
            "mensagens": self.mensagens,
        }
        registro.update(extra)

        saida.write_text(json.dumps(registro), encoding="utf-8")
