"""
Orquestrador da medição.

Para cada cenário e repetição:
  1. sobe o servidor (ou o atacante) como um processo;
  2. espera ele começar a escutar;
  3. sobe o cliente como outro processo;
  4. espera os dois terminarem e recolhe as métricas.

Ordem: 1 execução com contagem de operações por cenário, depois as
execuções de aquecimento (descartadas na análise) e, por fim, as repetições
medidas, alternando os cenários a cada repetição para que uma eventual
deriva da máquina afete os dois igualmente.

Saída (pasta --saida, por padrão medicao/resultados):
    execucoes.csv   uma linha por processo por execução
    etapas.csv      uma linha por etapa (tempo + operações)
    mensagens.csv   bytes de cada mensagem
    ambiente.json   dados da máquina, para a seção de metodologia

Uso:
    python medicao/rodar.py --repeticoes 30
"""

import argparse
import csv
import json
import platform
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parents[1]
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from medicao.config import (  # noqa: E402
    HOST,
    OPERACOES,
    PASTA_DADOS,
    PASTA_RESULTADOS,
    RAIZ,
)
from medicao.provisionar import provisionar  # noqa: E402

CENARIOS = {
    # cenário: (módulo que ocupa o lado do servidor, papel dele)
    "normal": ("medicao.servidor_main", "servidor"),
    "ataque": ("medicao.atacante_main", "atacante"),
}

COLUNAS_EXECUCOES = [
    "modo", "cenario", "repeticao", "papel",
    "real_processo_s", "real_interno_s",
    "cpu_user_s", "cpu_sys_s", "cpu_total_s",
    "autenticado", "chave_sha256", "chaves_iguais",
]

COLUNAS_ETAPAS = [
    "modo", "cenario", "repeticao", "papel", "etapa",
    "real_ns", "cpu_ns", *OPERACOES,
]

COLUNAS_MENSAGENS = [
    "modo", "cenario", "repeticao", "papel", "mensagem", "sentido", "bytes",
]


# ----------------------------------------------------------------------
# Uma sessão (servidor/atacante + cliente)
# ----------------------------------------------------------------------

def porta_livre() -> int:
    with socket.socket() as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def comando(modulo, porta, dados, saida, contar, pronto=None):
    cmd = [
        sys.executable, "-m", modulo,
        "--porta", str(porta),
        "--dados", str(dados),
        "--saida", str(saida),
    ]
    if contar:
        cmd.append("--contar")
    if pronto is not None:
        cmd += ["--pronto", str(pronto)]
    return cmd


def aguardar(processos, timeout):
    """
    Espera todos os processos terminarem. Devolve
    {nome: (codigo_de_saida, segundos_desde_o_inicio)}, com o instante de
    término de cada um observado separadamente.
    """

    fim = {}
    limite = time.perf_counter() + timeout

    while len(fim) < len(processos):
        for nome, (proc, inicio) in processos.items():
            if nome not in fim and proc.poll() is not None:
                fim[nome] = (
                    proc.returncode,
                    time.perf_counter() - inicio,
                )

        if len(fim) == len(processos):
            break

        if time.perf_counter() > limite:
            for proc, _ in processos.values():
                if proc.poll() is None:
                    proc.kill()
            raise TimeoutError(
                f"Sessão excedeu {timeout}s (processos finalizados à força)."
            )

        time.sleep(0.002)

    return fim


def executar_sessao(cenario, modo, repeticao, dados, timeout):
    modulo_servidor, papel_servidor = CENARIOS[cenario]
    contar = modo == "contagem"
    porta = porta_livre()

    with tempfile.TemporaryDirectory(prefix="pgc_medicao_") as tmp:
        tmp = Path(tmp)
        pronto = tmp / "pronto"
        saida_srv = tmp / "servidor.json"
        saida_cli = tmp / "cliente.json"
        erro_srv = (tmp / "servidor.err").open("wb")
        erro_cli = (tmp / "cliente.err").open("wb")

        processos = {}

        try:
            # Servidor (ou atacante).
            inicio_srv = time.perf_counter()
            proc_srv = subprocess.Popen(
                comando(modulo_servidor, porta, dados, saida_srv,
                        contar, pronto),
                cwd=RAIZ,
                stdout=subprocess.DEVNULL,
                stderr=erro_srv,
            )
            processos[papel_servidor] = (proc_srv, inicio_srv)

            # Espera o servidor começar a escutar.
            limite = time.perf_counter() + timeout
            while not pronto.exists():
                if proc_srv.poll() is not None:
                    raise RuntimeError(
                        f"{papel_servidor} terminou antes de escutar:\n"
                        + (tmp / "servidor.err").read_text(errors="replace")
                    )
                if time.perf_counter() > limite:
                    proc_srv.kill()
                    raise TimeoutError("Servidor não começou a escutar.")
                time.sleep(0.002)

            # Cliente.
            inicio_cli = time.perf_counter()
            proc_cli = subprocess.Popen(
                comando("medicao.cliente_main", porta, dados, saida_cli,
                        contar),
                cwd=RAIZ,
                stdout=subprocess.DEVNULL,
                stderr=erro_cli,
            )
            processos["cliente"] = (proc_cli, inicio_cli)

            fim = aguardar(processos, timeout)
        finally:
            for proc, _ in processos.values():
                if proc.poll() is None:
                    proc.kill()
            erro_srv.close()
            erro_cli.close()

        for nome, (codigo, _) in fim.items():
            if codigo != 0:
                arquivo = "servidor.err" if nome != "cliente" else "cliente.err"
                raise RuntimeError(
                    f"Processo '{nome}' terminou com código {codigo}:\n"
                    + (tmp / arquivo).read_text(errors="replace")
                )

        metricas = {
            papel_servidor: json.loads(saida_srv.read_text(encoding="utf-8")),
            "cliente": json.loads(saida_cli.read_text(encoding="utf-8")),
        }

    return metricas, fim


def linhas_da_sessao(cenario, modo, repeticao, metricas, fim):
    execucoes, etapas, mensagens = [], [], []

    chaves = {m["chave_sha256"] for m in metricas.values()}
    chaves_iguais = len(chaves) == 1 and None not in chaves

    for papel, m in metricas.items():
        execucoes.append({
            "modo": modo,
            "cenario": cenario,
            "repeticao": repeticao,
            "papel": papel,
            "real_processo_s": fim[papel][1],
            "real_interno_s": m["real_interno_s"],
            "cpu_user_s": m["cpu_user_s"],
            "cpu_sys_s": m["cpu_sys_s"],
            "cpu_total_s": m["cpu_user_s"] + m["cpu_sys_s"],
            "autenticado": m.get("autenticado", ""),
            "chave_sha256": m["chave_sha256"],
            "chaves_iguais": chaves_iguais,
        })

        for nome, e in m["etapas"].items():
            linha = {
                "modo": modo, "cenario": cenario,
                "repeticao": repeticao, "papel": papel,
                "etapa": nome,
                "real_ns": e["real_ns"], "cpu_ns": e["cpu_ns"],
            }
            for op in OPERACOES:
                linha[op] = e["operacoes"].get(op, 0)
            etapas.append(linha)

        for msg in m["mensagens"]:
            mensagens.append({
                "modo": modo, "cenario": cenario,
                "repeticao": repeticao, "papel": papel, **msg,
            })

    return execucoes, etapas, mensagens, chaves_iguais, metricas


def conferir(cenario, metricas, chaves_iguais):
    """Confirma que a sessão fez o que o cenário deveria fazer."""

    problemas = []

    if not chaves_iguais:
        problemas.append("as chaves de sessão não coincidem")

    if not metricas["cliente"].get("autenticado"):
        problemas.append("o cliente não aceitou a confirmação Di")

    if cenario == "normal" and not metricas["servidor"].get("autenticado"):
        problemas.append("o servidor não aceitou o cliente")

    return problemas


# ----------------------------------------------------------------------
# Saída
# ----------------------------------------------------------------------

def gravar_csv(caminho, colunas, linhas):
    with caminho.open("w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=colunas)
        escritor.writeheader()
        escritor.writerows(linhas)


def descrever_ambiente(args):
    try:
        import py_ecc
        versao_py_ecc = getattr(py_ecc, "__version__", "desconhecida")
    except ImportError:
        versao_py_ecc = "não instalada"

    return {
        "data": datetime.now().isoformat(timespec="seconds"),
        "sistema": platform.platform(),
        "processador": platform.processor(),
        "nucleos_logicos": __import__("os").cpu_count(),
        "python": sys.version,
        "py_ecc": versao_py_ecc,
        "repeticoes": args.repeticoes,
        "aquecimento": args.aquecimento,
        "cenarios": args.cenarios,
        "observacao": (
            "Anote manualmente: modelo da CPU, memória RAM, "
            "plano de energia e se o computador estava na tomada."
        ),
    }


# ----------------------------------------------------------------------
# Principal
# ----------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repeticoes", type=int, default=30)
    parser.add_argument("--aquecimento", type=int, default=2,
                        help="Sessões descartadas antes das medidas.")
    parser.add_argument("--cenarios", nargs="+", choices=list(CENARIOS),
                        default=list(CENARIOS))
    parser.add_argument("--dados", type=Path, default=PASTA_DADOS)
    parser.add_argument("--saida", type=Path, default=PASTA_RESULTADOS)
    parser.add_argument("--timeout", type=float, default=180.0,
                        help="Limite por sessão, em segundos.")
    parser.add_argument("--reprovisionar", action="store_true",
                        help="Gera novas chaves mesmo que já existam.")
    args = parser.parse_args()

    if args.reprovisionar or not (args.dados / "parametros.json").exists():
        print("Provisionando o SGC...")
        provisionar(args.dados)

    args.saida.mkdir(parents=True, exist_ok=True)

    execucoes, etapas, mensagens = [], [], []
    avisos = []

    def rodar(cenario, modo, repeticao, rotulo):
        inicio = time.perf_counter()
        metricas, fim = executar_sessao(
            cenario, modo, repeticao, args.dados, args.timeout
        )
        exe, eta, msg, chaves_iguais, _ = linhas_da_sessao(
            cenario, modo, repeticao, metricas, fim
        )

        problemas = conferir(cenario, metricas, chaves_iguais)
        if problemas:
            avisos.append((cenario, modo, repeticao, problemas))

        print(
            f"{rotulo:<18} {cenario:<7} "
            f"{time.perf_counter() - inicio:5.2f}s  "
            + ("OK" if not problemas else "ATENÇÃO: " + "; ".join(problemas))
        )

        # Aquecimento entra no arquivo, mas marcado, para conferência.
        execucoes.extend(exe)
        etapas.extend(eta)
        mensagens.extend(msg)

    # 1. Contagem de operações (uma sessão por cenário).
    for cenario in args.cenarios:
        rodar(cenario, "contagem", 0, "contagem")

    # 2. Aquecimento.
    for i in range(1, args.aquecimento + 1):
        for cenario in args.cenarios:
            rodar(cenario, "aquecimento", i, f"aquecimento {i}")

    # 3. Repetições medidas, alternando os cenários.
    for i in range(1, args.repeticoes + 1):
        for cenario in args.cenarios:
            rodar(cenario, "tempo", i, f"repeticao {i}/{args.repeticoes}")

    gravar_csv(args.saida / "execucoes.csv", COLUNAS_EXECUCOES, execucoes)
    gravar_csv(args.saida / "etapas.csv", COLUNAS_ETAPAS, etapas)
    gravar_csv(args.saida / "mensagens.csv", COLUNAS_MENSAGENS, mensagens)
    (args.saida / "ambiente.json").write_text(
        json.dumps(descrever_ambiente(args), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print()
    print(f"Resultados gravados em {args.saida}")
    if avisos:
        print(f"ATENÇÃO: {len(avisos)} sessão(ões) com problemas:")
        for cenario, modo, repeticao, problemas in avisos:
            print(f"  {cenario}/{modo}/{repeticao}: {'; '.join(problemas)}")
    else:
        print("Todas as sessões passaram nas conferências.")


if __name__ == "__main__":
    main()
