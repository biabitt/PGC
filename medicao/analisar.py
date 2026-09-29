"""
Análise dos resultados gravados por rodar.py.

Gera, na pasta de resultados:

    resumo_protocolo.csv     tempo do protocolo por papel (média, desvio...)
    resumo_etapas.csv        tempo de cada etapa (ms)
    resumo_processo.csv      tempo do processo inteiro (real, user, sys)
    resumo_operacoes.csv     operações criptográficas por papel
    operacoes_por_etapa.csv  as mesmas operações, etapa por etapa
    resumo_mensagens.csv     bytes de cada mensagem
    grafico_tempo_protocolo.png
    grafico_operacoes.png
    grafico_mensagens.png

Uso:
    python medicao/analisar.py
    python medicao/analisar.py --excel     (CSV com ';' e vírgula decimal)
"""

import argparse
import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parents[1]
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import matplotlib  # noqa: E402

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from medicao.config import (  # noqa: E402
    OPERACOES,
    PASTA_RESULTADOS,
    PREFIXOS_FORA_DO_PROTOCOLO,
)

# Tokens do sistema de cores (modo claro); ver referência de paleta.
SUPERFICIE = "#fcfcfb"
TINTA = "#0b0b0b"
TINTA_2 = "#52514e"
TINTA_MUDA = "#898781"
GRADE = "#e1e0d9"
EIXO = "#c3c2b7"
AZUL = "#2a78d6"     # série 1
LARANJA = "#eb6834"  # série 2
AQUA = "#1baf7a"     # série 3

NOME_CENARIO = {
    "normal": "Autenticação normal",
    "ataque": "Ataque de personificação",
}

NOME_PAPEL = {
    "cliente": "Cliente",
    "servidor": "Servidor",
    "atacante": "Atacante",
}


# ----------------------------------------------------------------------
# Utilitários
# ----------------------------------------------------------------------

def classificar_etapa(nome: str) -> str:
    for prefixo in PREFIXOS_FORA_DO_PROTOCOLO:
        if nome.startswith(prefixo):
            return prefixo
    return "protocolo"


def agregar(df, chaves, colunas):
    """Média, desvio-padrão amostral, mediana, mínimo e máximo por grupo."""

    g = df.groupby(chaves)[colunas].agg(
        ["count", "mean", "std", "median", "min", "max"]
    )
    g.columns = [f"{c}_{s}" for c, s in g.columns]

    g.insert(0, "n", g[f"{colunas[0]}_count"])
    g = g.drop(columns=[c for c in g.columns if c.endswith("_count")])

    return g.reset_index()


def numero(valor, casas=0) -> str:
    """Formata com vírgula decimal (padrão brasileiro)."""
    return f"{valor:,.{casas}f}".replace(",", "X").replace(".", ",").replace(
        "X", "."
    )


def estilo() -> None:
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["Segoe UI", "DejaVu Sans", "Arial"],
        "figure.facecolor": SUPERFICIE,
        "axes.facecolor": SUPERFICIE,
        "savefig.facecolor": SUPERFICIE,
        "text.color": TINTA,
        "axes.labelcolor": TINTA_2,
        "xtick.color": TINTA_2,
        "ytick.color": TINTA_MUDA,
        "axes.edgecolor": EIXO,
    })


def preparar_eixo(ax) -> None:
    for lado in ("top", "right", "left"):
        ax.spines[lado].set_visible(False)
    ax.spines["bottom"].set_color(EIXO)
    ax.yaxis.grid(True, color=GRADE, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", length=0)


def cabecalho(fig, titulo: str, subtitulo: str) -> None:
    fig.text(0.02, 0.97, titulo, ha="left", va="top",
             fontsize=13, fontweight="bold", color=TINTA)
    fig.text(0.02, 0.905, subtitulo, ha="left", va="top",
             fontsize=9, color=TINTA_2)


def salvar_figura(fig, caminho: Path) -> None:
    fig.savefig(caminho, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  {caminho.name}")


# ----------------------------------------------------------------------
# Tabelas
# ----------------------------------------------------------------------

def montar_tabelas(pasta: Path):
    etapas = pd.read_csv(pasta / "etapas.csv")
    execucoes = pd.read_csv(pasta / "execucoes.csv")
    mensagens = pd.read_csv(pasta / "mensagens.csv")

    etapas["grupo"] = etapas["etapa"].map(classificar_etapa)

    # --- tempo (somente repetições medidas) ---------------------------
    tempo = etapas[etapas["modo"] == "tempo"]

    por_execucao = (
        tempo.groupby(["cenario", "papel", "repeticao", "grupo"])[
            ["real_ns", "cpu_ns"]
        ]
        .sum()
        .reset_index()
    )
    por_execucao["real_ms"] = por_execucao["real_ns"] / 1e6
    por_execucao["cpu_ms"] = por_execucao["cpu_ns"] / 1e6

    protocolo = por_execucao[por_execucao["grupo"] == "protocolo"]
    resumo_protocolo = agregar(
        protocolo, ["cenario", "papel"], ["real_ms", "cpu_ms"]
    )

    tempo_etapas = tempo.assign(
        real_ms=tempo["real_ns"] / 1e6, cpu_ms=tempo["cpu_ns"] / 1e6
    )
    resumo_etapas = agregar(
        tempo_etapas[tempo_etapas["grupo"] != "espera"],
        ["cenario", "papel", "etapa"],
        ["real_ms", "cpu_ms"],
    )

    processo = execucoes[execucoes["modo"] == "tempo"]
    resumo_processo = agregar(
        processo,
        ["cenario", "papel"],
        ["real_processo_s", "cpu_user_s", "cpu_sys_s", "cpu_total_s"],
    )

    # --- operações (sessão com contagem) ------------------------------
    contagem = etapas[
        (etapas["modo"] == "contagem") & (etapas["grupo"] == "protocolo")
    ]
    operacoes_por_etapa = contagem[
        ["cenario", "papel", "etapa", *OPERACOES]
    ].reset_index(drop=True)
    resumo_operacoes = (
        contagem.groupby(["cenario", "papel"])[list(OPERACOES)]
        .sum()
        .reset_index()
    )

    # --- mensagens ----------------------------------------------------
    enviadas = mensagens[
        (mensagens["modo"] == "contagem")
        & (mensagens["sentido"] == "enviada")
    ]
    resumo_mensagens = (
        enviadas.rename(columns={"papel": "emissor"})[
            ["cenario", "mensagem", "emissor", "bytes"]
        ]
        .sort_values(["cenario", "mensagem"])
        .reset_index(drop=True)
    )

    return {
        "resumo_protocolo": resumo_protocolo,
        "resumo_etapas": resumo_etapas,
        "resumo_processo": resumo_processo,
        "resumo_operacoes": resumo_operacoes,
        "operacoes_por_etapa": operacoes_por_etapa,
        "resumo_mensagens": resumo_mensagens,
    }


def gravar_tabelas(tabelas, pasta: Path, excel: bool) -> None:
    for nome, df in tabelas.items():
        df = df.round(4)
        caminho = pasta / f"{nome}.csv"
        if excel:
            df.to_csv(caminho, index=False, sep=";", decimal=",",
                      encoding="utf-8-sig")
        else:
            df.to_csv(caminho, index=False, encoding="utf-8")
        print(f"  {caminho.name}")


# ----------------------------------------------------------------------
# Gráficos
# ----------------------------------------------------------------------

def grafico_tempo(resumo, pasta: Path) -> None:
    ordem = [
        ("normal", "cliente"), ("normal", "servidor"),
        ("ataque", "cliente"), ("ataque", "atacante"),
    ]
    linhas = []
    for cenario, papel in ordem:
        sel = resumo[
            (resumo["cenario"] == cenario) & (resumo["papel"] == papel)
        ]
        if not sel.empty:
            linhas.append((cenario, papel, sel.iloc[0]))

    if not linhas:
        return

    cor = {"normal": AZUL, "ataque": LARANJA}
    posicoes, x = [], 0.0
    anterior = None
    for cenario, _, _ in linhas:
        if anterior is not None and cenario != anterior:
            x += 0.6
        posicoes.append(x)
        x += 1.0
        anterior = cenario

    fig, ax = plt.subplots(figsize=(8, 4.6))
    preparar_eixo(ax)

    medias = [l[2]["real_ms_mean"] for l in linhas]
    desvios = [l[2]["real_ms_std"] for l in linhas]

    ax.bar(
        posicoes, medias, width=0.7,
        color=[cor[l[0]] for l in linhas],
        edgecolor=SUPERFICIE, linewidth=1.5, zorder=3,
    )
    ax.errorbar(
        posicoes, medias, yerr=[0 if pd.isna(d) else d for d in desvios],
        fmt="none", ecolor=TINTA_2, elinewidth=1, capsize=3, zorder=4,
    )

    topo = max(m + (0 if pd.isna(d) else d) for m, d in zip(medias, desvios))
    for xp, m, d in zip(posicoes, medias, desvios):
        d = 0 if pd.isna(d) else d
        ax.text(xp, m + d + topo * 0.02, f"{numero(m)} ms",
                ha="center", va="bottom", fontsize=9, color=TINTA)

    ax.set_xticks(posicoes)
    ax.set_xticklabels([NOME_PAPEL[l[1]] for l in linhas], fontsize=10)
    ax.set_ylabel("Tempo de execução (ms)")
    ax.set_ylim(0, topo * 1.4)

    n = int(linhas[0][2]["n"])
    cabecalho(
        fig,
        "Tempo de execução do protocolo por papel",
        f"Média de {n} execuções; barras de erro = ±1 desvio-padrão. "
        "Considera só o cálculo do protocolo (sem rede, sem serialização).",
    )
    ax.legend(
        handles=[Patch(facecolor=cor[c], label=NOME_CENARIO[c])
                 for c in dict.fromkeys(l[0] for l in linhas)],
        frameon=False, loc="upper left", fontsize=9,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.88))
    salvar_figura(fig, pasta / "grafico_tempo_protocolo.png")


def grafico_operacoes(resumo, pasta: Path) -> None:
    papeis = [
        ("normal", "cliente", "Cliente", AZUL),
        ("normal", "servidor", "Servidor", LARANJA),
        ("ataque", "atacante", "Atacante", AQUA),
    ]
    operacoes = [
        ("emparelhamento", "Emparelhamentos"),
        ("exp_gt", "Exponenciações em GT"),
        ("mult_g1", "Multiplicações em G1"),
        ("mult_g2", "Multiplicações em G2"),
    ]

    series = []
    for cenario, papel, nome, cor in papeis:
        sel = resumo[
            (resumo["cenario"] == cenario) & (resumo["papel"] == papel)
        ]
        if not sel.empty:
            series.append((nome, cor, sel.iloc[0]))

    if not series:
        return

    fig, ax = plt.subplots(figsize=(8, 4.6))
    preparar_eixo(ax)

    largura = 0.24
    deslocamento = (len(series) - 1) / 2

    maximo = 1
    for i, (nome, cor, linha) in enumerate(series):
        xs = [j + (i - deslocamento) * (largura + 0.02)
              for j in range(len(operacoes))]
        valores = [int(linha[op]) for op, _ in operacoes]
        maximo = max(maximo, *valores)
        ax.bar(xs, valores, width=largura, color=cor,
               edgecolor=SUPERFICIE, linewidth=1.5, zorder=3, label=nome)
        for xp, v in zip(xs, valores):
            ax.text(xp, v + maximo * 0.02, str(v), ha="center",
                    va="bottom", fontsize=9, color=TINTA)

    ax.set_xticks(range(len(operacoes)))
    ax.set_xticklabels([rotulo for _, rotulo in operacoes], fontsize=9)
    ax.set_ylabel("Número de operações")
    ax.set_ylim(0, maximo * 1.45)
    ax.yaxis.get_major_locator().set_params(integer=True)

    cabecalho(
        fig,
        "Operações criptográficas por papel",
        "Contagem exata em uma sessão completa do protocolo "
        "(mesma contagem em toda execução).",
    )
    ax.legend(frameon=False, loc="upper left", fontsize=9)
    fig.tight_layout(rect=(0, 0, 1, 0.88))
    salvar_figura(fig, pasta / "grafico_operacoes.png")


def grafico_mensagens(resumo, pasta: Path) -> None:
    normal = resumo[resumo["cenario"] == "normal"]
    if normal.empty:
        normal = resumo

    normal = normal.drop_duplicates("mensagem").sort_values("mensagem")
    if normal.empty:
        return

    rotulos = {
        1: "Msg 1\nUi → SPj\nsolicitação",
        2: "Msg 2\nSPj → Ui\nZ",
        3: "Msg 3\nUi → SPj\n(K2, C1)",
        4: "Msg 4\nSPj → Ui\nDi",
    }

    fig, ax = plt.subplots(figsize=(8, 4.6))
    preparar_eixo(ax)

    xs = list(range(len(normal)))
    valores = list(normal["bytes"])
    ax.bar(xs, valores, width=0.55, color=AZUL,
           edgecolor=SUPERFICIE, linewidth=1.5, zorder=3)

    for xp, v in zip(xs, valores):
        ax.text(xp, v + max(valores) * 0.02, f"{numero(v)} B",
                ha="center", va="bottom", fontsize=9, color=TINTA)

    ax.set_xticks(xs)
    ax.set_xticklabels([rotulos.get(int(m), f"Msg {int(m)}")
                        for m in normal["mensagem"]], fontsize=9)
    ax.set_ylabel("Tamanho (bytes)")
    ax.set_ylim(0, max(valores) * 1.15)

    cabecalho(
        fig,
        "Tamanho das mensagens do protocolo",
        f"Total trafegado em uma sessão: {numero(sum(valores))} bytes "
        "(dados úteis, sem cabeçalhos de TCP/IP).",
    )
    fig.tight_layout(rect=(0, 0, 1, 0.88))
    salvar_figura(fig, pasta / "grafico_mensagens.png")


# ----------------------------------------------------------------------
# Principal
# ----------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--pasta", type=Path, default=PASTA_RESULTADOS)
    parser.add_argument(
        "--excel", action="store_true",
        help="Grava os resumos com ';' e vírgula decimal (Excel pt-BR).",
    )
    args = parser.parse_args()

    for arquivo in ("etapas.csv", "execucoes.csv", "mensagens.csv"):
        if not (args.pasta / arquivo).exists():
            sys.exit(
                f"Não encontrei {args.pasta / arquivo}. "
                "Rode antes: python medicao/rodar.py"
            )

    tabelas = montar_tabelas(args.pasta)

    n = tabelas["resumo_protocolo"]["n"].min()
    if n < 10:
        print(f"ATENÇÃO: só {int(n)} repetições por grupo; "
              "use pelo menos 10 (o ideal são 30).\n")

    print("Tempo do protocolo por papel (ms):")
    resumo = tabelas["resumo_protocolo"]
    print(
        resumo[["cenario", "papel", "n", "real_ms_mean", "real_ms_std",
                "cpu_ms_mean", "cpu_ms_std"]]
        .round(1).to_string(index=False)
    )

    print("\nOperações por papel:")
    print(tabelas["resumo_operacoes"].to_string(index=False))

    print("\nArquivos gerados:")
    gravar_tabelas(tabelas, args.pasta, args.excel)

    estilo()
    grafico_tempo(tabelas["resumo_protocolo"], args.pasta)
    grafico_operacoes(tabelas["resumo_operacoes"], args.pasta)
    grafico_mensagens(tabelas["resumo_mensagens"], args.pasta)


if __name__ == "__main__":
    main()
