import argparse
import csv
import os
from dataclasses import dataclass, fields

from benchmark.base import ResultadoComponente, ResultadoPar, desvio, escrever_csv, media, ms, percentual, us

OPERACOES = ["puf", "gen", "rep", "mask", "protect", "recover"]


@dataclass(frozen=True)
class ResumoProtocolo:
    protocolo: str
    pares: int
    registro_orig_ms: float
    registro_puf_ms: float
    sessao_orig_ms: float
    sessao_puf_ms: float
    custo_puf_ms: float
    custo_puf_desvio_ms: float
    custo_pct: float


def ler_csv(caminho: str, tipo):
    tipos = {f.name: f.type for f in fields(tipo)}
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        return [tipo(**{k: (int(v) if tipos[k] is int else v) for k, v in linha.items()})
                for linha in csv.DictReader(arquivo)]


def resumir(nome: str, rodadas: list[ResultadoPar]) -> ResumoProtocolo:
    """Uma linha da tabela final a partir das rodadas de um protocolo."""
    def coluna(campo):
        return [getattr(rodada, campo) for rodada in rodadas]

    def media_ms(valores):
        return round(ms(media(valores)), 3)

    # custo da camada em cada rodada: diferença de preparo entre as versões
    custo_por_rodada = [preparo_puf - preparo_orig
                        for preparo_puf, preparo_orig in zip(coluna("preparo_puf_ns"), coluna("preparo_orig_ns"))]
    sessao_orig = media(coluna("sessao_orig_ns"))
    custo_puf = media(custo_por_rodada)

    return ResumoProtocolo(
        protocolo=nome,
        pares=len(rodadas),
        registro_orig_ms=media_ms(coluna("registro_orig_ns")),
        registro_puf_ms=media_ms(coluna("registro_puf_ns")),
        sessao_orig_ms=round(ms(sessao_orig), 3),
        sessao_puf_ms=media_ms(coluna("sessao_puf_ns")),
        custo_puf_ms=round(ms(custo_puf), 3),
        custo_puf_desvio_ms=round(ms(desvio(custo_por_rodada)), 3),
        custo_pct=round(percentual(sessao_orig, custo_puf), 3),
    )


def imprimir_tabela(resumos: list[ResumoProtocolo]) -> None:
    quantidades = sorted({resumo.pares for resumo in resumos})
    print("=" * 92)
    print(f"CUSTO DA CAMADA PUF - medias de medicao pareada (ms), n = {'/'.join(map(str, quantidades))} pares por protocolo")
    print("=" * 92)
    print(f"{'':<10}{'REGISTRO (1x)':^20}  {'POR SESSAO':^58}")
    print(f"{'protocolo':<10}{'orig':>9}{'puf':>11}  {'sessao orig':>13}{'sessao puf':>13}"
          f"{'custo PUF':>12}{'(desvio)':>10}{'custo %':>10}")
    print("-" * 92)
    for resumo in resumos:
        print(f"{resumo.protocolo:<10}{resumo.registro_orig_ms:>9.2f}{resumo.registro_puf_ms:>11.2f}  "
              f"{resumo.sessao_orig_ms:>13.2f}{resumo.sessao_puf_ms:>13.2f}{resumo.custo_puf_ms:>+12.2f}"
              f"{resumo.custo_puf_desvio_ms:>10.2f}{resumo.custo_pct:>+9.2f}%")
    print("-" * 92)


def imprimir_componentes(componentes: list[ResultadoComponente]) -> None:
    print()
    print("=" * 60)
    print("CUSTO DA CAMADA PUF POR OPERACAO (us)")
    print("=" * 60)
    print(f"{'operacao':<10}{'media':>12}{'desvio':>12}")
    for operacao in OPERACOES:
        tempos = [c.tempo_ns for c in componentes if c.operacao == operacao]
        print(f"{operacao:<10}{us(media(tempos)):>12.1f}{us(desvio(tempos)):>12.1f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Tabela final a partir do CSV bruto do benchmark.")
    parser.add_argument("--entrada", default=os.path.join("resultados", "benchmark.csv"))
    args = parser.parse_args()
    pasta = os.path.dirname(args.entrada) or "."

    por_protocolo: dict[str, list[ResultadoPar]] = {}
    for rodada in ler_csv(args.entrada, ResultadoPar):
        por_protocolo.setdefault(rodada.protocolo, []).append(rodada)
    if not por_protocolo:
        raise SystemExit(f"Nenhum par em {args.entrada}.")

    resumos = [resumir(nome, rodadas) for nome, rodadas in por_protocolo.items()]
    imprimir_tabela(resumos)
    saida = os.path.join(pasta, "resumo.csv")
    escrever_csv(saida, resumos)

    componentes = os.path.join(pasta, "componentes.csv")
    if os.path.exists(componentes):
        imprimir_componentes(ler_csv(componentes, ResultadoComponente))

    print(f"\nResumo salvo em: {os.path.abspath(saida)}")


if __name__ == "__main__":
    main()
