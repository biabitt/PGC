import argparse
import csv
import os
from dataclasses import dataclass, fields

from benchmark.base import ResultadoComponente, ResultadoPar, desvio, escrever_csv, media, ms, percentual, us

OPERACOES = ["puf", "gen", "rep", "mask", "protect", "recover"]


@dataclass(frozen=True)
class ResumoProtocolo:
    """Tabela antiga: para CSVs gerados antes da separação cliente/servidor."""
    protocolo: str
    pares: int
    registro_orig_ms: float
    registro_puf_ms: float
    sessao_orig_ms: float
    sessao_puf_ms: float
    custo_puf_ms: float
    custo_puf_desvio_ms: float
    custo_pct: float


@dataclass(frozen=True)
class ResumoSeparado:
    """Uma linha por protocolo com os tempos de cada lado (ms, médias de `pares` rodadas)."""
    protocolo: str
    pares: int
    # Tabela A: registro (só cliente, uma vez)
    registro_original_ms: float
    registro_puf_ms: float
    registro_delta_ms: float                 # média de (registro_puf - registro_orig) por rodada
    # Tabela B: processamento por participante
    preparo_original_ms: float
    preparo_puf_ms: float
    auth_cliente_original_ms: float          # soma das chamadas do cliente na troca
    auth_cliente_puf_ms: float
    auth_servidor_original_ms: float         # soma das chamadas do servidor na troca
    auth_servidor_puf_ms: float
    cliente_original_ms: float               # preparo + auth cliente
    cliente_puf_ms: float
    servidor_original_ms: float              # = auth servidor
    servidor_puf_ms: float
    sessao_original_ms: float                # preparo + auth total (mesma definição da tabela antiga)
    sessao_puf_ms: float
    overhead_runner_ms: float                # média de (auth total - auth cliente - auth servidor)
    # Tabela C: impacto da camada
    custo_puf_ms: float                      # média de (preparo_puf - preparo_orig): métrica legada
    custo_puf_desvio_ms: float               # pstdev dessas diferenças
    custo_preparo_sobre_cliente_pct: float   # custo_puf / cliente_original
    custo_preparo_sobre_sessao_pct: float    # custo_puf / sessao_original (percentual legado)
    delta_cliente_ms: float                  # média de (cliente_puf - cliente_orig) por rodada
    delta_cliente_pct: float                 # delta_cliente / cliente_original
    # Investigação: diferença pareada (puf - orig) em cada lado da troca
    dif_auth_cliente_ms: float
    dif_auth_cliente_desvio_ms: float
    auth_cliente_puf_mais_rapido: int        # rodadas em que auth_cliente_puf < auth_cliente_orig
    dif_auth_servidor_ms: float
    dif_auth_servidor_desvio_ms: float
    auth_servidor_puf_mais_rapido: int


def ler_csv(caminho: str, tipo):
    tipos = {f.name: f.type for f in fields(tipo)}
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        return [tipo(**{k: (int(v) if tipos[k] is int else v) for k, v in linha.items() if k in tipos})
                for linha in csv.DictReader(arquivo)]


def tem_separacao(rodadas: list[ResultadoPar]) -> bool:
    return any(r.auth_cliente_orig_ns or r.auth_servidor_orig_ns for r in rodadas)


def resumir(nome: str, rodadas: list[ResultadoPar]) -> ResumoProtocolo:
    """Uma linha da tabela antiga a partir das rodadas de um protocolo."""
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


def resumir_separado(nome: str, rodadas: list[ResultadoPar]) -> ResumoSeparado:
    """Uma linha das Tabelas A/B/C a partir das rodadas de um protocolo. Contas em ns; ms só no fim."""
    def coluna(campo):
        return [getattr(rodada, campo) for rodada in rodadas]

    def r3(ns):
        return round(ms(ns), 3)

    registro_orig, registro_puf = coluna("registro_orig_ns"), coluna("registro_puf_ns")
    preparo_orig, preparo_puf = coluna("preparo_orig_ns"), coluna("preparo_puf_ns")
    auth_orig, auth_puf = coluna("auth_orig_ns"), coluna("auth_puf_ns")
    cli_orig, cli_puf = coluna("auth_cliente_orig_ns"), coluna("auth_cliente_puf_ns")
    srv_orig, srv_puf = coluna("auth_servidor_orig_ns"), coluna("auth_servidor_puf_ns")

    custo_por_rodada = [p - o for p, o in zip(preparo_puf, preparo_orig)]
    cliente_orig_por_rodada = [p + a for p, a in zip(preparo_orig, cli_orig)]
    cliente_puf_por_rodada = [p + a for p, a in zip(preparo_puf, cli_puf)]
    delta_cliente_por_rodada = [p - o for p, o in zip(cliente_puf_por_rodada, cliente_orig_por_rodada)]
    dif_cli = [p - o for p, o in zip(cli_puf, cli_orig)]
    dif_srv = [p - o for p, o in zip(srv_puf, srv_orig)]
    overhead = [a - c - s for a, c, s in zip(auth_orig + auth_puf, cli_orig + cli_puf, srv_orig + srv_puf)]

    cliente_original = media(cliente_orig_por_rodada)
    sessao_original = media(coluna("sessao_orig_ns"))
    custo_puf = media(custo_por_rodada)
    delta_cliente = media(delta_cliente_por_rodada)

    return ResumoSeparado(
        protocolo=nome,
        pares=len(rodadas),
        registro_original_ms=r3(media(registro_orig)),
        registro_puf_ms=r3(media(registro_puf)),
        registro_delta_ms=r3(media([p - o for p, o in zip(registro_puf, registro_orig)])),
        preparo_original_ms=r3(media(preparo_orig)),
        preparo_puf_ms=r3(media(preparo_puf)),
        auth_cliente_original_ms=r3(media(cli_orig)),
        auth_cliente_puf_ms=r3(media(cli_puf)),
        auth_servidor_original_ms=r3(media(srv_orig)),
        auth_servidor_puf_ms=r3(media(srv_puf)),
        cliente_original_ms=r3(cliente_original),
        cliente_puf_ms=r3(media(cliente_puf_por_rodada)),
        servidor_original_ms=r3(media(srv_orig)),
        servidor_puf_ms=r3(media(srv_puf)),
        sessao_original_ms=r3(sessao_original),
        sessao_puf_ms=r3(media(coluna("sessao_puf_ns"))),
        overhead_runner_ms=r3(media(overhead)),
        custo_puf_ms=r3(custo_puf),
        custo_puf_desvio_ms=r3(desvio(custo_por_rodada)),
        custo_preparo_sobre_cliente_pct=round(percentual(cliente_original, custo_puf), 3),
        custo_preparo_sobre_sessao_pct=round(percentual(sessao_original, custo_puf), 3),
        delta_cliente_ms=r3(delta_cliente),
        delta_cliente_pct=round(percentual(cliente_original, delta_cliente), 3),
        dif_auth_cliente_ms=r3(media(dif_cli)),
        dif_auth_cliente_desvio_ms=r3(desvio(dif_cli)),
        auth_cliente_puf_mais_rapido=sum(1 for d in dif_cli if d < 0),
        dif_auth_servidor_ms=r3(media(dif_srv)),
        dif_auth_servidor_desvio_ms=r3(desvio(dif_srv)),
        auth_servidor_puf_mais_rapido=sum(1 for d in dif_srv if d < 0),
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


def imprimir_tabelas_separadas(resumos: list[ResumoSeparado]) -> None:
    quantidades = "/".join(map(str, sorted({r.pares for r in resumos})))
    largura = 100

    def titulo(texto):
        print("=" * largura)
        print(texto)
        print("=" * largura)

    titulo(f"TABELA A - REGISTRO (cliente, 1x) - ms, n = {quantidades} pares por protocolo")
    print(f"{'protocolo':<10}{'original':>12}{'com PUF':>12}{'acrescimo':>12}")
    print("-" * largura)
    for r in resumos:
        print(f"{r.protocolo:<10}{r.registro_original_ms:>12.2f}{r.registro_puf_ms:>12.2f}{r.registro_delta_ms:>+12.2f}")
    print()

    titulo("TABELA B - PROCESSAMENTO POR PARTICIPANTE NA AUTENTICACAO - ms")
    print(f"{'protocolo':<10}{'cliente orig':>13}{'cliente puf':>13}{'servidor orig':>15}{'servidor puf':>14}"
          f"{'sessao orig':>13}{'sessao puf':>12}")
    print("-" * largura)
    for r in resumos:
        print(f"{r.protocolo:<10}{r.cliente_original_ms:>13.2f}{r.cliente_puf_ms:>13.2f}"
              f"{r.servidor_original_ms:>15.2f}{r.servidor_puf_ms:>14.2f}"
              f"{r.sessao_original_ms:>13.2f}{r.sessao_puf_ms:>12.2f}")
    print()

    titulo("TABELA C - IMPACTO DA CAMADA PUF (medido no preparo do cliente) - ms")
    print(f"{'protocolo':<10}{'custo PUF':>12}{'(desvio)':>10}{'% do cliente':>14}{'% da sessao':>13}"
          f"{'delta cliente':>15}{'delta cli. %':>14}")
    print("-" * largura)
    for r in resumos:
        print(f"{r.protocolo:<10}{r.custo_puf_ms:>+12.2f}{r.custo_puf_desvio_ms:>10.2f}"
              f"{r.custo_preparo_sobre_cliente_pct:>+13.2f}%{r.custo_preparo_sobre_sessao_pct:>+12.2f}%"
              f"{r.delta_cliente_ms:>+15.2f}{r.delta_cliente_pct:>+13.2f}%")
    print("-" * largura)


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

    if all(tem_separacao(rodadas) for rodadas in por_protocolo.values()):
        resumos = [resumir_separado(nome, rodadas) for nome, rodadas in por_protocolo.items()]
        imprimir_tabelas_separadas(resumos)
    else:
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
