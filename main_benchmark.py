import argparse
import os

from benchmark.base import escrever_csv
from benchmark.runner import BenchmarkRunner

MEDIDORES = {
    "tsailo": "medir_tsailo",
    "irshad": "medir_irshad",
    "jia": "medir_jia",
    "kaur": "medir_kaur",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark pareado do overhead da camada PUF.")
    parser.add_argument("--iteracoes", type=int, default=100, help="pares por protocolo")
    parser.add_argument("--saida", type=str, default="resultados")
    parser.add_argument("--protocolos", nargs="+", default=list(MEDIDORES),
                        choices=list(MEDIDORES))
    parser.add_argument("--detalhado", action="store_true",
                        help="também mede o custo por operação da camada PUF")
    args = parser.parse_args()

    runner = BenchmarkRunner()
    pares = []
    for nome in args.protocolos:
        print(f"Medindo {nome}: {args.iteracoes} pares original/PUF...")
        pares += getattr(runner, MEDIDORES[nome])(args.iteracoes)
    escrever_csv(os.path.join(args.saida, "benchmark.csv"), pares)

    if args.detalhado:
        print("Medindo componentes da camada PUF...")
        escrever_csv(os.path.join(args.saida, "componentes.csv"),
                     runner.medir_componentes(args.iteracoes))

    print(f"CSV salvo em: {os.path.abspath(args.saida)}")
    print(f"Tabela final: python main_resultados.py --entrada {os.path.join(args.saida, 'benchmark.csv')}")


if __name__ == "__main__":
    main()
