import csv
import os
import statistics
from dataclasses import asdict, dataclass, fields


@dataclass(frozen=True)
class ResultadoPar:
    """Uma rodada: os tempos das três fases nas duas versões (ns). sessao = preparo + auth."""
    protocolo: str
    iteracao: int
    registro_orig_ns: int
    registro_puf_ns: int
    preparo_orig_ns: int
    preparo_puf_ns: int
    auth_orig_ns: int
    auth_puf_ns: int
    sessao_orig_ns: int
    sessao_puf_ns: int
    delta_sessao_ns: int
    # tempo das chamadas de cada lado dentro de auth (0 em CSVs gerados antes dessa separação)
    auth_cliente_orig_ns: int = 0
    auth_servidor_orig_ns: int = 0
    auth_cliente_puf_ns: int = 0
    auth_servidor_puf_ns: int = 0


@dataclass(frozen=True)
class ResultadoComponente:
    operacao: str      # puf, gen, rep, mask, protect, recover
    iteracao: int
    tempo_ns: int


def media(valores) -> float:
    valores = list(valores)
    return statistics.fmean(valores) if valores else 0.0


def mediana(valores) -> float:
    valores = list(valores)
    return statistics.median(valores) if valores else 0.0


def desvio(valores) -> float:
    valores = list(valores)
    return statistics.pstdev(valores) if len(valores) > 1 else 0.0


def percentual(base: float, delta: float) -> float:
    return delta / base * 100.0 if base else 0.0


def ms(ns: float) -> float:
    return ns / 1_000_000.0


def us(ns: float) -> float:
    return ns / 1_000.0


def escrever_csv(caminho: str, linhas: list) -> None:
    if not linhas:
        return
    os.makedirs(os.path.dirname(caminho) or ".", exist_ok=True)
    with open(caminho, "w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=[f.name for f in fields(linhas[0])])
        escritor.writeheader()
        escritor.writerows(asdict(linha) for linha in linhas)
