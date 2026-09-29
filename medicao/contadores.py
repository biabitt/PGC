"""
Medição por etapa: tempo e contagem de operações criptográficas.

O tempo de cada etapa é sempre medido (custo desprezível). A contagem de
operações só existe depois de chamar instalar(), que "embrulha" as funções da
py_ecc usadas pelo protocolo. Por isso o orquestrador faz UMA execução com
contagem (modo "contagem") e as demais sem ela (modo "tempo"), para que o
embrulho nunca interfira nas medidas de tempo.

Operações contadas:

    emparelhamento   pairing(...)
    exp_gt           exponenciação em GT (elemento ** inteiro)
    mult_g1/mult_g2  multiplicação escalar de ponto em G1 / G2
    soma_g1/soma_g2  soma de pontos em G1 / G2
    hash             H1..H4 do protocolo

Uma operação é contada apenas na chamada mais externa: o pairing() da py_ecc
faz exponenciações internas e a exponenciação em GT é recursiva, e nada disso
deve inflar a contagem.
"""

import time
from collections import Counter
from contextlib import contextmanager

_contagem: Counter = Counter()
_profundidade = 0
_instalado = False


def _grupo(ponto) -> str:
    from py_ecc.optimized_bn128 import FQ2

    try:
        return "g2" if isinstance(ponto[0], FQ2) else "g1"
    except (TypeError, IndexError):
        return "g1"


def _envolver(funcao, classificar):
    def envolvida(*args, **kwargs):
        global _profundidade

        if _profundidade == 0:
            _contagem[classificar(*args)] += 1

        _profundidade += 1
        try:
            return funcao(*args, **kwargs)
        finally:
            _profundidade -= 1

    envolvida.__wrapped__ = funcao
    return envolvida


def instalar() -> None:
    """Ativa a contagem de operações (idempotente)."""

    global _instalado

    if _instalado:
        return

    import ataque.atacante as m_atacante
    import protocolo.cliente as m_cliente
    import protocolo.servidor as m_servidor
    import protocolo.sgc as m_sgc
    from py_ecc.optimized_bn128 import FQ12

    classificadores = {
        "add": lambda ponto, *_: "soma_" + _grupo(ponto),
        "multiply": lambda ponto, *_: "mult_" + _grupo(ponto),
        "pairing": lambda *_: "emparelhamento",
        "hash_para_inteiro": lambda *_: "hash",
        "hash_chave_sessao": lambda *_: "hash",
        "hash_autenticacao": lambda *_: "hash",
        "hash_confirmacao": lambda *_: "hash",
    }

    for modulo in (m_cliente, m_servidor, m_atacante, m_sgc):
        for nome, classificar in classificadores.items():
            original = getattr(modulo, nome, None)
            if original is not None:
                setattr(modulo, nome, _envolver(original, classificar))

    FQ12.__pow__ = _envolver(FQ12.__pow__, lambda *_: "exp_gt")

    _instalado = True


@contextmanager
def etapa(registro: dict, nome: str):
    """
    Mede uma etapa e a registra em `registro[nome]`:

        real_ns   relógio de parede (perf_counter_ns)
        cpu_ns    CPU do processo (process_time_ns: user + sys)
        operacoes contagem de operações (vazio se instalar() não foi chamado)
    """

    antes = dict(_contagem)
    inicio_real = time.perf_counter_ns()
    inicio_cpu = time.process_time_ns()

    try:
        yield
    finally:
        fim_cpu = time.process_time_ns()
        fim_real = time.perf_counter_ns()

        operacoes = {}
        for chave, valor in _contagem.items():
            delta = valor - antes.get(chave, 0)
            if delta:
                operacoes[chave] = delta

        registro[nome] = {
            "real_ns": fim_real - inicio_real,
            "cpu_ns": fim_cpu - inicio_cpu,
            "operacoes": operacoes,
        }
