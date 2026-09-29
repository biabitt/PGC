"""Constantes compartilhadas pelos scripts de medição."""

from pathlib import Path

PASTA_MEDICAO = Path(__file__).resolve().parent
RAIZ = PASTA_MEDICAO.parent

# Chaves do sistema de teste (geradas por provisionar.py). Não versionar.
PASTA_DADOS = PASTA_MEDICAO / "dados"
PASTA_RESULTADOS = PASTA_MEDICAO / "resultados"

HOST = "127.0.0.1"

# Mesmas identidades usadas em cenarios.preparar_ambiente().
IDENTIDADE_CLIENTE = "cliente01"
SENHA_CLIENTE = "senha123"
IMPRESSAO_DIGITAL = "digital01"
IDENTIDADE_SERVIDOR = "servidor01"

# Operações criptográficas contadas (ver contadores.py).
OPERACOES = (
    "emparelhamento",
    "exp_gt",
    "mult_g1",
    "mult_g2",
    "soma_g1",
    "soma_g2",
    "hash",
)

# Etapas que NÃO fazem parte do custo do protocolo em si.
PREFIXOS_FORA_DO_PROTOCOLO = ("espera", "inicializacao", "codec")
