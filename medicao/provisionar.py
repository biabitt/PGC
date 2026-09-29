"""
Provisionamento: executa o SGC uma vez e grava em disco os parâmetros
públicos e as chaves privadas de cliente e servidor.

Cliente, servidor e atacante rodam em processos separados, então precisam
partilhar a mesma chave mestra do SGC. Este passo NÃO entra na medição.

Uso:
    python medicao/provisionar.py
"""

import argparse
import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parents[1]
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from medicao.codec import salvar_provisionamento  # noqa: E402
from medicao.config import (  # noqa: E402
    IDENTIDADE_CLIENTE,
    IDENTIDADE_SERVIDOR,
    PASTA_DADOS,
)
from protocolo.sgc import SGC  # noqa: E402


def provisionar(pasta: Path = PASTA_DADOS) -> None:
    sgc = SGC()
    parametros = sgc.configurar_sistema()

    registro_cliente = sgc.registrar_cliente(IDENTIDADE_CLIENTE)
    registro_servidor = sgc.registrar_servidor(IDENTIDADE_SERVIDOR)

    salvar_provisionamento(
        pasta, parametros, registro_cliente, registro_servidor
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dados", type=Path, default=PASTA_DADOS)
    args = parser.parse_args()

    provisionar(args.dados)
    print(f"Provisionamento gravado em {args.dados}")


if __name__ == "__main__":
    main()
