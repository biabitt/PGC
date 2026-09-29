"""
Conversão em bytes das mensagens do protocolo e dos dados de provisionamento.

Reaproveita criptografia/serializacao.py (pontos de G1 e G2) e acrescenta o
que faltava para separar cliente e servidor em processos: a desserialização de
elementos de GT (o desafio Z trafega na mensagem 2).

Formato das mensagens na rede (cada uma enviada com send_bytes):

    1  Ui -> SPj   identidade do servidor (UTF-8)
    2  SPj -> Ui   Z                       (GT, 12 x 32 = 384 bytes)
    3  Ui -> SPj   K2 || C1                (K2 em G2 = 128 bytes, depois C1)
    4  SPj -> Ui   Di                      (hash)
"""

import json
from pathlib import Path

from py_ecc.optimized_bn128 import FQ12

from criptografia.serializacao import (
    TAMANHO_CAMPO,
    TAMANHO_G2,
    bytes_para_inteiro,
    desserializar_ponto_g1,
    desserializar_ponto_g2,
    serializar_elemento_gt,
    serializar_ponto_g1,
    serializar_ponto_g2,
)
from protocolo.mensagens import (
    ConfirmacaoServidor,
    DesafioServidor,
    RespostaCliente,
    SolicitacaoServico,
)
from protocolo.parametros import (
    ParametrosPublicos,
    RegistroCliente,
    RegistroServidor,
)

GRAU_GT = 12
TAMANHO_GT = GRAU_GT * TAMANHO_CAMPO


# ----------------------------------------------------------------------
# GT
# ----------------------------------------------------------------------

def desserializar_elemento_gt(dados: bytes):
    """Reconstrói um elemento de GT (FQ12) a partir de 384 bytes."""
    if len(dados) != TAMANHO_GT:
        raise ValueError(
            f"Um elemento de GT deve possuir exatamente {TAMANHO_GT} bytes."
        )

    coeficientes = [
        bytes_para_inteiro(
            dados[i * TAMANHO_CAMPO:(i + 1) * TAMANHO_CAMPO]
        )
        for i in range(GRAU_GT)
    ]

    return FQ12(coeficientes)


# ----------------------------------------------------------------------
# Mensagens
# ----------------------------------------------------------------------

def codificar_solicitacao(mensagem: SolicitacaoServico) -> bytes:
    return mensagem.identidade_servidor.encode("utf-8")


def decodificar_solicitacao(dados: bytes) -> SolicitacaoServico:
    return SolicitacaoServico(identidade_servidor=dados.decode("utf-8"))


def codificar_desafio(mensagem: DesafioServidor) -> bytes:
    return serializar_elemento_gt(mensagem.z)


def decodificar_desafio(dados: bytes) -> DesafioServidor:
    return DesafioServidor(z=desserializar_elemento_gt(dados))


def codificar_resposta(mensagem: RespostaCliente) -> bytes:
    return serializar_ponto_g2(mensagem.k2) + mensagem.c1


def decodificar_resposta(dados: bytes) -> RespostaCliente:
    if len(dados) < TAMANHO_G2:
        raise ValueError("Mensagem 3 menor que um ponto de G2.")

    return RespostaCliente(
        k2=desserializar_ponto_g2(dados[:TAMANHO_G2]),
        c1=dados[TAMANHO_G2:],
    )


def codificar_confirmacao(mensagem: ConfirmacaoServidor) -> bytes:
    return mensagem.di


def decodificar_confirmacao(dados: bytes) -> ConfirmacaoServidor:
    return ConfirmacaoServidor(di=dados)


# ----------------------------------------------------------------------
# Provisionamento (parâmetros públicos e chaves privadas em disco)
# ----------------------------------------------------------------------

def _escrever_json(caminho: Path, conteudo: dict) -> None:
    caminho.write_text(
        json.dumps(conteudo, indent=2), encoding="utf-8"
    )


def _ler_json(caminho: Path) -> dict:
    return json.loads(caminho.read_text(encoding="utf-8"))


def salvar_provisionamento(
    pasta: Path,
    parametros: ParametrosPublicos,
    registro_cliente: RegistroCliente,
    registro_servidor: RegistroServidor,
) -> None:
    pasta.mkdir(parents=True, exist_ok=True)

    _escrever_json(
        pasta / "parametros.json",
        {
            "gerador_g1": serializar_ponto_g1(parametros.gerador_g1).hex(),
            "gerador_g2": serializar_ponto_g2(parametros.gerador_g2).hex(),
            "chave_publica_g1": serializar_ponto_g1(
                parametros.chave_publica_g1
            ).hex(),
            "chave_publica_g2": serializar_ponto_g2(
                parametros.chave_publica_g2
            ).hex(),
            "emparelhamento_base": serializar_elemento_gt(
                parametros.emparelhamento_base
            ).hex(),
            "ordem_grupo": str(parametros.ordem_grupo),
        },
    )

    _escrever_json(
        pasta / "registro_cliente.json",
        {
            "identidade": registro_cliente.identidade,
            "chave_privada_g2": serializar_ponto_g2(
                registro_cliente.chave_privada_g2
            ).hex(),
        },
    )

    _escrever_json(
        pasta / "registro_servidor.json",
        {
            "identidade": registro_servidor.identidade,
            "chave_privada_g1": serializar_ponto_g1(
                registro_servidor.chave_privada_g1
            ).hex(),
        },
    )


def carregar_parametros(pasta: Path) -> ParametrosPublicos:
    d = _ler_json(pasta / "parametros.json")

    return ParametrosPublicos(
        gerador_g1=desserializar_ponto_g1(bytes.fromhex(d["gerador_g1"])),
        gerador_g2=desserializar_ponto_g2(bytes.fromhex(d["gerador_g2"])),
        chave_publica_g1=desserializar_ponto_g1(
            bytes.fromhex(d["chave_publica_g1"])
        ),
        chave_publica_g2=desserializar_ponto_g2(
            bytes.fromhex(d["chave_publica_g2"])
        ),
        emparelhamento_base=desserializar_elemento_gt(
            bytes.fromhex(d["emparelhamento_base"])
        ),
        ordem_grupo=int(d["ordem_grupo"]),
    )


def carregar_registro_cliente(pasta: Path) -> RegistroCliente:
    d = _ler_json(pasta / "registro_cliente.json")

    return RegistroCliente(
        identidade=d["identidade"],
        chave_privada_g2=desserializar_ponto_g2(
            bytes.fromhex(d["chave_privada_g2"])
        ),
    )


def carregar_registro_servidor(pasta: Path) -> RegistroServidor:
    d = _ler_json(pasta / "registro_servidor.json")

    return RegistroServidor(
        identidade=d["identidade"],
        chave_privada_g1=desserializar_ponto_g1(
            bytes.fromhex(d["chave_privada_g1"])
        ),
    )
