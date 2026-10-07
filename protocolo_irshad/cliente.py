import hmac

from py_ecc.optimized_bn128 import add, curve_order, multiply, pairing

from criptografia.hashes import (
    gerar_aleatorio,
    hash_autenticacao,
    hash_chave_sessao,
    hash_confirmacao,
    hash_para_inteiro,
    inverso_modular,
)
from criptografia.serializacao import desserializar_ponto_g2, serializar_ponto_g2
from criptografia.utilitarios import gerar_mascara, xor_bytes

from protocolo.cliente import Cliente
from protocolo.codificacao import codificar_dados_cliente
from protocolo.mensagens import DesafioServidor, RespostaCliente, SolicitacaoServico
from protocolo.parametros import RegistroCliente

from protocolo_irshad.mensagens import ConfirmacaoServidorIrshad

from shared.util import hash_rotulado_32


# --- cartão inteligente (Hb simulado por hash rotulado) -----------------------

def _bio_hash(impressao_digital: str) -> bytes:
    return hash_rotulado_32("IRSHAD-BIOHASH", impressao_digital)


def _di(identidade, senha, hb) -> bytes:
    """Di = h(IDi || PWi || Hb(fi))"""
    return hash_rotulado_32("IRSHAD-DI", identidade, senha, hb)


def _mascara_chave(senha, hb, tamanho) -> bytes:
    """h(PWi || Hb(fi)) expandida ao tamanho da chave serializada."""
    return gerar_mascara(chave=hash_rotulado_32("IRSHAD-EI", senha, hb), tamanho=tamanho)


class ClienteIrshad(Cliente):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._b: int | None = None
        self._ei: bytes | None = None
        self._di: bytes | None = None

    # --- registro: Di e Ei no cartão -------------------------------------------

    def receber_registro(self, registro: RegistroCliente) -> None:
        if registro.identidade != self.identidade:
            raise ValueError("O registro recebido pertence a outro cliente.")
        hb = _bio_hash(self._impressao_digital)
        chave = serializar_ponto_g2(registro.chave_privada_g2)
        self._ei = xor_bytes(chave, _mascara_chave(self._senha, hb, len(chave)))
        self._di = _di(self.identidade, self._senha, hb)
        self._chave_privada_g2 = None

    # --- login: verificação local e recuperação de Ki --------------------------

    def preparar_autenticacao(self) -> None:
        """Di' ?= Di e Ki = Ei XOR h(.). Os métodos de autenticação chamam sob demanda."""
        self._verificacao_local()
        self._recuperar_chave()

    def finalizar_sessao(self) -> None:
        self._chave_privada_g2 = None

    def criar_solicitacao(self, identidade_servidor: str) -> SolicitacaoServico:
        self._verificacao_local()
        return super().criar_solicitacao(identidade_servidor)

    def _verificacao_local(self) -> None:
        if self._di is None:
            raise RuntimeError("O cliente ainda não recebeu sua chave privada.")
        di_linha = _di(self.identidade, self._senha, _bio_hash(self._impressao_digital))
        if not hmac.compare_digest(di_linha, self._di):
            raise ValueError("Verificação local falhou: identidade, senha ou biometria incorretas.")

    def _recuperar_chave(self) -> None:
        if self._chave_privada_g2 is not None:
            return
        if self._ei is None:
            raise RuntimeError("O cliente ainda não recebeu sua chave privada.")
        hb = _bio_hash(self._impressao_digital)
        chave = xor_bytes(self._ei, _mascara_chave(self._senha, hb, len(self._ei)))
        self._chave_privada_g2 = desserializar_ponto_g2(chave)

    # --- autenticação ------------------------------------------------------------

    def responder_desafio(self, desafio: DesafioServidor) -> RespostaCliente:
        self._recuperar_chave()
        self._validar_pronto()
        if self._identidade_servidor is None:
            raise RuntimeError("O cliente ainda não criou uma solicitação.")

        b = gerar_aleatorio()
        z = desafio.z
        chave_sessao = hash_chave_sessao(z ** b)

        k2 = multiply(add(self._parametros.chave_publica_g2,
                          multiply(self._parametros.gerador_g2,
                                   hash_para_inteiro(self._identidade_servidor))), b)
        qi = add(self._parametros.chave_publica_g1,
                 multiply(self._parametros.gerador_g1, hash_para_inteiro(self.identidade)))
        w = multiply(qi, b)

        h3 = hash_autenticacao(self.identidade, z, self._identidade_servidor, w, chave_sessao)
        si = multiply(self._chave_privada_g2, inverso_modular((b + h3) % curve_order))

        dados = codificar_dados_cliente(identidade=self.identidade, si_g2=si, w_g1=w)
        c1 = xor_bytes(dados, gerar_mascara(chave=chave_sessao, tamanho=len(dados)))

        self._ultimo_z = z
        self._chave_sessao = chave_sessao
        self._b = b
        return RespostaCliente(k2=k2, c1=c1)

    def autenticar_servidor(self, confirmacao: ConfirmacaoServidorIrshad) -> bool:
        """Mij' = H2(e(R3, Ki)^y); aceita se Zi == H4(Mij' || A || IDi || IDj)."""
        if (self._chave_sessao is None or self._ultimo_z is None
                or self._identidade_servidor is None or self._b is None):
            raise RuntimeError("O cliente ainda não respondeu a um desafio.")
        self._recuperar_chave()
        chave = hash_chave_sessao(pairing(self._chave_privada_g2, confirmacao.r3) ** self._b)
        zi = hash_confirmacao(chave, self._ultimo_z, self.identidade, self._identidade_servidor)
        return hmac.compare_digest(zi, confirmacao.zi)

    def _validar_pronto(self) -> None:
        if self._parametros is None:
            raise RuntimeError("O cliente ainda não recebeu os parâmetros públicos.")
        if self._chave_privada_g2 is None and self._ei is None:
            raise RuntimeError("O cliente ainda não recebeu sua chave privada.")
