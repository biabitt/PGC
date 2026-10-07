from py_ecc.optimized_bn128 import add, multiply

from criptografia.hashes import hash_para_inteiro

from protocolo.mensagens import RespostaCliente, ResultadoAutenticacao
from protocolo.servidor import Servidor

from protocolo_irshad.mensagens import ConfirmacaoServidorIrshad


class ServidorIrshad(Servidor):
    def autenticar_cliente(self, resposta: RespostaCliente) -> ResultadoAutenticacao:
        resultado = super().autenticar_cliente(resposta)
        if not resultado.autenticado:
            return resultado

        qi = add(self._parametros.chave_publica_g1,
                 multiply(self._parametros.gerador_g1, hash_para_inteiro(resultado.identidade_cliente)))
        return ResultadoAutenticacao(
            autenticado=True,
            identidade_cliente=resultado.identidade_cliente,
            # A base chama de Di o que Irshad chama de Zi.
            confirmacao=ConfirmacaoServidorIrshad(zi=resultado.confirmacao.di, r3=multiply(qi, self._a)),
        )
