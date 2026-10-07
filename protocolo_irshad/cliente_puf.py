from criptografia.serializacao import desserializar_ponto_g2, serializar_ponto_g2

from protocolo.parametros import RegistroCliente
from protocolo_irshad.cliente import ClienteIrshad

from shared.puf_cliente import EspecCredencial, PUFClientMixin


class ClienteIrshadPUF(PUFClientMixin, ClienteIrshad):
    PID = "IRSHAD"
    CREDENCIAIS = (
        EspecCredencial("KEY", "_chave_privada_g2", lambda r: r.chave_privada_g2,
                        serializar_ponto_g2, desserializar_ponto_g2),
    )

    def __init__(self, identidade, seed_puf=2026, ruido_puf=0.01, config=None):
        # Cenário M2M: sem senha/biometria; a base exige os campos, mas não os usa aqui.
        super().__init__(identidade, senha="puf-hardware", impressao_digital="puf-hardware")
        self._configurar_puf(identidade, seed_puf, ruido_puf, config)

    def receber_registro(self, registro: RegistroCliente) -> None:
        self._registrar_credenciais(registro)

    def _verificacao_local(self) -> None:
        pass  # o verificador V da camada PUF substitui o Di' ?= Di do cartão

    def responder_desafio(self, desafio):
        self._recuperar_se_necessario()
        return super().responder_desafio(desafio)

    def autenticar_servidor(self, confirmacao) -> bool:
        self._recuperar_se_necessario()
        return super().autenticar_servidor(confirmacao)

    def _validar_pronto(self) -> None:
        if self._parametros is None:
            raise RuntimeError("O cliente ainda não recebeu os parâmetros públicos.")
        if self._protector.verificador is None:
            raise RuntimeError("O cliente ainda não recebeu sua chave privada protegida.")
