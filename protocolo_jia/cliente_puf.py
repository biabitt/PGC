from criptografia.serializacao import bytes_para_inteiro, inteiro_para_bytes

from protocolo_jia.cliente import Usuario
from protocolo_jia.tipos import RegistroUsuario

from shared.puf_cliente import EspecCredencial, PUFClientMixin


class UsuarioPUF(PUFClientMixin, Usuario):
    PID = "JIA"
    CREDENCIAIS = (
        EspecCredencial("SID", "_sid_u", lambda r: r.sid_u, inteiro_para_bytes, bytes_para_inteiro),
    )

    def __init__(self, identidade, seed_puf=2026, ruido_puf=0.01, config=None, tolerancia_tempo=300):
        super().__init__(identidade, tolerancia_tempo)
        self._configurar_puf(identidade, seed_puf, ruido_puf, config)

    def receber_registro(self, registro: RegistroUsuario) -> None:
        self._r_u = registro.r_u_ponto
        self._registrar_credenciais(registro)

    def criar_mensagem_autenticacao(self, identidade_servidor):
        self._recuperar_se_necessario()
        return super().criar_mensagem_autenticacao(identidade_servidor)

    def verificar_resposta(self, resposta) -> bool:
        self._recuperar_se_necessario()
        return super().verificar_resposta(resposta)
