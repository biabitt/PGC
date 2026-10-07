from criptografia.serializacao import bytes_para_inteiro, inteiro_para_bytes

from protocolo_kaur.cliente import Usuario
from protocolo_kaur.tipos import RegistroUsuario

from shared.puf_cliente import EspecCredencial, PUFClientMixin


def _escalar(rotulo, atributo, campo):
    return EspecCredencial(rotulo, atributo, lambda r: getattr(r, campo),
                           inteiro_para_bytes, bytes_para_inteiro)


class UsuarioPUF(PUFClientMixin, Usuario):
    PID = "KAUR"
    CREDENCIAIS = (
        _escalar("SID", "_sid_u", "sid_u"),
        _escalar("DU", "_d_u", "d_u"),
        _escalar("RU", "_r_u", "r_u"),
    )

    def __init__(self, identidade, seed_puf=2026, ruido_puf=0.01, config=None, tolerancia_tempo=300):
        super().__init__(identidade, tolerancia_tempo)
        self._configurar_puf(identidade, seed_puf, ruido_puf, config)

    def receber_registro(self, registro: RegistroUsuario) -> None:
        self._registrar_credenciais(registro)

    def criar_mensagem_autenticacao(self):
        self._recuperar_se_necessario()
        return super().criar_mensagem_autenticacao()

    def verificar_resposta(self, resposta):
        self._recuperar_se_necessario()
        return super().verificar_resposta(resposta)
