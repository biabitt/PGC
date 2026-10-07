import hashlib
import hmac

from criptografia.hashes import concatenar_para_hash
from criptografia.utilitarios import xor_bytes

from puf.fuzzy_extractor import FuzzyExtractorSimples
from puf.simulacao import PUFConfig, SimulatedPUF


class CredentialProtector:
    def __init__(self, puf: SimulatedPUF, fuzzy: FuzzyExtractorSimples,
                 pid: str, identidade: str) -> None:
        self._puf = puf
        self._fuzzy = fuzzy
        self._pid = pid
        self._identidade = identidade
        self.helper_data: bytes | None = None          # W
        self.verificador: bytes | None = None          # V
        self._protegidas: dict[str, bytes] = {}        # E_{i,k}

    @classmethod
    def criar(cls, pid, identidade, config: PUFConfig | None = None):
        config = config or PUFConfig()
        return cls(SimulatedPUF(config),
                   FuzzyExtractorSimples(config.tamanho_chave, config.repeticoes),
                   pid, identidade)

    def registrar(self, credenciais: dict[str, bytes]) -> None:
        chave, self.helper_data = self._fuzzy.gen(self._puf.avaliar())
        self.verificador = self._verificador(chave)
        self._protegidas = {
            k: xor_bytes(s, self._mascara(chave, k, len(s))) for k, s in credenciais.items()
        }

    def recuperar(self) -> dict[str, bytes]:
        if self.helper_data is None:
            raise RuntimeError("A camada PUF ainda não foi provisionada.")
        chave = self._fuzzy.rep(self._puf.avaliar(), self.helper_data)
        if not hmac.compare_digest(self._verificador(chave), self.verificador):
            raise ValueError("Falha na verificação: a chave da PUF não foi reconstruída.")
        return {
            k: xor_bytes(e, self._mascara(chave, k, len(e))) for k, e in self._protegidas.items()
        }

    def _mascara(self, chave, rotulo, tamanho) -> bytes:
        dados = concatenar_para_hash(chave, self._pid, self._identidade, rotulo, b"MASK")
        return hashlib.shake_256(dados).digest(tamanho)

    def _verificador(self, chave) -> bytes:
        dados = concatenar_para_hash(chave, self._pid, self._identidade, b"VERIFY")
        return hashlib.sha256(dados).digest()
