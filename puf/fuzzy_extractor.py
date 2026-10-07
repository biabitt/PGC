import hashlib
import secrets

import numpy as np


class FuzzyExtractorSimples:
    def __init__(self, tamanho_chave: int = 32, repeticoes: int = 11) -> None:
        if tamanho_chave <= 0:
            raise ValueError("O tamanho da chave deve ser positivo.")
        if repeticoes < 3 or repeticoes % 2 == 0:
            raise ValueError("O número de repetições deve ser ímpar e pelo menos 3.")
        self.tamanho_chave = tamanho_chave
        self.repeticoes = repeticoes
        self.quantidade_bits = tamanho_chave * 8
        self.tamanho_resposta = self.quantidade_bits * repeticoes

    def gen(self, resposta: np.ndarray) -> tuple[bytes, bytes]:
        resposta = self._validar(resposta)
        segredo = secrets.token_bytes(self.tamanho_chave)
        codigo = np.repeat(np.unpackbits(np.frombuffer(segredo, dtype=np.uint8)), self.repeticoes)
        helper = np.packbits(np.bitwise_xor(resposta, codigo)).tobytes()
        return hashlib.sha256(segredo).digest(), helper

    def rep(self, resposta: np.ndarray, helper_data: bytes) -> bytes:
        resposta = self._validar(resposta)
        helper_bits = np.unpackbits(np.frombuffer(helper_data, dtype=np.uint8))[: self.tamanho_resposta]
        if helper_bits.size != self.tamanho_resposta:
            raise ValueError("Os dados auxiliares possuem tamanho inválido.")
        blocos = np.bitwise_xor(resposta, helper_bits).reshape(self.quantidade_bits, self.repeticoes)
        bits = (blocos.sum(axis=1) > self.repeticoes // 2).astype(np.uint8)
        return hashlib.sha256(np.packbits(bits).tobytes()[: self.tamanho_chave]).digest()

    def _validar(self, resposta) -> np.ndarray:
        resposta = np.asarray(resposta, dtype=np.uint8).reshape(-1)
        if resposta.size != self.tamanho_resposta:
            raise ValueError(f"A resposta deve possuir {self.tamanho_resposta} bits.")
        if not np.all((resposta == 0) | (resposta == 1)):
            raise ValueError("A resposta deve conter apenas bits 0 e 1.")
        return resposta
