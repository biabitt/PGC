from dataclasses import dataclass

import numpy as np
from pypuf.simulation import XORArbiterPUF


@dataclass(frozen=True)
class PUFConfig:
    device_seed: int = 2026      # identifica o dispositivo
    ruido: float = 0.01          # probabilidade de ruído por bit em cada leitura
    tamanho_chave: int = 32      # bytes do segredo estável
    repeticoes: int = 11         # código de repetição (ímpar); corrige repeticoes//2 bits/bloco
    largura_desafio: int = 64
    k_arbiter: int = 4

    @property
    def tamanho_resposta(self) -> int:
        return self.tamanho_chave * 8 * self.repeticoes


class SimulatedPUF:
    """dispositivo + conjunto fixo de desafios -> resposta com ruído."""

    def __init__(self, config: PUFConfig | None = None) -> None:
        self.config = config or PUFConfig()
        c = self.config
        self._puf = XORArbiterPUF(n=c.largura_desafio, k=c.k_arbiter,
                                  seed=c.device_seed, noisiness=c.ruido)
        self._desafios = np.random.default_rng(c.device_seed + 1).choice(
            [-1, 1], size=(c.tamanho_resposta, c.largura_desafio)
        ).astype(np.int8)

    def avaliar(self) -> np.ndarray:
        """Uma leitura ruidosa: bits {0,1} de tamanho ``tamanho_resposta``."""
        return (np.asarray(self._puf.eval(self._desafios)).reshape(-1) > 0).astype(np.uint8)
