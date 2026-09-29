# Medição de desempenho: cliente e servidor em processos separados

Esta pasta mede o custo de execução do protocolo de autenticação e do ataque
de personificação, com cliente e servidor (ou atacante) rodando como
**processos independentes** que conversam por TCP em `localhost`.

Nada nas pastas `protocolo/`, `ataque/`, `criptografia/` ou em `cenarios.py`
foi alterado: as classes `Cliente`, `Servidor` e `Atacante` são as mesmas.

## Como executar (Windows)

No PowerShell ou no Prompt de Comando, dentro da pasta raiz do projeto
(a que contém `main.py`):

```
py -m pip install -r medicao\requirements.txt

py medicao\rodar.py --repeticoes 30
py medicao\analisar.py
```

Se o comando `py` não existir, use `python` no lugar.

- `rodar.py` faz o provisionamento (na primeira vez), executa as sessões e
  grava os CSVs em `medicao\resultados\`. Com 30 repetições e dois cenários
  leva cerca de 1 a 2 minutos.
- `analisar.py` lê os CSVs e gera as tabelas resumo e os gráficos (PNG).
  Use `py medicao\analisar.py --excel` para gravar os resumos com `;` e
  vírgula decimal, que abrem direto no Excel em português.

Testes desta pasta (opcional): `py -m pytest medicao`.

Rodar em macOS ou Linux é igual, trocando `py` por `python3` e `\` por `/`.

## O que é medido

Cada sessão de autenticação é feita por **dois processos novos** (servidor ou
atacante, e cliente), e cada um mede a si mesmo:

| Medida | Como | Onde aparece |
|---|---|---|
| Tempo de cada etapa (relógio) | `perf_counter_ns` em volta de cada método do protocolo | `etapas.csv` (`real_ns`) |
| Tempo de CPU de cada etapa | `process_time_ns` | `etapas.csv` (`cpu_ns`) |
| Tempo do processo inteiro: real, user, sys | relógio do orquestrador e `os.times()` | `execucoes.csv` |
| Operações criptográficas por etapa | contagem exata (uma sessão por cenário) | `etapas.csv`, colunas de operações |
| Bytes de cada mensagem | tamanho do que foi enviado | `mensagens.csv` |

Operações contadas: `emparelhamento`, `exp_gt` (exponenciação em GT),
`mult_g1`, `mult_g2`, `soma_g1`, `soma_g2` e `hash`.

### Etapas

| Processo | Etapas do protocolo | Etapas que **não** entram no custo do protocolo |
|---|---|---|
| Servidor | `gerar_desafio`, `autenticar_cliente` | `inicializacao`, `espera_*`, `codec_*` |
| Atacante | `interceptar_solicitacao`, `interceptar_resposta` | idem |
| Cliente | `criar_solicitacao`, `responder_desafio`, `autenticar_servidor` | idem |

`inicializacao` é carregar os parâmetros e chaves; `espera_*` é o tempo
bloqueado esperando o outro lado; `codec_*` é converter mensagens em bytes.
Elas ficam registradas à parte para não contaminar o custo do protocolo.

## Como a medição é organizada

1. `provisionar.py` executa o SGC **uma vez** e grava parâmetros públicos e
   chaves em `medicao\dados\` (fora da medição; a pasta não é versionada).
2. Para cada cenário, `rodar.py` faz:
   1. **1 sessão com contagem** de operações (as contagens são exatas e iguais
      em toda execução, então uma basta);
   2. **sessões de aquecimento** (padrão: 2), marcadas como `aquecimento` e
      ignoradas na análise;
   3. **N repetições medidas** (padrão: 30), **alternando** os cenários
      (normal, ataque, normal, ataque...) para que uma deriva da máquina
      afete os dois igualmente.
3. A contagem de operações roda **separada** das repetições de tempo, para o
   código de contagem nunca interferir nas medidas de tempo.
4. Toda saída dos processos vai para `DEVNULL` (equivalente ao `> /dev/null`).
5. Cada sessão é conferida: as chaves de sessão de cliente e servidor
   (ou atacante) precisam coincidir e o cliente precisa aceitar a
   confirmação `Di`. Qualquer falha é avisada no final da execução.

## Arquivos gerados em `medicao\resultados\`

Brutos (uma linha por medição):

- `execucoes.csv`: um processo por linha (`real_processo_s`, `cpu_user_s`,
  `cpu_sys_s`...).
- `etapas.csv`: uma etapa por linha (tempo e operações).
- `mensagens.csv`: bytes de cada mensagem.
- `ambiente.json`: sistema, Python, versão da `py_ecc`, data e parâmetros.

Resumos (gerados por `analisar.py`):

- `resumo_protocolo.csv`: tempo do protocolo por papel (média, desvio,
  mediana, mínimo, máximo).
- `resumo_etapas.csv`: o mesmo, etapa por etapa.
- `resumo_processo.csv`: tempo do processo inteiro (real, user, sys).
- `resumo_operacoes.csv` e `operacoes_por_etapa.csv`: contagem de operações.
- `resumo_mensagens.csv`: tamanho das mensagens.
- `grafico_tempo_protocolo.png`, `grafico_operacoes.png`,
  `grafico_mensagens.png`.

## Para o experimento valer

Deixe registrado na metodologia (o `ambiente.json` ajuda, mas anote também o
modelo do processador e a memória RAM):

- rodar **na mesma máquina**, com tudo fechado (navegador, mensageiros,
  atualizações, antivírus em varredura);
- computador **na tomada**, com plano de energia em "Alto desempenho" ou
  "Melhor desempenho";
- **não usar o computador** durante a coleta;
- rodar `rodar.py` mais de uma vez em momentos diferentes e comparar, para
  ver se os resultados se repetem.

## Limitações a citar no trabalho

- **Rede em loopback.** Não há latência nem perda de pacotes; o que se mede é
  o custo de CPU e o volume de dados, não o tempo de rede real.
- **Implementação em Python puro** (`py_ecc`). Os tempos absolutos são muito
  maiores que os de uma biblioteca em C (como PBC ou RELIC); a comparação
  entre papéis e cenários continua válida, mas os valores não se comparam
  diretamente com os do artigo original. Por isso a contagem de operações
  complementa o tempo.
- **Resolução do tempo de CPU no Windows.** `process_time` e `os.times()`
  avançam em passos de cerca de 15 ms. Para as etapas (100 a 700 ms) isso é
  aceitável e a média de várias execuções ameniza; por isso o gráfico principal
  usa o relógio (`perf_counter`), que tem alta resolução. As colunas de CPU
  ficam como conferência.
- Os tempos do **processo inteiro** incluem a inicialização do Python e os
  `import`s da `py_ecc`, iguais para todos os papéis. O `real` do servidor
  também inclui o tempo esperando o cliente; para comparar custo, prefira
  `cpu_total_s` ou os tempos de etapa.
- Não há medição de memória.

## Estrutura

```
medicao/
  config.py          constantes (pastas, identidades, operações)
  codec.py           mensagens <-> bytes; desserialização de GT; provisionamento
  contadores.py      cronômetro por etapa e contagem de operações
  comum.py           argumentos e gravação das métricas de cada processo
  provisionar.py     roda o SGC uma vez e grava as chaves
  servidor_main.py   processo do servidor legítimo
  cliente_main.py    processo do cliente
  atacante_main.py   processo do atacante
  rodar.py           orquestrador: sobe os processos, repete, grava CSVs
  analisar.py        resumos e gráficos
  test_medicao.py    testes
```
