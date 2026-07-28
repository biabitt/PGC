# PGC — Análise de Segurança de Protocolos de Autenticação em MEC

Simulação, em Python, de um protocolo de autenticação mútua baseado em
emparelhamento bilinear (bilinear pairing) para ambientes de **Multi-Access
Edge Computing (MEC)**, incluindo a reprodução prática de um **ataque de
personificação do provedor de serviço (service provider impersonation)**.

## Contexto

O crescimento de paradigmas como *Mobile Cloud Computing* (MCC) e
*Multi-Access Edge Computing* (MEC) impulsionou o desenvolvimento de
protocolos de autenticação voltados a ambientes distribuídos e com recursos
limitados. Nesse contexto, garantir uma comunicação segura e privada entre
usuários e provedores de serviço é um desafio relevante. Diversos esquemas
propostos na literatura buscam equilibrar eficiência computacional e
privacidade do usuário, mas estudos recentes indicam que esses protocolos
podem apresentar vulnerabilidades quando avaliados sob cenários adversariais
mais realistas.

## Objetivo

Este projeto tem como objetivo analisar a segurança de protocolos de
autenticação em ambientes MEC, com foco na identificação de vulnerabilidades
e no estudo de ataques descritos na literatura. Como proposta prática, foi
desenvolvida a simulação de um ataque de personificação do provedor de
serviço, permitindo avaliar, na prática, a exploração dessas fragilidades e
contribuir para uma melhor compreensão dos riscos associados a esse tipo de
esquema.

## Visão geral do protocolo implementado

O protocolo simulado segue um esquema de autenticação mútua sem certificado
(*certificateless*), baseado em criptografia de curvas elípticas com
emparelhamento (implementado com a biblioteca `py_ecc`, curva BN128). As
entidades envolvidas são:

- **SGC (Smart Card Generator)** — autoridade confiável que configura o
  sistema, gera a chave mestra `s` e emite as chaves privadas do cliente e do
  servidor a partir de suas identidades públicas.
- **Cliente (Ui)** — usuário móvel que deseja se autenticar perante um
  provedor de serviço.
- **Servidor (SPj)** — provedor de serviço (nó MEC) que autentica o cliente e
  precisa, por sua vez, provar sua própria identidade a ele.

Fluxo de mensagens (autenticação mútua com acordo de chave de sessão):

1. `Ui -> SPj`: solicitação de serviço, contendo a identidade do servidor.
2. `SPj -> Ui`: desafio `Z = e(P2, P1)^a`, com `a` aleatório escolhido pelo
   servidor.
3. `Ui -> SPj`: resposta `(K2, C1)`, em que `K2` é derivado de um segredo
   aleatório `b` do cliente e `C1` mascara `(IDi, si, w)` usando a chave de
   sessão calculada pelo cliente, `Kij = H2(Z^b)`.
4. `SPj -> Ui`: confirmação `Di = H4(Kij || Z || IDi || IDj)`, que prova ao
   cliente que o servidor calculou a mesma chave de sessão.

Ao final, cliente e servidor devem compartilhar a mesma chave de sessão
`Kij`, derivada de forma equivalente a um acordo de chave estilo
Diffie-Hellman sobre o grupo alvo do emparelhamento (`GT`).

## Estrutura do repositório

```
criptografia/   Primitivas criptográficas: curva/emparelhamento, hashes
                (H1-H4), serialização de pontos e utilitários (XOR, máscara).
protocolo/      Entidades do protocolo: SGC, Cliente, Servidor e as
                mensagens trocadas entre elas.
ataque/         Implementação do atacante que executa a personificação do
                provedor de serviço.
testes/         Testes automatizados (pytest) cobrindo criptografia,
                registro, autenticação legítima e o ataque.
_old/           Protótipo inicial do protocolo, mantido como referência
                histórica do desenvolvimento.
main.py         Script de demonstração com os dois cenários: autenticação
                normal e ataque de personificação.
```

## Ataque de personificação do provedor de serviço

O cenário de ataque, implementado em `ataque/atacante.py` e demonstrado em
`main.py`, simula um adversário posicionado no canal de comunicação (modelo
Dolev-Yao) que:

- **não conhece** a chave mestra do SGC, nem a chave privada do servidor
  legítimo, nem a chave privada do cliente;
- **utiliza apenas** informações públicas: os parâmetros publicados pelo
  SGC e a identidade pública do servidor que está sendo personificado.

### Como o ataque funciona

1. O atacante intercepta a solicitação de serviço do cliente e, em vez de
   encaminhá-la ao servidor legítimo, gera seu próprio desafio:

   ```
   Z = e(Ppub2 + H1(IDj)·P2, P1)^a
   ```

   usando apenas o parâmetro público do sistema e a identidade pública do
   servidor `IDj` — sem precisar da chave privada `Sj1`.

2. O cliente, acreditando estar falando com o servidor legítimo, responde
   normalmente com `(K2, C1)`, em que `K2 = b·(Ppub2 + H1(IDj)·P2)`.

3. Como `K2` é um múltiplo escalar do mesmo ponto público usado pelo
   atacante para montar `Z`, o atacante consegue reconstruir exatamente a
   mesma chave de sessão calculada pelo cliente:

   ```
   Kij = H2(e(K2, P1)^a) = H2(Z^b)
   ```

   sem jamais realizar a operação de emparelhamento que dependeria da chave
   privada real do servidor (`Sj1`).

4. Com `Kij` em mãos, o atacante desmascara `C1`, recupera a identidade do
   cliente e os dados protegidos, e devolve a confirmação
   `Di = H4(Kij || Z || IDi || IDj)`. Como o cálculo de `Kij` é idêntico ao
   do cliente, essa confirmação é aceita como legítima.

O resultado é uma personificação completa do provedor de serviço: o cliente
autentica o atacante como se fosse o servidor real, ambos compartilham a
mesma chave de sessão e o servidor legítimo nunca participa da interação.

### Causa raiz

A vulnerabilidade decorre do fato de o desafio `Z` não estar vinculado a
nenhum segredo exclusivo do servidor no momento em que é gerado — ele tem a
forma `e(X, P1)^a`, em que `X = Ppub2 + H1(IDj)·P2` é inteiramente público e
pode ser recalculado por qualquer parte a partir da identidade do servidor.
A posse da chave privada `Sj1` só é efetivamente exigida na etapa em que o
*servidor* verificaria a assinatura do cliente (`si`, `w`) — mas, como o
atacante nunca precisa (nem tenta) validar essa assinatura para completar a
autenticação do lado do cliente, ele consegue concluir todo o protocolo de
personificação sem jamais possuir a chave privada do servidor.

Esse resultado ilustra, na prática, por que a etapa de autenticação do
servidor (prova de identidade perante o cliente) deve depender de um
segredo que só o servidor legítimo possui, calculado de forma que não possa
ser reproduzido a partir apenas de informação pública mais uma resposta
honesta do cliente.

## Como executar

Pré-requisitos: Python 3.10+.

```bash
pip install -r requirements.txt

# Executa os dois cenários de demonstração (autenticação normal e ataque)
python main.py

# Executa a suíte de testes automatizados
pytest testes/
```

## Aviso

Este projeto tem finalidade exclusivamente acadêmica e educacional. Toda a
simulação — protocolo, entidades e ataque — é executada localmente, em
processo único, sem interação com sistemas, redes ou serviços de terceiros.
O objetivo é apoiar a análise de robustez de protocolos de autenticação
descritos na literatura, e não fornecer ferramentas para exploração de
sistemas em produção.
