---
title: "Introdução ao OWASP Top 10"
description: "O que é OWASP, como funciona o Top 10 e como usar este guia"
---

# Introdução ao OWASP Top 10

## O que é OWASP?

**OWASP** (Open Worldwide Application Security Project) é uma fundação sem fins lucrativos dedicada a melhorar a segurança de software. Fundada em 2001, reúne milhares de voluntários ao redor do mundo — pesquisadores, desenvolvedores, e profissionais de segurança — que colaboram para criar documentos, ferramentas e padrões abertos e gratuitos.

> "A missão da OWASP é tornar a segurança de software visível, para que indivíduos e organizações possam tomar decisões informadas sobre riscos reais de segurança."

### Por que a OWASP importa?

- Seus documentos são usados como referência por reguladores (PCI DSS, ISO 27001)
- Empresas de todo o mundo usam o OWASP Top 10 como base para auditorias
- É completamente gratuito e de código aberto
- É atualizado periodicamente com base em dados reais de vulnerabilidades

---

## O que é o OWASP Top 10?

O **OWASP Top 10** é uma lista das 10 categorias de vulnerabilidades mais críticas em aplicações web. A lista é gerada a partir de uma análise de dados de:

- Centenas de organizações parceiras
- Dezenas de milhares de aplicações reais testadas
- CVEs (Common Vulnerabilities and Exposures) catalogados
- Contribuições da comunidade de segurança global

!!! info "Não é apenas uma lista"
    O OWASP Top 10 não é só uma lista — é um **documento de conscientização** com explicações detalhadas, exemplos de ataque, e recomendações de prevenção. Este guia expande e didatiza esse conteúdo.

### Histórico das versões

| Ano | Grandes mudanças |
|-----|-----------------|
| 2003 | Primeira versão publicada |
| 2007 | Refatoração completa |
| 2010 | Adição de métricas de risco |
| 2013 | Inclusão de CSRF e componentes vulneráveis |
| 2017 | Adição de XXE e desserialização insegura |
| 2021 | Maior reformulação até então: 3 novas categorias |
| **2025** | **Versão atual: foco em supply chain e condições excepcionais** |

---

## O que mudou no OWASP Top 10:2025?

A edição de 2025 traz mudanças significativas em relação a 2021:

=== "Novidades em 2025"
    - **A03** agora é **Software Supply Chain Failures** (anteriormente "Injection" estava em A03)
    - **A10** passa a ser **Mishandling of Exceptional Conditions** — novo foco em tratamento de erros
    - Maior ênfase em ataques à cadeia de suprimentos de software (npm, PyPI, Docker Hub)
    - Reconhecimento de ataques a sistemas de CI/CD

=== "O que permaneceu"
    - **A01 — Broken Access Control** continua no topo (falha mais comum)
    - **Injection** (SQL, NoSQL, OS, LDAP) ainda é crítico
    - Falhas criptográficas seguem sendo um problema endêmico
    - Autenticação fraca continua sendo um vetor primário de ataque

---

## Como usar este guia

### Estrutura de cada vulnerabilidade

Cada página segue o mesmo padrão para facilitar o aprendizado:

1. **Badge de risco e analogia** — uma metáfora do mundo real para contextualizar
2. **Explicação em 3 níveis** — para leigos, devs juniores e devs seniores
3. **Código vulnerável vs. seguro** — exemplos práticos comentados
4. **Cenário de ataque** — como isso acontece na vida real
5. **Checklist de prevenção** — o que fazer para se proteger
6. **Exercícios práticos** — hands-on com respostas
7. **Quiz rápido** — 3 perguntas para fixar
8. **Referências** — links oficiais, ferramentas, CVEs

### Glossário

Não entendeu um termo? O [Glossário](extras/glossario.md) tem mais de 30 definições dos termos técnicos mais usados neste guia.

### Ferramentas

A página de [Ferramentas](extras/ferramentas.md) lista ferramentas gratuitas organizadas por categoria para você começar a praticar.

---

## Conceitos fundamentais de segurança web

Antes de mergulhar nas vulnerabilidades, é importante ter clareza sobre alguns conceitos:

### CIA Triad (Tríade CID)

```
Confidencialidade — Integridade — Disponibilidade
```

- **Confidencialidade**: apenas quem deve ver, vê
- **Integridade**: os dados não foram alterados sem autorização
- **Disponibilidade**: o sistema está acessível quando necessário

### Autenticação vs. Autorização

!!! tip "Confusão clássica"
    **Autenticação** = verificar **quem você é** (login com senha, biometria)

    **Autorização** = verificar **o que você pode fazer** (permissões, papéis)

    Muitas vulnerabilidades do OWASP Top 10 envolvem a confusão entre esses dois conceitos.

### Superfície de ataque

A **superfície de ataque** é o conjunto de todos os pontos onde um atacante pode tentar entrar em um sistema: formulários web, APIs, parâmetros de URL, cookies, cabeçalhos HTTP, uploads de arquivo, etc.

Quanto maior a superfície de ataque, maior o risco. Uma das melhores práticas de segurança é **minimizar a superfície de ataque**.

---

## A mentalidade do atacante

Para defender bem, você precisa pensar como um atacante.

!!! danger "Pense como um atacante (para defender melhor)"
    Um atacante faz perguntas como:

    - "O que acontece se eu mudar o ID de `1` para `2` na URL?"
    - "E se eu enviar um payload SQL no campo de busca?"
    - "Esse arquivo de configuração está acessível publicamente?"
    - "Qual a versão desse framework? Tem CVE conhecido?"

    Desenvolver essa mentalidade é o que separa um dev que escreve código que funciona
    de um dev que escreve código **seguro**.

---

## Referências

!!! info "Documentação oficial"
    - [OWASP Top 10:2025](https://owasp.org/Top10/2025/) — Documento oficial
    - [OWASP Foundation](https://owasp.org/) — Site principal
    - [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — Guias práticos por tema
    - [CWE/SANS Top 25](https://cwe.mitre.org/top25/) — Lista complementar de fraquezas de software
