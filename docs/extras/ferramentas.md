---
title: "Ferramentas de Segurança Web"
description: "Arsenal de ferramentas gratuitas para testar e melhorar a segurança de aplicações web"
---

# Ferramentas de Segurança Web

Ferramentas gratuitas e open source organizadas por categoria. Todas são usadas profissionalmente e têm ampla documentação disponível.

!!! warning "Use apenas em ambientes autorizados"
    Todas as ferramentas abaixo podem ser usadas para fins ofensivos e defensivos. Use **apenas em sistemas que você tem autorização explícita para testar**. Usar essas ferramentas em sistemas de terceiros sem permissão é ilegal.

---

## DAST — Dynamic Application Security Testing

Ferramentas que testam aplicações **em execução**, simulando ataques externos.

| Ferramenta | Descrição | Uso Principal |
|-----------|-----------|---------------|
| **OWASP ZAP** | Scanner web open source, mantido pela OWASP | Scan automático e manual de aplicações web |
| **Burp Suite Community** | Proxy de intercepção HTTP, padrão da indústria | Análise e modificação de requisições HTTP |
| **Nikto** | Scanner de vulnerabilidades em servidores web | Detecção de configurações inseguras e versões |
| **Gobuster** | Brute force de diretórios e arquivos web | Descoberta de endpoints ocultos |
| **ffuf** | Fuzzer de requisições HTTP rápido | Descoberta de parâmetros e caminhos |

---

## SAST — Static Application Security Testing

Ferramentas que analisam o **código-fonte** sem executar a aplicação.

| Ferramenta | Linguagem | Descrição |
|-----------|-----------|-----------|
| **Bandit** | Python | Analisa código Python em busca de problemas de segurança comuns |
| **Semgrep** | Multi-linguagem | Análise estática com regras customizáveis, muito rápido |
| **SonarQube Community** | Multi-linguagem | Plataforma completa de qualidade e segurança de código |
| **CodeQL** | Multi-linguagem | Análise semântica de código, usado pelo GitHub |
| **ESLint (plugins de segurança)** | JavaScript | Com plugins como `eslint-plugin-security` |
| **Gosec** | Go | Verificador de segurança para código Go |
| **Bearer** | Multi-linguagem | Focado em proteção de dados sensíveis (PII) |

---

## Análise de Dependências

Ferramentas para detectar **vulnerabilidades em bibliotecas e dependências**.

| Ferramenta | Ecossistema | Descrição |
|-----------|-------------|-----------|
| **npm audit** | Node.js | Auditoria de dependências npm, integrado ao npm |
| **pip-audit** | Python | Verifica pacotes Python contra bancos de vulnerabilidades |
| **OWASP Dependency-Check** | Java/Multi | Identifica dependências com CVEs conhecidos |
| **Trivy** | Containers/Multi | Scanner de vulnerabilidades para imagens Docker e repositórios |
| **Snyk (free tier)** | Multi-linguagem | Monitoramento contínuo de dependências com notificações |
| **Dependabot** | GitHub | Atualizações automáticas de dependências com PRs |
| **Grype** | Containers | Scanner de vulnerabilidades de containers da Anchore |

---

## Testes de Injeção

Ferramentas especializadas em **SQL injection, XSS e similares**.

| Ferramenta | Tipo | Descrição |
|-----------|------|-----------|
| **SQLMap** | SQL Injection | Automação completa de detecção e exploração de SQL injection |
| **XSSer** | XSS | Framework para detecção e exploração de Cross-Site Scripting |
| **Commix** | Command Injection | Automatização de testes de command injection |
| **NoSQLMap** | NoSQL Injection | Testes de injection para MongoDB, CouchDB, etc. |
| **Ghauri** | SQL Injection | Alternativa moderna ao SQLMap, mais rápido em alguns cenários |

---

## Autenticação e Senhas

Ferramentas para testar **robustez de autenticação**.

| Ferramenta | Descrição |
|-----------|-----------|
| **Hydra** | Brute force de protocolos de autenticação (HTTP, SSH, FTP, etc.) |
| **Medusa** | Similar ao Hydra, paralelizado |
| **John the Ripper** | Crack de hashes de senhas offline |
| **Hashcat** | Crack de hashes com suporte a GPU — extremamente rápido |
| **HaveIBeenPwned** | API para verificar se senhas/emails estão em vazamentos |
| **CeWL** | Gerador de wordlists a partir de sites (para testes de força bruta) |

---

## Análise de Tráfego e Rede

| Ferramenta | Descrição |
|-----------|-----------|
| **Wireshark** | Analisador de pacotes de rede, captura tráfego em tempo real |
| **mitmproxy** | Proxy MITM interativo em Python, bom para scripts |
| **tcpdump** | Captura de pacotes via linha de comando |
| **nmap** | Scanner de portas e serviços de rede |
| **Masscan** | Scanner de portas ultrarrápido |

---

## Cloud Security

| Ferramenta | Cloud | Descrição |
|-----------|-------|-----------|
| **Prowler** | AWS/Azure/GCP | Auditoria de segurança e conformidade em cloud |
| **ScoutSuite** | Multi-cloud | Auditoria de segurança multi-cloud |
| **CloudSploit** | Multi-cloud | Scanner de configurações inseguras em cloud |
| **Pacu** | AWS | Framework de exploração de AWS (para pentest) |
| **S3Scanner** | AWS | Descoberta de S3 buckets expostos |
| **Checkov** | IaC | Análise estática de Terraform, CloudFormation, Kubernetes |

---

## Análise de Containers e Kubernetes

| Ferramenta | Descrição |
|-----------|-----------|
| **Trivy** | Scanner de imagens Docker, sistemas de arquivos e repositórios |
| **Falco** | Runtime security para containers — detecta comportamento suspeito |
| **kube-bench** | Verifica conformidade do Kubernetes com CIS Benchmark |
| **kube-hunter** | Testes de penetração em clusters Kubernetes |
| **Cosign** | Assinatura e verificação de imagens de containers |
| **Hadolint** | Linter de Dockerfile para boas práticas de segurança |

---

## Labs e Ambientes de Prática

Aplicações intencionalmente vulneráveis para aprendizado seguro.

| Aplicação | Descrição | Vulnerabilidades |
|-----------|-----------|-----------------|
| **DVWA** (Damn Vulnerable Web App) | Aplicação PHP/MySQL vulnerável por design | SQL injection, XSS, CSRF, File Upload, etc. |
| **WebGoat** | Aplicação Java da OWASP com lições interativas | Todas as categorias OWASP |
| **Juice Shop** | Aplicação Node.js da OWASP com 100+ desafios | OWASP Top 10 completo |
| **HackTheBox** | Plataforma com máquinas virtuais para pentest | Todos os tipos |
| **TryHackMe** | Plataforma guiada, ideal para iniciantes | Todos os tipos |
| **VulnHub** | Máquinas virtuais para download e prática local | Todos os tipos |
| **PentesterLab** | Exercícios web com certificação | Web application security |
| **Hacksplaining** | Tutoriais interativos e gamificados | OWASP Top 10 e mais |
| **PortSwigger Web Academy** | Labs do criador do Burp Suite | Web application security |
| **Root-Me** | Plataforma francesa com desafios variados | CTF e web security |

---

## Verificação de Configuração

| Ferramenta | Descrição |
|-----------|-----------|
| **SSL Labs** | Testa configuração TLS de um servidor web |
| **securityheaders.com** | Verifica headers de segurança HTTP |
| **Mozilla Observatory** | Análise completa de segurança de sites |
| **testssl.sh** | Script para testar configuração SSL/TLS localmente |
| **CIS-CAT** | Verificação de conformidade com CIS Benchmarks |

---

## Monitoramento e SIEM

| Ferramenta | Descrição |
|-----------|-----------|
| **Elastic Stack (ELK)** | Elasticsearch + Logstash + Kibana — stack completa de logging |
| **Wazuh** | SIEM open source com agentes de endpoint |
| **Graylog** | Gerenciamento centralizado de logs |
| **OSSEC** | Sistema de detecção de intrusão baseado em host |
| **Zeek** | Framework de análise de tráfego de rede |

---

## Integração em Pipeline CI/CD

```yaml
# Exemplo: pipeline de segurança no GitHub Actions
name: Security Scan

on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: SAST com Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: p/owasp-top-ten

  dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Audit de dependências Python
        run: pip-audit -r requirements.txt

  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build e scan com Trivy
        run: |
          docker build -t app:test .
          trivy image --exit-code 1 --severity HIGH,CRITICAL app:test
```

!!! tip "Por onde começar?"
    1. **Iniciante**: comece pelo [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) localmente com Docker
    2. **Intermediário**: configure OWASP ZAP e analise seus próprios projetos
    3. **Avançado**: use Burp Suite Professional + SQLMap em um programa de bug bounty
