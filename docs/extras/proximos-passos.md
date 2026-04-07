---
title: "Próximos Passos em Segurança Web"
description: "Certificações, labs, roadmap e recursos para avançar na carreira em segurança"
---

# Próximos Passos

Você estudou o OWASP Top 10:2025. E agora? Este guia mostra como aprofundar seu conhecimento e avançar na carreira em segurança.

---

## Certificações Recomendadas

### Por nível de experiência

=== "🟢 Iniciante"
    | Certificação | Entidade | Foco | Custo estimado |
    |-------------|---------|------|---------------|
    | **CompTIA Security+** | CompTIA | Fundamentos de segurança | ~$400 USD |
    | **CEH (Certified Ethical Hacker)** | EC-Council | Hacking ético | ~$1.200 USD |
    | **eJPT** | INE/eLearnSecurity | Pentest júnior, prático | ~$200 USD |
    | **Google Cybersecurity Certificate** | Google/Coursera | Fundamentos práticos | ~$50/mês |

    !!! tip "Dica"
        O **eJPT** é o melhor custo-benefício para iniciantes que querem começar com pentest.
        O exame é 100% prático — você precisa comprometer máquinas reais, não responder questões teóricas.

=== "🟡 Intermediário"
    | Certificação | Entidade | Foco | Custo estimado |
    |-------------|---------|------|---------------|
    | **OSCP** (Offensive Security Certified Professional) | OffSec | Pentest prático | ~$1.500 USD |
    | **GWEB** (GIAC Web Application Penetration Tester) | GIAC/SANS | Pentest web | ~$8.000 USD |
    | **BSCP** (Burp Suite Certified Practitioner) | PortSwigger | Web hacking | Grátis (labs) + ~$99 USD |
    | **PNPT** (Practical Network Penetration Tester) | TCM Security | Pentest de rede | ~$400 USD |
    | **Web Application Hacker's Handbook** | Leitura | Web security | ~$50 USD |

    !!! tip "Dica"
        O **OSCP** é o mais reconhecido na indústria. Exige dedicação intensa (90 dias de lab),
        mas abre muitas portas. O **BSCP** da PortSwigger é excelente para quem quer se especializar em web.

=== "🔴 Avançado"
    | Certificação | Entidade | Foco | Custo estimado |
    |-------------|---------|------|---------------|
    | **OSEP** (Offensive Security Experienced Penetration Tester) | OffSec | Evasão e AD | ~$1.500 USD |
    | **OSED** (Offensive Security Exploit Developer) | OffSec | Desenvolvimento de exploits | ~$1.500 USD |
    | **GXPN** (GIAC Exploit Researcher) | GIAC/SANS | Pesquisa de exploits | ~$9.000 USD |
    | **CISSP** | (ISC)² | Gestão de segurança | ~$700 USD |

---

## Labs Gratuitos para Praticar

### Aplicações vulneráveis locais

```bash
# OWASP Juice Shop — 100+ desafios, excelente para iniciantes e avançados
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop
# Acesse: http://localhost:3000

# DVWA — clássico, múltiplos níveis de dificuldade
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa
# Acesse: http://localhost

# WebGoat — lições interativas da OWASP
docker pull webgoat/webgoat
docker run -d -p 8080:8080 webgoat/webgoat
# Acesse: http://localhost:8080/WebGoat
```

### Plataformas online

| Plataforma | Custo | Nível | Destaque |
|-----------|-------|-------|----------|
| **PortSwigger Web Security Academy** | Grátis | Todos | Melhor conteúdo de web hacking disponível |
| **Hacksplaining** | Grátis | Iniciante | Formato interativo e gamificado |
| **TryHackMe** | Freemium | Iniciante/Médio | Trilhas guiadas, ótimo para começar |
| **HackTheBox** | Freemium | Médio/Avançado | Máquinas reais, comunidade ativa |
| **PentesterLab** | Freemium | Todos | Foco em web, com certificado |
| **Root-Me** | Grátis | Todos | +400 desafios variados |
| **VulnHub** | Grátis | Médio/Avançado | VMs para download e prática offline |

---

## Roadmap de Estudos

### Fase 1 — Fundamentos (3-6 meses)

```
Redes → HTTP/HTTPS → Linux básico → Python básico
         ↓
OWASP Top 10 (este guia!)
         ↓
DVWA + Juice Shop (prática)
         ↓
TryHackMe — trilha "Jr Penetration Tester"
```

### Fase 2 — Especialização em Web (3-6 meses)

```
PortSwigger Web Academy (todos os módulos)
         ↓
Burp Suite — dominar intercepção, scanner, repeater, intruder
         ↓
CTFs focados em web (HackTheBox, PicoCTF)
         ↓
Bug Bounty (HackerOne, Bugcrowd) — começo com programas com escopo amplo
```

### Fase 3 — Pentest Profissional (6-12 meses)

```
Metodologias: PTES, OWASP Testing Guide
         ↓
Relatórios: como documentar e comunicar vulnerabilidades
         ↓
OSCP ou BSCP (certificação prática)
         ↓
Especialização: mobile, cloud, API security, hardware
```

---

## Áreas de Especialização

Após dominar os fundamentos, considere se especializar em:

=== "Web & API Security"
    - GraphQL security
    - OAuth/OIDC vulnerabilities
    - WebSocket attacks
    - API fuzzing e testing
    - **Recurso**: PortSwigger Web Security Academy

=== "Cloud Security"
    - AWS/Azure/GCP security
    - Container security (Docker/Kubernetes)
    - Infrastructure as Code security
    - Cloud SIEM e detecção
    - **Recurso**: CloudGoat (Rhino Security Labs)

=== "AppSec / DevSecOps"
    - SAST/DAST em pipelines CI/CD
    - Threat modeling
    - Security code review
    - SBOM e supply chain
    - **Recurso**: OWASP SAMM, BSIMM

=== "Red Team / Pentest"
    - Active Directory attacks
    - Evasão de EDR/AV
    - Command & Control (C2)
    - Physical security
    - **Recurso**: OSCP, CRTE

=== "Malware & Exploit Development"
    - Engenharia reversa (Ghidra, IDA)
    - Desenvolvimento de exploits (buffer overflow, heap)
    - Análise de malware
    - **Recurso**: OSED, Azeria Labs

---

## Bug Bounty — Ganhando Experiência (e Dinheiro)

Bug bounty é a prática de reportar vulnerabilidades a empresas em troca de recompensas.

### Plataformas principais

| Plataforma | Tipo | URL |
|-----------|------|-----|
| **HackerOne** | Privada e pública | hackerone.com |
| **Bugcrowd** | Privada e pública | bugcrowd.com |
| **Intigriti** | Europeia, focada em privacidade | intigriti.com |
| **Synack** | Vetted, melhor pagamento | synack.com |

### Dicas para começar

!!! tip "Como começar no Bug Bounty"
    1. **Comece com escopo amplo**: programas como HackerOne do governo dos EUA (h1.gov) têm escopo grande
    2. **Foque em um tipo de vulnerabilidade**: torne-se especialista em IDOR ou XSS ou SSRF, não em tudo ao mesmo tempo
    3. **Leia relatórios públicos**: o HackerOne tem disclosures públicos — leia centenas para entender os padrões
    4. **Documente bem**: a qualidade do relatório é tão importante quanto encontrar a vulnerabilidade
    5. **Seja ético**: nunca extrapole o escopo, reporte de forma responsável, aguarde o fix antes de divulgar

---

## Comunidade e Recursos

### Podcasts

- **Darknet Diaries** — histórias reais de hacking e crimes cibernéticos
- **Security Now** — segurança técnica semanal com Steve Gibson
- **Risky Business** — notícias de segurança para profissionais
- **Smashing Security** — notícias de segurança de forma leve e divertida (em inglês)

### Canais YouTube

- **John Hammond** — CTFs, malware analysis, tutorial
- **IppSec** — walkthroughs de HackTheBox (aprenda com ele antes de ver a resposta)
- **TCM Security** — cursos e tutoriais de pentest
- **LiveOverflow** — conteúdo técnico profundo sobre hacking
- **NetworkChuck** — networking e segurança para iniciantes

### Livros recomendados

| Livro | Autor | Nível |
|-------|-------|-------|
| The Web Application Hacker's Handbook | Stuttard & Pinto | Intermediário |
| Hacking: The Art of Exploitation | Jon Erickson | Avançado |
| The Hacker Playbook 3 | Peter Kim | Intermediário |
| Real World Bug Hunting | Peter Yaworski | Iniciante/Médio |
| Bug Bounty Bootcamp | Vickie Li | Iniciante/Médio |

### Newsletters

- **tl;dr sec** — resumo semanal de segurança
- **Risky.Biz** — notícias de segurança para profissionais
- **CISA Alerts** — alertas oficiais do governo dos EUA sobre ameaças ativas

---

## Ética e Legalidade

!!! danger "Importante — Sempre atue legalmente"
    Todo o conhecimento deste guia deve ser usado de forma **ética e legal**:

    - **Nunca** teste sistemas sem autorização explícita e por escrito
    - Em Brasil, ataques a sistemas são crime (Lei 12.737/2012 — Lei Carolina Dieckmann, e Marco Civil da Internet)
    - Bug bounty não substitui autorização — leia o escopo cuidadosamente
    - Em caso de dúvida, pergunte ao responsável pelo sistema

    A linha entre segurança ofensiva e crime está na **autorização**. Com autorização, é pentest. Sem autorização, é crime.

!!! tip "Disclosure responsável"
    Se você encontrar uma vulnerabilidade em um sistema sem programa de bug bounty:

    1. Documente a vulnerabilidade sem explorá-la além do necessário para confirmar
    2. Contate o responsável pelo sistema (email de segurança, CERT, ou contato geral)
    3. Dê um prazo razoável para correção (geralmente 90 dias — padrão Google Project Zero)
    4. Após o fix, você pode fazer divulgação pública (coordinated disclosure)
