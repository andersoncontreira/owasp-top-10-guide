# OWASP Top 10:2025 — Guia Didático

Guia educacional completo sobre as 10 principais vulnerabilidades web de 2025, construído com MkDocs e o tema Material.

## Requisitos

- Python 3.10+
- pip

## Instalação

```bash
pip install -r requirements.txt
```

## Rodando localmente

```bash
mkdocs serve
```

Acesse em: http://localhost:8000

## Gerando o site estático

```bash
mkdocs build
```

O site é gerado na pasta `site/` e pode ser hospedado em qualquer servidor estático (GitHub Pages, Netlify, etc.).

## Estrutura do projeto

```
owasp-top-10-guide/
├── mkdocs.yml                  # Configuração do MkDocs
├── requirements.txt            # Dependências Python
├── README.md                   # Este arquivo
└── docs/
    ├── index.md                # Página inicial
    ├── introducao.md           # Introdução ao OWASP
    ├── vulnerabilidades/       # As 10 vulnerabilidades
    │   ├── a01-broken-access-control.md
    │   ├── a02-security-misconfiguration.md
    │   ├── a03-software-supply-chain-failures.md
    │   ├── a04-cryptographic-failures.md
    │   ├── a05-injection.md
    │   ├── a06-insecure-design.md
    │   ├── a07-authentication-failures.md
    │   ├── a08-software-data-integrity-failures.md
    │   ├── a09-security-logging-alerting-failures.md
    │   └── a10-mishandling-exceptional-conditions.md
    └── extras/
        ├── glossario.md
        ├── ferramentas.md
        └── proximos-passos.md
```

## Aviso

Este guia é exclusivamente para fins **educacionais**. O conhecimento aqui apresentado deve ser usado para **defender** sistemas, nunca para atacar sistemas sem autorização explícita.

## Referências

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP Foundation](https://owasp.org/)
