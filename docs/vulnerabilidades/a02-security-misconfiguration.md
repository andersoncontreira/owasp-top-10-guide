---
title: "A02:2025 — Security Misconfiguration"
description: "Configuração incorreta de segurança: quando o sistema está montado de forma errada"
tags: [configuração, misconfiguration, crítico, a02]
---

# A02:2025 — Security Misconfiguration

<span style="background-color: #c0392b; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO CRÍTICO</span>

> **Analogia**: Você instalou uma porta blindada em sua casa, mas deixou a janela do banheiro aberta. A porta é ótima, mas a configuração do ambiente como um todo criou uma vulnerabilidade.

---

## O que é?

=== "🟢 Para leigos"
    Security Misconfiguration acontece quando um sistema está instalado corretamente, mas
    configurado de forma insegura. É diferente de um bug no código — é um problema de **como
    o sistema foi montado e configurado**.

    Exemplos do dia a dia:

    - Router de internet com senha padrão "admin/admin"
    - Câmera de segurança com acesso remoto habilitado e sem senha
    - Servidor de banco de dados acessível pela internet sem firewall

    Em aplicações web, é parecido: o software funciona, mas foi configurado de forma que
    expõe informações ou funcionalidades que não deveriam estar expostas.

=== "🟡 Desenvolvedor júnior"
    Security Misconfiguration inclui uma ampla gama de problemas:

    - **Funcionalidades desnecessárias habilitadas**: admin interfaces, debugging, portas abertas
    - **Contas padrão não alteradas**: admin/admin, sa/sa, root sem senha
    - **Mensagens de erro detalhadas em produção**: stack traces com caminhos de arquivo
    - **Headers de segurança ausentes**: sem HSTS, CSP, X-Frame-Options
    - **Permissões incorretas**: arquivos de configuração com permissão de leitura pública
    - **Software desatualizado**: versões com CVEs conhecidos em produção
    - **Cloud storage público**: S3 buckets sem autenticação

=== "🔴 Desenvolvedor sênior"
    Em 2025, Security Misconfiguration subiu para A02 porque o aumento de adoção de cloud,
    containers e IaC (Infrastructure as Code) multiplicou a superfície de ataque de configuração.

    Vetores críticos modernos:

    - **Kubernetes RBAC mal configurado**: service accounts com cluster-admin desnecessário
    - **Cloud IAM overpermission**: roles com `*:*` que nunca deveriam existir
    - **Secrets em variáveis de ambiente expostas**: `/proc/self/environ`, logs de CI
    - **CORS muito permissivo**: `Access-Control-Allow-Origin: *` com `credentials: true`
    - **Feature flags em produção**: endpoints de debug/test acessíveis
    - **Terraform/Bicep com defaults inseguros**: grupos de segurança `0.0.0.0/0`

---

## Código vulnerável vs. seguro

=== "❌ Flask em modo debug em produção"
    ```python
    from flask import Flask, jsonify

    app = Flask(__name__)

    # PROBLEMA: Debug mode expõe console interativo Python no navegador!
    # Qualquer pessoa pode executar código Python arbitrário no servidor
    # Também expõe stack traces completos com caminhos de arquivo
    app.run(debug=True, host='0.0.0.0')

    # Também errado: expor informações de erro para o usuário
    @app.errorhandler(500)
    def erro_interno(e):
        # Nunca retornar o erro completo para o cliente!
        return jsonify({'erro': str(e), 'stack': traceback.format_exc()}), 500
    ```

=== "✅ Configuração segura para produção"
    ```python
    import os
    from flask import Flask, jsonify
    import logging

    app = Flask(__name__)

    # Carrega configurações de variáveis de ambiente (nunca hardcode!)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['DEBUG'] = False  # Nunca True em produção
    app.config['TESTING'] = False

    # Configuração de logging: registra erros internamente, mas não expõe ao usuário
    logging.basicConfig(
        filename='/var/log/app/errors.log',
        level=logging.ERROR
    )

    @app.errorhandler(500)
    def erro_interno(e):
        # Loga o erro internamente
        app.logger.error(f"Erro interno: {e}")
        # Retorna mensagem genérica ao usuário — sem detalhes técnicos
        return jsonify({'erro': 'Ocorreu um erro interno. Tente novamente.'}), 500

    @app.errorhandler(404)
    def nao_encontrado(e):
        return jsonify({'erro': 'Recurso não encontrado'}), 404

    if __name__ == '__main__':
        # Em produção, use gunicorn ou uvicorn, não app.run()
        app.run(host='127.0.0.1', port=8000, debug=False)
    ```

=== "✅ Headers de segurança HTTP"
    ```python
    from flask import Flask
    from flask_talisman import Talisman

    app = Flask(__name__)

    # flask-talisman adiciona headers de segurança automaticamente
    Talisman(app,
        # HSTS: força HTTPS por 1 ano
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        # CSP: controla quais recursos podem ser carregados
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self'",
            'style-src': "'self' 'unsafe-inline'",
            'img-src': "'self' data:",
        },
        # Impede clickjacking
        frame_options='DENY',
        # Impede MIME sniffing
        content_type_options=True,
    )

    # Headers resultantes nas respostas:
    # Strict-Transport-Security: max-age=31536000; includeSubDomains
    # Content-Security-Policy: default-src 'self'; ...
    # X-Frame-Options: DENY
    # X-Content-Type-Options: nosniff
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — S3 bucket público"
    **Situação**: Uma empresa de saúde migra para AWS e um desenvolvedor cria um S3 bucket
    para armazenar laudos médicos digitalizados. Por pressa, deixa o bucket com acesso público
    para "facilitar os testes".

    **Ataque**:

    1. Atacante usa ferramentas como `s3scanner` para descobrir buckets públicos de empresas
    2. Encontra o bucket: `s3://clinica-xpto-laudos-prod`
    3. Lista todos os arquivos: `aws s3 ls s3://clinica-xpto-laudos-prod --no-sign-request`
    4. Baixa todos os laudos médicos com dados de pacientes

    **Consequência**: Violação grave da LGPD, exposição de dados sensíveis de saúde,
    multa de até 2% do faturamento, processo judicial e dano reputacional irreversível.

    **Caso real**: Em 2019, Capital One teve 100 milhões de registros expostos por
    misconfiguration em firewall de WAF no AWS. O atacante era ex-funcionário da AWS.

---

## Como prevenir

- [x] **Ambiente mínimo**: instalar apenas o necessário, desativar features não usadas
- [x] **Nenhuma senha padrão**: trocar todas as senhas padrão antes de ir para produção
- [x] **Revisão de configuração**: processo de revisão antes de cada deploy
- [ ] **Headers de segurança HTTP**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- [ ] **Mensagens de erro genéricas**: nunca expor stack traces ou detalhes técnicos
- [ ] **Cloud security posture**: AWS Config, Azure Security Center, GCP Security Command Center
- [ ] **Scan automático de misconfiguration**: Prowler, ScoutSuite, CloudSploit
- [ ] **Princípio do menor privilégio em IAM**: revisar permissões de cloud regularmente

---

## Exercícios práticos

!!! question "Exercício 1 — Encontre o problema"
    Analise esta configuração de Nginx e encontre os problemas de segurança:

    ```nginx
    server {
        listen 80;
        server_name exemplo.com;

        # Expõe versão do Nginx no header Server
        server_tokens on;

        location / {
            proxy_pass http://backend:8000;
        }

        # Expõe diretório de uploads
        location /uploads {
            autoindex on;
            root /var/www;
        }
    }
    ```

    ??? success "Ver resposta"
        **Problema 1**: `server_tokens on` — expõe a versão exata do Nginx no header `Server`.
        Atacante usa isso para buscar CVEs específicos daquela versão.

        **Problema 2**: `autoindex on` — lista todos os arquivos da pasta `/uploads`. Atacante pode
        baixar arquivos privados de outros usuários.

        **Problema 3**: Não há redirecionamento HTTP → HTTPS. Tráfego em texto puro.

        **Correção**:
        ```nginx
        server {
            listen 80;
            server_name exemplo.com;
            # Redireciona todo HTTP para HTTPS
            return 301 https://$host$request_uri;
        }

        server {
            listen 443 ssl;
            server_name exemplo.com;
            server_tokens off;  # Oculta versão do Nginx

            add_header Strict-Transport-Security "max-age=31536000" always;
            add_header X-Frame-Options DENY;
            add_header X-Content-Type-Options nosniff;

            location / {
                proxy_pass http://backend:8000;
            }

            location /uploads {
                # autoindex off por padrão — não precisa declarar
                # Adicionar autenticação antes de servir uploads
                auth_request /auth;
                root /var/www;
            }
        }
        ```

!!! question "Exercício 2 — Identifique configurações inseguras"
    Quais problemas você vê neste `docker-compose.yml`?

    ```yaml
    version: '3'
    services:
      db:
        image: mysql:8.0
        environment:
          MYSQL_ROOT_PASSWORD: root
          MYSQL_DATABASE: app
        ports:
          - "3306:3306"  # Expõe porta do MySQL para o host

      app:
        image: minha-app:latest
        environment:
          DATABASE_URL: mysql://root:root@db/app
          SECRET_KEY: mysecretkey123
          DEBUG: "true"
        ports:
          - "0.0.0.0:80:8000"
    ```

    ??? success "Ver solução modelo"
        **Problema 1**: Senha do MySQL `root` — fraca e igual ao username.

        **Problema 2**: Porta 3306 do MySQL exposta para o host e potencialmente para a internet.
        O banco de dados nunca deve ser acessível diretamente da internet.

        **Problema 3**: Credenciais hardcoded no docker-compose (deve usar secrets ou .env).

        **Problema 4**: `SECRET_KEY` fraca e hardcoded.

        **Problema 5**: `DEBUG: "true"` em produção.

        **Correção**:
        ```yaml
        version: '3.8'
        services:
          db:
            image: mysql:8.0
            environment:
              MYSQL_ROOT_PASSWORD_FILE: /run/secrets/db_root_password
              MYSQL_DATABASE: app
            # Sem ports: — banco não acessível externamente
            networks:
              - backend
            secrets:
              - db_root_password

          app:
            image: minha-app:latest
            env_file:
              - .env.production  # Variáveis em arquivo separado (não commitado)
            ports:
              - "127.0.0.1:80:8000"  # Apenas localhost, não 0.0.0.0
            networks:
              - backend
              - frontend

        networks:
          backend:
          frontend:

        secrets:
          db_root_password:
            external: true
        ```

!!! tip "Desafio extra — Hacksplaining"
    - [XML External Entities (XXE)](https://www.hacksplaining.com/exercises/xml-external-entities) — relacionado a misconfiguration de parsers XML
    - [Clickjacking](https://www.hacksplaining.com/exercises/click-jacking) — resolvido com header X-Frame-Options

---

## Quiz rápido

!!! example "Pergunta 1"
    Por que mensagens de erro detalhadas (com stack trace) são um problema de segurança?

    ??? note "Ver resposta"
        Stack traces revelam informações valiosas para o atacante: caminhos de arquivo no servidor
        (`/home/ubuntu/app/src/database.py`), nomes de bibliotecas e versões, estrutura interna
        do código, e às vezes até fragmentos de dados sensíveis. Isso facilita enormemente o
        reconhecimento (fase inicial de um ataque).

!!! example "Pergunta 2"
    O que é o header `Strict-Transport-Security` (HSTS) e por que ele é importante?

    ??? note "Ver resposta"
        HSTS instrui o navegador a **sempre usar HTTPS** para aquele domínio, pelo período especificado.
        Mesmo que o usuário digite `http://`, o navegador converte para `https://` antes de fazer
        a requisição. Isso previne ataques de downgrade (SSL stripping) onde um atacante tenta
        forçar a conexão para HTTP não criptografado.

!!! example "Pergunta 3"
    Por que é um problema de segurança ter o banco de dados MySQL acessível diretamente pela internet (porta 3306)?

    ??? note "Ver resposta"
        1. **Força bruta**: atacantes podem tentar credenciais diretamente no banco
        2. **CVEs**: vulnerabilidades do MySQL podem ser exploradas remotamente
        3. **Reconhecimento**: confirma que existe um banco MySQL e possivelmente sua versão
        4. **Bypass da aplicação**: se conseguir acesso ao banco, bypassa toda a lógica de autorização da aplicação

        O banco de dados deve estar em uma rede privada, acessível apenas pela aplicação.

---

## Referências

!!! info "Saiba mais"
    - [OWASP A02:2025 — Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
    - [OWASP Security Headers](https://owasp.org/www-project-secure-headers/)
    - [securityheaders.com](https://securityheaders.com/) — verifique os headers do seu site
    - [Prowler](https://github.com/prowler-cloud/prowler) — auditoria de segurança AWS/Azure/GCP
    - [Hacksplaining — Clickjacking](https://www.hacksplaining.com/exercises/click-jacking)
