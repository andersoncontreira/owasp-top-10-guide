---
title: "A09:2025 — Security Logging and Alerting Failures"
description: "Falhas em logging e alertas: quando ataques passam despercebidos"
tags: [logging, monitoramento, alertas, médio, a09]
---

# A09:2025 — Security Logging and Alerting Failures

<span style="background-color: #f39c12; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO MÉDIO</span>

> **Analogia**: Uma loja tem câmeras de segurança, mas as fitas são sobrescritas a cada 24 horas, ninguém monitora as câmeras ao vivo, e quando ocorre um furto, não há como saber quando aconteceu ou quem foi o responsável.

---

## O que é?

=== "🟢 Para leigos"
    Logging é o registro de eventos que acontecem em um sistema — quem acessou o quê,
    quando, de onde, e se deu certo ou falhou.

    Falhas nessa área significam que quando algo errado acontece — uma invasão, um
    acesso indevido, uma tentativa de ataque — o sistema não registra, não detecta, ou
    não alerta ninguém. O ataque pode acontecer por meses sem que ninguém saiba.

    O caso mais famoso: a Equifax demorou **76 dias** para detectar o ataque que
    comprometeu 147 milhões de pessoas. Logs adequados teriam detectado em horas.

=== "🟡 Desenvolvedor júnior"
    Logging failures incluem:

    - **Eventos críticos não logados**: logins, falhas de autenticação, acesso a dados sensíveis
    - **Logs sem informações suficientes**: sem timestamp, sem IP, sem contexto
    - **Logs apenas locais**: se o servidor for comprometido, o atacante apaga os logs
    - **Sem alertas**: logs existem, mas ninguém é notificado em tempo real
    - **Dados sensíveis nos logs**: senhas, tokens, CPFs aparecem em logs — novo vetor de vazamento
    - **Logs não monitorados**: gerados mas nunca analisados

=== "🔴 Desenvolvedor sênior"
    Em 2025, logging & alerting é a diferença entre **Mean Time To Detect (MTTD)** de horas
    versus meses. MTTD médio global ainda está em torno de 200 dias.

    **Framework de logging de segurança:**

    - **O que logar**: eventos de autenticação, acesso a dados sensíveis, mudanças de permissão,
      erros de validação, atividade administrativa, chamadas a APIs externas
    - **O que NÃO logar**: senhas, tokens, PII completo (CPF, cartão), dados de saúde
    - **Structured logging**: JSON logs para correlação automática (ELK, Splunk, Datadog)
    - **Log integrity**: WORM storage, checksums, envio em tempo real para SIEM externo
    - **Alerting tiers**: crítico (imediato), alto (< 1h), médio (< 24h)

---

## Código vulnerável vs. seguro

=== "❌ Sem logging de segurança"
    ```python
    @app.route('/login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']

        usuario = db.find_user(username)

        if usuario and check_password_hash(usuario['password_hash'], password):
            session['user_id'] = usuario['id']
            # Nenhum log: não sabe quem logou, quando, de onde
            return redirect('/dashboard')

        # Nenhum log de falha: não detecta força bruta
        return "Credenciais inválidas", 401

    @app.route('/admin/usuarios/<int:id>/deletar', methods=['DELETE'])
    @admin_required
    def deletar_usuario(id):
        usuario = User.query.get_or_404(id)
        db.session.delete(usuario)
        db.session.commit()
        # Nenhum log de ação administrativa crítica!
        return jsonify({'ok': True})
    ```

=== "✅ Logging de segurança estruturado"
    ```python
    import logging
    import json
    from datetime import datetime
    from flask import request, g

    # Logger de segurança separado do logger de aplicação
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)

    # Handler que envia para SIEM em tempo real
    # Em produção: usar CloudWatch, Splunk, ELK, Datadog, etc.
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))  # JSON puro
    security_logger.addHandler(handler)

    def log_evento_seguranca(evento: str, nivel: str = 'INFO', **kwargs):
        """
        Log estruturado de evento de segurança.
        NUNCA incluir: senhas, tokens completos, dados de cartão, CPF completo.
        """
        entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'evento': evento,
            'nivel': nivel,
            'ip': request.remote_addr,
            'user_agent': request.user_agent.string[:200],  # Limitar tamanho
            'request_id': g.get('request_id', 'N/A'),
            **kwargs
        }
        security_logger.log(
            getattr(logging, nivel),
            json.dumps(entry)
        )

    @app.route('/login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']

        usuario = db.find_user(username)

        if usuario and check_password_hash(usuario['password_hash'], password):
            session['user_id'] = usuario['id']

            # Log de login bem-sucedido
            log_evento_seguranca(
                'LOGIN_SUCESSO',
                user_id=usuario['id'],
                username=username  # OK: username não é dado sensível
                # NUNCA logar a senha!
            )
            return redirect('/dashboard')

        # Log de falha de autenticação — crítico para detectar ataques
        log_evento_seguranca(
            'LOGIN_FALHA',
            nivel='WARNING',
            username=username,
            motivo='credenciais_invalidas'
        )
        return "Credenciais inválidas", 401

    @app.route('/admin/usuarios/<int:id>/deletar', methods=['DELETE'])
    @admin_required
    def deletar_usuario(id):
        usuario = User.query.get_or_404(id)

        # Log ANTES de executar — se a ação falhar, o log ainda existe
        log_evento_seguranca(
            'USUARIO_DELETADO',
            nivel='WARNING',
            admin_id=current_user.id,
            usuario_deletado_id=id,
            usuario_deletado_email=usuario.email
        )

        db.session.delete(usuario)
        db.session.commit()
        return jsonify({'ok': True})
    ```

=== "✅ Alertas automáticos"
    ```python
    import boto3  # AWS SNS para alertas
    from functools import wraps

    sns = boto3.client('sns')
    ALERTA_TOPIC = 'arn:aws:sns:us-east-1:123456789:alertas-seguranca'

    def alertar_seguranca(assunto: str, mensagem: str, prioridade: str = 'ALTO'):
        """Envia alerta para canal de segurança (Slack, email, PagerDuty)."""
        sns.publish(
            TopicArn=ALERTA_TOPIC,
            Subject=f"[{prioridade}] Alerta de Segurança: {assunto}",
            Message=mensagem
        )

    def detectar_forca_bruta():
        """Detecta padrão de força bruta e alerta."""
        redis_key = f"login_falha:{request.remote_addr}"
        falhas = int(r.get(redis_key) or 0)

        if falhas >= 10:  # 10 falhas em 5 minutos
            alertar_seguranca(
                "Possível ataque de força bruta",
                f"IP {request.remote_addr} teve {falhas} tentativas de login falhas.",
                prioridade='CRITICO'
            )
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — Equifax (2017)"
    **Situação**: Equifax, uma das maiores empresas de crédito dos EUA, com dados de
    147 milhões de americanos.

    **Ataque**:

    1. Atacantes exploram CVE-2017-5638 (Apache Struts) em maio de 2017
    2. Ficam na rede por **76 dias** sem serem detectados
    3. Acessam dados de 147 milhões de pessoas: nome, SSN, data de nascimento, endereço
    4. A empresa só descobre em julho de 2017 porque um certificado SSL expirou,
       o que desabilitou inspeção de tráfego criptografado — os alertas **existiam**
       mas estavam desabilitados!

    **Consequência**: Multa de $700 milhões, processo coletivo, queda de 35% nas ações,
    renúncia do CEO. Um dos maiores vazamentos de dados da história.

    **Lição**: Logging e alertas precisam ser **monitorados ativamente** — não basta configurar.

---

## Como prevenir

- [x] **Logar eventos de autenticação**: todos os logins, falhas, logouts, MFA
- [x] **Logar acesso a dados sensíveis**: quem acessou quais dados, quando
- [x] **Logs centralizados e imutáveis**: enviar para SIEM externo, não apenas arquivo local
- [ ] **Alertas em tempo real**: notificação imediata para eventos críticos
- [ ] **Correlação de eventos**: detectar padrões de ataque (força bruta, scanning)
- [ ] **Retenção adequada**: logs por pelo menos 1 ano (requisito LGPD/GDPR)
- [ ] **Nunca logar dados sensíveis**: senhas, tokens, cartões, CPF completo
- [ ] **Testar os alertas**: verificar regularmente que alertas estão funcionando

---

## Exercícios práticos

!!! question "Exercício 1 — O que deveria ser logado?"
    Para um sistema bancário com transferências PIX, liste 5 eventos críticos de segurança
    que deveriam ser logados, com quais dados incluir.

    ??? success "Ver resposta"
        1. **LOGIN**: `{evento: 'LOGIN', user_id, ip, timestamp, sucesso: true/false, motivo_falha}`
        2. **TRANSFERENCIA_PIX**: `{evento: 'PIX_ENVIADO', user_id, valor, chave_destino_hash, ip, timestamp}`
        3. **MUDANÇA_SENHA**: `{evento: 'SENHA_ALTERADA', user_id, ip, timestamp, motivo: 'usuario/admin'}`
        4. **DISPOSITIVO_NOVO**: `{evento: 'NOVO_DISPOSITIVO', user_id, device_fingerprint, ip, timestamp}`
        5. **LIMITE_EXCEDIDO**: `{evento: 'LIMITE_TRANSACAO_EXCEDIDO', user_id, valor_tentado, limite, timestamp}`

        **O que NÃO incluir**: número completo da conta de destino, chave PIX em texto puro, saldo atual.

!!! question "Exercício 2 — Encontre o problema de logging"
    Analise este código de log e identifique o problema:

    ```python
    @app.route('/redefinir-senha', methods=['POST'])
    def redefinir_senha():
        email = request.form['email']
        senha_nova = request.form['senha_nova']
        token = request.form['token']

        logger.info(f"Redefinindo senha: email={email}, token={token}, nova_senha={senha_nova}")

        if verificar_token(email, token):
            atualizar_senha(email, senha_nova)
            return "Senha redefinida"
        return "Token inválido", 400
    ```

    ??? success "Ver resposta"
        **Problema crítico**: o log inclui `token` e `nova_senha` em texto puro!

        - `token` é um segredo que permite redefinir a senha — se o log vazar, atacante pode usar
        - `nova_senha` é a senha do usuário em texto puro — cria novo vetor de vazamento

        **Correção**:
        ```python
        logger.info(
            "Tentativa de redefinição de senha",
            extra={
                'email': email,
                'token_prefix': token[:8] + '...',  # Apenas prefixo para debugging
                # NUNCA logar: token completo, senha_nova
            }
        )
        ```

!!! tip "Desafio extra"
    Configure uma stack básica de logging de segurança:

    1. Instale o **Elastic Stack** (Elasticsearch + Logstash + Kibana) localmente com Docker
    2. Configure sua aplicação para enviar logs em JSON para o Logstash
    3. Crie um dashboard no Kibana para visualizar tentativas de login falhas por IP
    4. Configure um alerta quando um IP tiver mais de 10 falhas em 5 minutos

---

## Quiz rápido

!!! example "Pergunta 1"
    Por que logar apenas em arquivo local no servidor é insuficiente?

    ??? note "Ver resposta"
        Se um atacante compromete o servidor, uma das primeiras ações é **apagar os logs** para remover evidências. Logs apenas locais são eliminados junto com o servidor comprometido. Logs devem ser enviados em tempo real para um sistema externo (SIEM, cloud) que o atacante não consiga acessar facilmente. Além disso, logs centralizados permitem correlacionar eventos de múltiplos servidores.

!!! example "Pergunta 2"
    Por que é perigoso incluir senhas, tokens ou dados de cartão em logs?

    ??? note "Ver resposta"
        Logs são frequentemente acessados por mais pessoas e sistemas do que a aplicação principal: desenvolvedores, suporte, ferramentas de monitoramento, pipelines de análise. Logs são frequentemente armazenados por longos períodos e em locais com controle de acesso menos rigoroso. Um vazamento de logs expõe todos os dados sensíveis registrados. Regras de conformidade (LGPD, PCI DSS) explicitamente proíbem armazenar dados de cartão em logs.

!!! example "Pergunta 3"
    O que é SIEM e qual sua função na segurança?

    ??? note "Ver resposta"
        SIEM (Security Information and Event Management) é um sistema que coleta, normaliza e correlaciona logs de segurança de múltiplas fontes (firewalls, aplicações, servidores, cloud) em tempo real. Ele aplica regras de detecção para identificar padrões de ataque, gera alertas e suporta investigações forenses. Exemplos: Splunk, IBM QRadar, Microsoft Sentinel, Elastic SIEM. É o equivalente da central de monitoramento de câmeras de um banco — não apenas grava, mas analisa e alerta.

---

## Referências

!!! info "Saiba mais"
    - [OWASP A09:2025 — Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
    - [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
    - [OWASP Application Logging Vocabulary](https://owasp.org/www-project-security-logging/)
    - [Elastic Stack (ELK)](https://www.elastic.co/elastic-stack)
    - [CVE-2017-5638 — Apache Struts (Equifax breach)](https://nvd.nist.gov/vuln/detail/cve-2017-5638)
