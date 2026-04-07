---
title: "A07:2025 — Authentication Failures"
description: "Falhas de autenticação: quando o sistema não consegue verificar quem é você"
tags: [autenticação, login, jwt, mfa, crítico, a07]
---

# A07:2025 — Authentication Failures

<span style="background-color: #c0392b; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO CRÍTICO</span>

> **Analogia**: Um clube noturno que deixa qualquer pessoa entrar se ela souber dizer "sou sócio", sem verificar carteirinha, documento ou reconhecimento facial. Qualquer pessoa pode afirmar ser quem quiser.

---

## O que é?

=== "🟢 Para leigos"
    Autenticação é o processo de verificar **quem você é** — como mostrar sua carteira de
    identidade na entrada de um evento. Falhas de autenticação acontecem quando esse processo
    é fraco ou pode ser enganado.

    Exemplos do dia a dia:

    - Site que permite senhas fracas como "123456"
    - Login que não bloqueia após várias tentativas erradas (permite força bruta)
    - "Lembrar de mim" que guarda a senha em texto no cookie do navegador
    - Recuperação de senha por perguntas fáceis ("qual o nome do seu pet?")

=== "🟡 Desenvolvedor júnior"
    Authentication Failures incluem:

    - **Força bruta sem proteção**: sem rate limiting, sem CAPTCHA, sem bloqueio de conta
    - **Senhas fracas permitidas**: sem política de senha, sem verificação contra senhas comuns
    - **Session fixation**: atacante define o ID de sessão antes do login
    - **Session não invalidada no logout**: token JWT ainda válido após logout
    - **Credenciais na URL**: `?token=abc123` em logs de servidor
    - **Multi-factor authentication (MFA) ausente**: apenas senha como autenticação

=== "🔴 Desenvolvedor sênior"
    Vetores avançados em 2025:

    - **Credential stuffing**: listas de vazamentos anteriores testadas automaticamente (HaveIBeenPwned)
    - **JWT vulnerabilities**: `alg: none`, weak secrets, algorithm confusion (RS256 → HS256)
    - **OAuth misconfigurations**: open redirect em redirect_uri, CSRF no authorization flow
    - **WebAuthn bypass**: implementações incorretas de FIDO2/Passkeys
    - **SIM swapping**: atacar o número de telefone do usuário para bypassar SMS-MFA
    - **Session puzzling**: reutilizar mesma variável de sessão em contextos diferentes

---

## Código vulnerável vs. seguro

=== "❌ Login sem proteção"
    ```python
    @app.route('/login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']

        # Sem rate limiting — permite força bruta ilimitada
        usuario = db.find_user(username)

        # Sem hash de senha — comparação direta (catastrophic!)
        if usuario and usuario['password'] == password:
            # Session ID previsível
            session['user_id'] = usuario['id']
            session['username'] = username
            # Sem definir expiração da sessão
            return redirect('/dashboard')

        return "Login inválido", 401
    ```

=== "✅ Login seguro"
    ```python
    from flask_limiter import Limiter
    from flask_bcrypt import check_password_hash
    import secrets

    limiter = Limiter(key_func=get_remote_address)

    @app.route('/login', methods=['POST'])
    @limiter.limit("5 per minute")  # Rate limiting: 5 tentativas por minuto por IP
    def login():
        username = request.form['username'].strip().lower()
        password = request.form['password']

        # Tempo de resposta constante para evitar user enumeration por timing
        usuario = db.find_user(username)

        # check_password_hash tem tempo constante — evita timing attacks
        senha_valida = usuario and check_password_hash(usuario['password_hash'], password)

        if not senha_valida:
            # Log de tentativa falha para monitoramento
            logger.warning(f"Tentativa de login falha para usuário: {username} IP: {get_remote_address()}")
            # Resposta idêntica — não revela se o username existe
            return "Credenciais inválidas", 401

        # Verifica se MFA é necessário
        if usuario.get('mfa_enabled'):
            # Não cria sessão completa ainda — aguarda 2o fator
            session['pending_mfa_user'] = usuario['id']
            return redirect('/verificar-mfa')

        # Regenera o ID de sessão após login (previne session fixation)
        session.clear()
        session['user_id'] = usuario['id']
        session.permanent = True  # Aplica timeout configurado
        app.permanent_session_lifetime = timedelta(hours=8)

        return redirect('/dashboard')

    @app.route('/logout', methods=['POST'])
    def logout():
        # Invalida a sessão completamente
        session.clear()
        # Se usar JWT, adicionar à blacklist ou usar short-lived tokens
        return redirect('/login')
    ```

=== "✅ JWT seguro"
    ```python
    import jwt
    from datetime import datetime, timedelta
    import os

    # Chave secreta forte — mínimo 256 bits
    SECRET_KEY = os.environ['JWT_SECRET_KEY']

    def criar_token(user_id: int) -> str:
        """Cria JWT com expiração curta e claims mínimos."""
        payload = {
            'sub': str(user_id),      # subject — ID do usuário
            'iat': datetime.utcnow(), # issued at
            'exp': datetime.utcnow() + timedelta(minutes=15),  # expiração curta!
            'jti': secrets.token_hex(16)  # JWT ID único — permite blacklist
        }
        # Especificar algoritmo explicitamente — previne algorithm confusion
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    def verificar_token(token: str) -> dict:
        """Verifica e decodifica JWT de forma segura."""
        try:
            # algorithms=['HS256'] — lista explícita, nunca ['none']!
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=['HS256'],  # NUNCA usar ['none'] ou lista vazia
                options={'require': ['exp', 'sub', 'iat']}
            )

            # Verificar se token está na blacklist (logout)
            if is_token_blacklisted(payload['jti']):
                raise jwt.InvalidTokenError("Token revogado")

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError("Token expirado — faça login novamente")
        except jwt.InvalidTokenError as e:
            raise AuthError(f"Token inválido: {e}")
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — Credential Stuffing"
    **Situação**: Um serviço de streaming tem 5 milhões de usuários. Não tem MFA, não
    tem rate limiting robusto.

    **Ataque**:

    1. Em 2023, 2 bilhões de pares email/senha são vazados de vários serviços (Collection #1)
    2. Atacante baixa a lista e usa ferramenta automatizada (OpenBullet, SentryMBA)
    3. Testa 50.000 pares por hora contra o serviço de streaming
    4. Como muitas pessoas reutilizam senhas, ~2% das tentativas têm sucesso
    5. Com 50 milhões de tentativas, compromete ~1 milhão de contas

    **Consequência**: Contas vendidas em fóruns por $2-5 cada, acesso a cartões de crédito
    armazenados, dados pessoais dos usuários expostos.

    **Defesa**: MFA obrigatório ou opt-in, rate limiting por IP e por conta, detecção de
    login de localização incomum, verificação contra listas de senhas vazadas (k-anonymity da HaveIBeenPwned API).

---

## Como prevenir

- [x] **Rate limiting**: bloquear ou desacelerar após N tentativas falhas
- [x] **Hash correto de senhas**: bcrypt, Argon2, scrypt — nunca MD5 ou SHA para senhas
- [x] **Política de senhas**: mínimo de comprimento, verificação contra senhas comuns
- [ ] **MFA (Multi-Factor Authentication)**: TOTP (Google Authenticator), hardware keys (YubiKey)
- [ ] **Sessão regenerada após login**: prevenir session fixation
- [ ] **Logout seguro**: invalidar token/sessão completamente no servidor
- [ ] **Monitoramento de logins**: alertar usuário sobre login de novo dispositivo/localização
- [ ] **Passkeys/WebAuthn**: autenticação sem senha — mais seguro e conveniente

---

## Exercícios práticos

!!! question "Exercício 1 — Encontre as vulnerabilidades"
    Este código de verificação de token tem 3 problemas. Encontre-os:

    ```python
    def verificar_token(token):
        payload = jwt.decode(
            token,
            options={'verify_signature': False}  # Pula verificação de assinatura
        )

        if payload['role'] == 'admin':
            return True
        return False
    ```

    ??? success "Ver resposta"
        **Problema 1**: `verify_signature: False` — não verifica a assinatura do JWT!
        Qualquer pessoa pode criar um token com `role: admin` e ele será aceito.

        **Problema 2**: Sem especificar `algorithms`, aceita qualquer algoritmo incluindo `none`
        — vulnerabilidade conhecida em bibliotecas JWT antigas.

        **Problema 3**: Sem verificar a expiração (`exp`) — tokens expirados são aceitos para sempre.

        **Correção**:
        ```python
        def verificar_token(token):
            try:
                payload = jwt.decode(
                    token,
                    SECRET_KEY,
                    algorithms=['HS256'],
                    options={'require': ['exp', 'sub', 'role']}
                )
                return payload['role'] == 'admin'
            except jwt.InvalidTokenError:
                return False
        ```

!!! question "Exercício 2 — Implemente rate limiting"
    Adicione proteção contra força bruta a este endpoint de login Flask.

    ??? success "Ver solução modelo"
        ```python
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        import redis

        # Limiter com Redis para persistência entre restarts
        limiter = Limiter(
            app,
            key_func=get_remote_address,
            storage_uri="redis://localhost:6379",
            default_limits=["200 per day", "50 per hour"]
        )

        # Rastrear falhas por conta (além de por IP)
        def incrementar_falhas_login(username: str):
            r = redis.Redis()
            key = f"login_falhas:{username}"
            falhas = r.incr(key)
            r.expire(key, 900)  # 15 minutos de janela
            return falhas

        @app.route('/login', methods=['POST'])
        @limiter.limit("10 per minute")  # Rate limit por IP
        def login():
            username = request.form['username']
            password = request.form['password']

            # Verificar bloqueio por conta
            falhas = int(r.get(f"login_falhas:{username}") or 0)
            if falhas >= 5:
                return jsonify({'erro': 'Conta temporariamente bloqueada. Aguarde 15 minutos.'}), 429

            usuario = db.find_user(username)
            if not usuario or not check_password_hash(usuario['password_hash'], password):
                incrementar_falhas_login(username)
                return jsonify({'erro': 'Credenciais inválidas'}), 401

            # Sucesso — limpar contador de falhas
            r.delete(f"login_falhas:{username}")
            # ... criar sessão
        ```

!!! tip "Desafio extra — Hacksplaining"
    - [Broken Authentication](https://www.hacksplaining.com/exercises/broken-authentication)
    - [Session Fixation](https://www.hacksplaining.com/exercises/session-fixation)

---

## Quiz rápido

!!! example "Pergunta 1"
    O que é **credential stuffing** e como ele difere de força bruta?

    ??? note "Ver resposta"
        **Força bruta**: testar combinações aleatórias de senha (abc, abd, abe...).
        **Credential stuffing**: usar pares reais de email/senha de vazamentos anteriores.
        Credential stuffing é muito mais eficaz porque explora o hábito de reutilização de senhas — estudos mostram que 60-70% das pessoas reutilizam senhas em múltiplos serviços.

!!! example "Pergunta 2"
    Por que SMS é considerado o método MFA mais fraco, apesar de ser melhor que nenhum MFA?

    ??? note "Ver resposta"
        SMS tem vulnerabilidades conhecidas: SIM swapping (convencer a operadora a transferir o número), SS7 protocol vulnerabilities (protocolo de telefonia de 1975 sem autenticação), e phishing de OTP em tempo real. TOTP (Google Authenticator) ou hardware keys (YubiKey) são muito mais seguros. Dito isso, SMS MFA ainda é infinitamente melhor que nenhum MFA.

!!! example "Pergunta 3"
    O que é **Passkey** e como ele elimina vulnerabilidades de autenticação?

    ??? note "Ver resposta"
        Passkeys (WebAuthn/FIDO2) substituem senhas por pares de chaves criptográficas. A chave privada fica no dispositivo do usuário (protegida por biometria ou PIN local), a chave pública fica no servidor. Elimina phishing (a chave é vinculada ao domínio), credential stuffing (não há senha para vazar), e força bruta (chave privada nunca sai do dispositivo). Implementado pelo Google, Apple, Microsoft e está se tornando o padrão.

---

## Referências

!!! info "Saiba mais"
    - [OWASP A07:2025 — Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
    - [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
    - [OWASP Multi-Factor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
    - [Have I Been Pwned API](https://haveibeenpwned.com/API/v3) — verificar senhas em vazamentos
    - [Passkeys.dev](https://passkeys.dev/) — guia de implementação de Passkeys
    - [Hacksplaining — Broken Authentication](https://www.hacksplaining.com/exercises/broken-authentication)
