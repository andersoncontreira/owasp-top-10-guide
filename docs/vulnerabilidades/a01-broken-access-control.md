---
title: "A01:2025 — Broken Access Control"
description: "Controle de acesso quebrado: quando usuários fazem mais do que deveriam"
tags: [acesso, autorização, crítico, a01]
---

# A01:2025 — Broken Access Control

<span style="background-color: #c0392b; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO CRÍTICO</span>

> **Analogia**: Imagine um prédio onde todas as portas têm fechadura, mas o segurança dá a chave mestra para qualquer pessoa que pedir. De que adianta a fechadura?

---

## O que é?

=== "🟢 Para leigos"
    Você já percebeu que ao acessar seu perfil em um site, a URL é algo como `/perfil/123`?

    Agora imagine que alguém troca esse `123` por `124` e consegue ver **o perfil de outra pessoa**.
    Isso é Broken Access Control — o sistema deveria verificar se você tem permissão para ver
    aquele perfil, mas não verifica.

    É como se um shopping tivesse câmeras em todos os corredores, mas as portas dos vestiários
    ficassem destrancadas. A câmera está lá, mas não resolve o problema.

=== "🟡 Desenvolvedor júnior"
    Broken Access Control acontece quando o sistema falha em **verificar se o usuário autenticado
    tem permissão** para acessar um recurso ou executar uma ação.

    Problemas comuns:

    - **IDOR (Insecure Direct Object Reference)**: expor IDs internos na URL sem verificar propriedade
    - **Privilege escalation vertical**: um usuário comum acessar funcionalidades de admin
    - **Privilege escalation horizontal**: um usuário acessar dados de outro usuário do mesmo nível
    - **Missing function-level access control**: endpoints de API sem verificação de permissão

    A autenticação verifica *quem você é*. O controle de acesso verifica *o que você pode fazer*.
    Muitos sistemas implementam a autenticação, mas esquecem o controle de acesso.

=== "🔴 Desenvolvedor sênior"
    Broken Access Control é consistentemente o **#1 do OWASP** porque é sistêmico: afeta toda
    a aplicação e não há uma única solução técnica.

    Vetores de ataque principais:

    - **IDOR em APIs REST**: `GET /api/orders/12345` sem validar que o pedido pertence ao usuário
    - **JWT manipulation**: alterar o payload do token sem verificação de assinatura
    - **Path traversal**: `../../etc/passwd` em parâmetros de arquivo
    - **HTTP verb tampering**: servidor aceita `DELETE` onde só deveria aceitar `GET`
    - **CORS misconfiguration**: `Access-Control-Allow-Origin: *` em APIs que retornam dados sensíveis
    - **Mass assignment**: frameworks ORM que mapeiam automaticamente campos do request para o modelo

    A defesa requer **deny by default** implementado em cada camada: aplicação, API gateway,
    banco de dados (RLS — Row Level Security) e infraestrutura.

---

## Código vulnerável vs. seguro

=== "❌ Código vulnerável"
    ```python
    from flask import Flask, jsonify, request
    from database import get_order_by_id

    app = Flask(__name__)

    @app.route('/api/orders/<int:order_id>')
    def get_order(order_id):
        # PROBLEMA: busca o pedido apenas pelo ID
        # Não verifica se o pedido pertence ao usuário logado!
        order = get_order_by_id(order_id)

        if not order:
            return jsonify({'error': 'Pedido não encontrado'}), 404

        # Qualquer usuário logado pode ver qualquer pedido
        # Basta mudar o número na URL: /api/orders/1, /api/orders/2...
        return jsonify(order)
    ```

=== "✅ Código corrigido"
    ```python
    from flask import Flask, jsonify, request
    from flask_jwt_extended import jwt_required, get_jwt_identity
    from database import get_order_by_id

    app = Flask(__name__)

    @app.route('/api/orders/<int:order_id>')
    @jwt_required()  # Garante que o usuário está autenticado
    def get_order(order_id):
        # Obtém o ID do usuário a partir do token JWT
        current_user_id = get_jwt_identity()

        # Busca o pedido pelo ID
        order = get_order_by_id(order_id)

        if not order:
            return jsonify({'error': 'Pedido não encontrado'}), 404

        # CORREÇÃO: verifica se o pedido pertence ao usuário logado
        if order['user_id'] != current_user_id:
            # Retorna 403 Forbidden, não 401 Unauthorized
            # 403 = você está autenticado, mas não tem permissão
            return jsonify({'error': 'Acesso negado'}), 403

        return jsonify(order)
    ```

=== "🗄️ SQL com Row Level Security"
    ```sql
    -- Alternativa: usar Row Level Security no PostgreSQL
    -- Isso garante controle de acesso no nível do banco de dados

    -- Habilita RLS na tabela de pedidos
    ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

    -- Cria uma política: usuários só veem seus próprios pedidos
    CREATE POLICY orders_isolation_policy ON orders
        FOR ALL
        TO app_user
        USING (user_id = current_setting('app.current_user_id')::INTEGER);

    -- No código Python, antes de qualquer query:
    -- db.execute("SET app.current_user_id = %s", [current_user_id])
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — IDOR em e-commerce"
    **Situação**: Uma loja online exibe pedidos com URLs como `/minha-conta/pedidos/78432`

    **Ataque**:

    1. Atacante faz login com sua conta legítima
    2. Acessa seu próprio pedido: `/minha-conta/pedidos/78432`
    3. Começa a iterar: `/minha-conta/pedidos/78431`, `78430`, `78429`...
    4. Consegue ver nome completo, endereço, CPF e itens comprados de outros clientes
    5. Automatiza com um script que varre milhares de IDs em minutos

    **Consequência**: Vazamento de dados pessoais de todos os clientes da loja,
    violação da LGPD, multa e dano reputacional severo.

    **Caso real**: Em 2019, a T-Mobile expôs dados de clientes por exatamente esse tipo
    de falha em sua API — apenas mudando o número de telefone na requisição.

---

## Como prevenir

- [x] **Deny by default**: negar acesso por padrão e liberar explicitamente
- [x] **Verificar propriedade**: sempre confirmar que o recurso pertence ao usuário autenticado
- [x] **Usar UUIDs**: preferir UUIDs aleatórios a IDs sequenciais (dificulta IDOR, mas não resolve)
- [ ] **Testes automatizados de controle de acesso**: incluir nos testes unitários e de integração
- [ ] **Row Level Security**: implementar RLS no banco de dados como segunda camada
- [ ] **Rate limiting**: limitar requisições para dificultar enumeração automática
- [ ] **Logging de tentativas negadas**: monitorar acessos negados para detectar ataques
- [ ] **Revisão de código focada em autorização**: incluir checklist de controle de acesso em code review

---

## Exercícios práticos

!!! question "Exercício 1 — Encontre o problema"
    Analise o código abaixo e identifique a vulnerabilidade de controle de acesso:

    ```python
    @app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
    @login_required
    def delete_user(user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'Usuário deletado com sucesso'})
    ```

    ??? success "Ver resposta"
        **Problema**: O decorator `@login_required` verifica apenas se o usuário está *autenticado*,
        mas não verifica se ele tem **permissão de administrador** para deletar outros usuários.

        Qualquer usuário logado consegue deletar qualquer conta acessando:
        `POST /admin/users/1/delete`

        **Correção**:
        ```python
        @app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
        @login_required
        @admin_required  # Verifica se o usuário tem papel de administrador
        def delete_user(user_id):
            # Proteção extra: não permitir que admin delete a si mesmo
            if user_id == current_user.id:
                return jsonify({'error': 'Não é possível deletar sua própria conta'}), 400

            user = User.query.get_or_404(user_id)
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'Usuário deletado com sucesso'})
        ```

!!! question "Exercício 2 — Corrija o código"
    Este endpoint de API retorna documentos de uma empresa. Corrija a vulnerabilidade:

    ```javascript
    // Node.js / Express
    app.get('/api/documents/:documentId', authenticateToken, async (req, res) => {
      const document = await Document.findById(req.params.documentId);

      if (!document) {
        return res.status(404).json({ error: 'Documento não encontrado' });
      }

      res.json(document);
    });
    ```

    ??? success "Ver solução modelo"
        ```javascript
        app.get('/api/documents/:documentId', authenticateToken, async (req, res) => {
          const document = await Document.findById(req.params.documentId);

          if (!document) {
            return res.status(404).json({ error: 'Documento não encontrado' });
          }

          // Verifica se o documento pertence à organização do usuário
          // (controle de acesso horizontal — mesmo nível de privilégio)
          if (document.organizationId !== req.user.organizationId) {
            return res.status(403).json({ error: 'Acesso negado' });
          }

          // Verifica se o usuário tem permissão específica para ler este documento
          // (controle de acesso baseado em papéis — RBAC)
          if (!req.user.permissions.includes('documents:read')) {
            return res.status(403).json({ error: 'Sem permissão para ler documentos' });
          }

          res.json(document);
        });
        ```

!!! tip "Desafio extra — Hacksplaining"
    Pratique IDOR e Broken Access Control no ambiente gamificado do Hacksplaining:

    - [Insecure Direct Object References (IDOR)](https://www.hacksplaining.com/exercises/insecure-direct-object-references)
    - [Broken Access Control](https://www.hacksplaining.com/exercises/broken-access-control)

    Complete os exercícios e tente identificar os padrões de vulnerabilidade nos exemplos deste guia.

---

## Quiz rápido

!!! example "Pergunta 1"
    Um usuário está autenticado como `user_id=42`. Ele faz uma requisição `GET /api/profile/99`.
    O servidor retorna os dados do perfil do usuário 99 sem erros. O que está acontecendo?

    ??? note "Ver resposta"
        Isso é um **IDOR (Insecure Direct Object Reference)** — um tipo de Broken Access Control.
        O servidor deveria verificar se `user_id=42` tem permissão para acessar o perfil `99`.
        Como não verifica, qualquer usuário autenticado consegue acessar qualquer perfil.

!!! example "Pergunta 2"
    Qual é a diferença entre um erro **401 Unauthorized** e **403 Forbidden**?

    ??? note "Ver resposta"
        - **401 Unauthorized**: o usuário **não está autenticado**. Precisa fazer login primeiro.
        - **403 Forbidden**: o usuário **está autenticado** mas **não tem permissão** para acessar o recurso.

        Retornar 403 em vez de 404 para recursos que existem mas o usuário não pode ver é correto —
        mas cuidado: às vezes é melhor retornar 404 para não confirmar que o recurso existe.

!!! example "Pergunta 3"
    Por que usar UUIDs em vez de IDs sequenciais ajuda na segurança, mas **não resolve** o problema de IDOR?

    ??? note "Ver resposta"
        UUIDs são difíceis de adivinhar (ex: `550e8400-e29b-41d4-a716-446655440000`), então um atacante
        não consegue simplesmente incrementar um número para descobrir outros recursos.

        Porém, se o UUID aparecer em logs, URLs compartilháveis, ou se for obtido por outro meio
        (ex: em outra requisição), o problema de autorização permanece. A **verificação de propriedade
        é obrigatória** independentemente do tipo de ID usado.

---

## Referências

!!! info "Saiba mais"
    **Documentação oficial:**

    - [OWASP A01:2025 — Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
    - [OWASP Testing Guide — Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/)
    - [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

    **Ferramentas para testar:**

    - **Burp Suite** — interceptar e modificar requisições HTTP
    - **OWASP ZAP** — scanner automático com módulo de autorização
    - **Autorize (extensão Burp)** — testa automaticamente controle de acesso

    **CVEs relevantes:**

    - CVE-2019-16759 — vBulletin: execução remota via IDOR
    - CVE-2020-14750 — Oracle WebLogic: bypass de autenticação
    - CVE-2021-22205 — GitLab: IDOR permitindo execução de código

    **Prática:**

    - [Hacksplaining — IDOR](https://www.hacksplaining.com/exercises/insecure-direct-object-references)
    - [DVWA — Insecure CAPTCHA / Authorization](http://www.dvwa.co.uk/)
    - [WebGoat — Access Control Flaws](https://github.com/WebGoat/WebGoat)

---

## Leitura complementar: CSRF (Cross-Site Request Forgery)

!!! note "Fora do OWASP Top 10:2025, mas ainda relevante"
    CSRF apareceu no OWASP Top 10 de **2007 a 2017** e foi **removido em 2017** porque
    frameworks modernos (Django, Rails, Laravel, Spring Security) incluem proteção CSRF
    ativada por padrão, reduzindo drasticamente sua incidência.

    Ainda assim, CSRF continua perigoso em:

    - Aplicações legadas sem framework moderno
    - APIs mal configuradas (CORS permissivo + cookies sem `SameSite`)
    - Endpoints que aceitam `GET` para ações que modificam estado
    - Implementações customizadas de autenticação

    O OWASP classifica CSRF residual dentro de **A01 — Broken Access Control** quando
    representa falha no controle de quem pode executar uma ação. **Vale a leitura.**

---

### O que é CSRF?

> **Analogia**: Você está logado no seu banco online. Alguém te manda um email com uma imagem "engraçada". Quando você abre, a imagem na verdade é uma requisição invisível que transfere dinheiro da sua conta para a conta do atacante — usando sua sessão ativa, sem que você perceba.

CSRF acontece quando um site malicioso **engana o navegador da vítima** para que ele faça
requisições autenticadas a outro site — sem o conhecimento ou consentimento da vítima. O
navegador automaticamente envia cookies de sessão em toda requisição, então o servidor
não consegue distinguir a requisição legítima da forjada.

=== "🟢 Para leigos"
    Você está logado no seu email. Abre outro site (malicioso) em outra aba.
    Esse site faz uma requisição invisível para o seu email pedindo para
    "encaminhar todas as mensagens para atacante@evil.com".

    Como você está logado, o navegador envia automaticamente seus cookies de sessão.
    O servidor do email acha que você mesmo fez o pedido — e obedece.

    Você nem sabe que isso aconteceu.

=== "🟡 Desenvolvedor júnior"
    O ataque explora o comportamento dos navegadores de **incluir cookies automaticamente**
    em toda requisição ao domínio correspondente, independente de qual site iniciou a requisição.

    Fluxo típico:

    1. Vítima faz login em `banco.com` — cookie de sessão é armazenado
    2. Vítima acessa `evil.com` (num anúncio, email, etc.)
    3. `evil.com` tem um formulário HTML oculto que aponta para `banco.com/transferir`
    4. O formulário é submetido automaticamente via JavaScript
    5. O navegador envia o cookie de sessão junto — `banco.com` aceita a requisição

=== "🔴 Desenvolvedor sênior"
    CSRF é especialmente crítico em:

    - **JSON APIs com cookies**: se a API aceita `Content-Type: text/plain` ou `multipart/form-data`,
      formulários HTML conseguem fazer o POST (bypass do pre-flight CORS)
    - **CORS mal configurado + credenciais**: `Access-Control-Allow-Origin: *` com `credentials: true`
      é inválido, mas `Access-Control-Allow-Origin: https://evil.com` com `credentials: true` é CSRF via CORS
    - **Subdomínios comprometidos**: cookie com `domain=.empresa.com` pode ser lido/enviado por
      qualquer subdomínio comprometido
    - **Login CSRF**: forçar a vítima a fazer login na conta do atacante — perigoso em apps que
      armazenam dados do usuário (histórico, endereços salvos)

---

### Código vulnerável vs. seguro

=== "❌ Endpoint vulnerável a CSRF"
    ```python
    from flask import Flask, request, session

    app = Flask(__name__)

    @app.route('/alterar-email', methods=['POST'])
    def alterar_email():
        # Verifica apenas se o usuário está autenticado (cookie de sessão)
        if 'user_id' not in session:
            return "Não autenticado", 401

        novo_email = request.form['email']

        # PROBLEMA: qualquer site pode submeter este formulário
        # usando o cookie de sessão da vítima automaticamente
        db.alterar_email(session['user_id'], novo_email)
        return "Email alterado com sucesso"
    ```

    ```html
    <!-- Página em evil.com que explora a vulnerabilidade -->
    <html>
    <body onload="document.forms[0].submit()">
        <!-- Formulário invisível que aponta para o site alvo -->
        <form action="https://banco.com/alterar-email" method="POST" style="display:none">
            <input name="email" value="atacante@evil.com">
        </form>
        <p>Carregando promoção incrível...</p>
    </body>
    </html>
    ```

=== "✅ Proteção com token CSRF"
    ```python
    import secrets
    from flask import Flask, request, session, render_template_string

    app = Flask(__name__)

    def gerar_token_csrf() -> str:
        """Gera token CSRF único por sessão."""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']

    def verificar_csrf():
        """Verifica se o token CSRF da requisição é válido."""
        token_formulario = request.form.get('csrf_token', '')
        token_sessao = session.get('csrf_token', '')

        # Comparação em tempo constante — previne timing attacks
        if not secrets.compare_digest(token_formulario, token_sessao):
            return False
        return True

    @app.route('/alterar-email', methods=['GET', 'POST'])
    def alterar_email():
        if 'user_id' not in session:
            return "Não autenticado", 401

        if request.method == 'POST':
            # Verifica o token CSRF antes de qualquer ação
            if not verificar_csrf():
                return "Token CSRF inválido — possível ataque CSRF", 403

            novo_email = request.form['email']
            db.alterar_email(session['user_id'], novo_email)
            return "Email alterado com sucesso"

        # GET: renderiza o formulário com o token CSRF embutido
        token = gerar_token_csrf()
        return render_template_string("""
            <form method="POST">
                <!-- Token oculto — evil.com não consegue ler (Same-Origin Policy) -->
                <input type="hidden" name="csrf_token" value="{{ token }}">
                <input type="email" name="email" placeholder="Novo email">
                <button type="submit">Alterar</button>
            </form>
        """, token=token)
    ```

=== "✅ Proteção com SameSite Cookie"
    ```python
    # Flask — configurar cookies com SameSite
    app.config.update(
        SESSION_COOKIE_SAMESITE='Lax',    # Ou 'Strict' para máxima proteção
        SESSION_COOKIE_SECURE=True,        # Apenas HTTPS
        SESSION_COOKIE_HTTPONLY=True,      # Inacessível ao JavaScript
    )

    # SameSite=Strict: cookie NUNCA é enviado em requisições cross-site
    # (quebra alguns fluxos legítimos como links de email)

    # SameSite=Lax: cookie não é enviado em POSTs cross-site (proteção vs CSRF)
    # mas é enviado em navegação top-level via GET (links normais funcionam)

    # SameSite=None: sem proteção — exige Secure e é necessário apenas para
    # cookies de terceiros (ads, widgets embarcados)
    ```

=== "✅ Proteção em APIs JSON"
    ```python
    # APIs que usam tokens no header (Authorization: Bearer) são imunes a CSRF
    # porque formulários HTML não conseguem definir headers customizados

    @app.route('/api/alterar-email', methods=['POST'])
    def api_alterar_email():
        # Verifica Authorization header — formulários HTML não conseguem enviar isso
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'erro': 'Token de autorização necessário'}), 401

        token = auth_header.split(' ')[1]
        user_id = verificar_jwt(token)

        # Verifica Content-Type — requisições CSRF via form têm content-type diferente
        if request.content_type != 'application/json':
            return jsonify({'erro': 'Content-Type inválido'}), 400

        dados = request.get_json()
        db.alterar_email(user_id, dados['email'])
        return jsonify({'ok': True})
    ```

---

### Cenário de ataque — CSRF

!!! danger "Cenário de ataque real — CSRF em transferência bancária"
    **Situação**: Um banco online processa transferências via formulário POST.
    Não usa tokens CSRF. Cookies de sessão sem `SameSite`.

    **Ataque**:

    1. Atacante descobre a estrutura do formulário de transferência via inspeção
    2. Cria uma página em `evil.com` com formulário oculto que imita a transferência
    3. Envia o link para a vítima via email ou SMS ("Você ganhou um prêmio!")
    4. Vítima (logada no banco) clica e abre `evil.com`
    5. Formulário oculto faz POST para `banco.com/transferir?valor=5000&destino=123456`
    6. O navegador envia os cookies de sessão automaticamente
    7. O banco processa a transferência como se a vítima tivesse solicitado

    **Caso real**: Em 2008, um banco europeu sofreu perdas de €2.3 milhões por ataques CSRF
    antes de implementar tokens. Clientes foram vítimas via emails de phishing.

---

### Como prevenir CSRF

- [x] **Token CSRF por sessão**: incluir em todo formulário que modifica estado
- [x] **SameSite=Lax nos cookies**: proteção padrão moderna — suficiente para a maioria dos casos
- [x] **Usar frameworks modernos**: Django, Rails, Laravel têm CSRF ativo por padrão
- [ ] **APIs com JWT no header**: tokens em `Authorization: Bearer` são imunes a CSRF
- [ ] **Verificar Origin/Referer header**: validar que a requisição veio do seu próprio domínio
- [ ] **Double submit cookie**: alternativa ao token sincronizado (para APIs stateless)
- [ ] **SameSite=Strict**: para funcionalidades críticas (transferências, troca de senha)
- [ ] **Re-autenticação para ações críticas**: pedir senha novamente antes de transferências grandes

---

### Exercícios — CSRF

!!! question "Exercício — Token CSRF bem implementado?"
    Analise esta implementação de proteção CSRF e identifique o problema:

    ```python
    @app.route('/deletar-conta', methods=['POST'])
    def deletar_conta():
        if 'user_id' not in session:
            return "Não autenticado", 401

        token_recebido = request.form.get('csrf_token', '')

        # Verifica se o token é não-vazio
        if token_recebido:
            db.deletar_usuario(session['user_id'])
            return "Conta deletada"

        return "Token CSRF ausente", 403
    ```

    ??? success "Ver resposta"
        **Problema**: a verificação apenas checa se o token é **não-vazio** — não compara
        com o token da sessão! Qualquer string não-vazia passaria na verificação.

        Um atacante pode simplesmente enviar `csrf_token=qualquercoisa` e o ataque funciona.

        **Correção**:
        ```python
        token_recebido = request.form.get('csrf_token', '')
        token_esperado = session.get('csrf_token', '')

        # Comparação real + tempo constante
        if not token_esperado or not secrets.compare_digest(token_recebido, token_esperado):
            return "Token CSRF inválido", 403
        ```

!!! tip "Prática — Hacksplaining"
    - [Cross-Site Request Forgery (CSRF)](https://www.hacksplaining.com/exercises/csrf)
    - [CSRF no PortSwigger Web Academy](https://portswigger.net/web-security/csrf) — labs práticos com diferentes cenários de bypass
