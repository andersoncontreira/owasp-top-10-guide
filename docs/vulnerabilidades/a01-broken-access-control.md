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
