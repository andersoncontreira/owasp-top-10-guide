---
title: "A05:2025 — Injection"
description: "Injeção: quando dados do usuário são executados como código"
tags: [injection, sql, xss, nosql, crítico, a05]
---

# A05:2025 — Injection

<span style="background-color: #c0392b; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO CRÍTICO</span>

> **Analogia**: Imagine que você pede uma pizza por telefone e, no lugar do endereço, você diz: "Rua das Flores, 10. E também cancele todos os outros pedidos." Se o atendente executar literalmente o que você disse, o problema não é você — é o sistema que não diferenciou instrução de dado.

---

## O que é?

=== "🟢 Para leigos"
    Injection acontece quando um sistema confunde **dados fornecidos pelo usuário** com
    **comandos do sistema**.

    O exemplo mais famoso é o SQL Injection: você preenche um formulário de login e, em vez
    de digitar sua senha, digita um trecho de código SQL que "engana" o banco de dados.

    O banco de dados achava que estava recebendo uma senha, mas na verdade recebeu uma instrução
    que diz "ignore a verificação de senha e deixe qualquer um entrar".

    É como se você escrevesse no campo de uma formulário: `João' OU '1'='1` e magicamente
    o sistema te deixasse entrar sem saber a senha.

=== "🟡 Desenvolvedor júnior"
    Injection ocorre quando **entrada não validada ou não sanitizada** é inserida diretamente
    em um interpretador (SQL, OS, LDAP, XML, etc.).

    **Tipos principais:**

    - **SQL Injection**: `' OR '1'='1` em campos de login
    - **NoSQL Injection**: `{"$gt": ""}` em queries MongoDB
    - **OS Command Injection**: `; rm -rf /` em campos que chamam comandos do sistema
    - **LDAP Injection**: manipulação de queries de diretório
    - **XPath Injection**: manipulação de queries XML
    - **Template Injection (SSTI)**: `{{7*7}}` em campos renderizados por templates

    A raiz do problema: **concatenar strings para montar queries** em vez de usar
    parâmetros preparados (prepared statements).

=== "🔴 Desenvolvedor sênior"
    Injection continua no Top 5 em 2025 apesar de ser um problema conhecido há 30 anos.
    Por quê? Porque:

    1. **Pressão por velocidade**: devs usam concatenação por ser mais rápido de escrever
    2. **ORMs não são silver bullet**: SQLAlchemy `text()`, Django `raw()`, Hibernate `createNativeQuery()` — todos vulneráveis se mal usados
    3. **Inputs inesperados**: HTTP headers, cookies, User-Agent, Referer — todos são vetores
    4. **Second-order injection**: dado armazenado "limpo" mas re-usado sem sanitização

    **Vetores avançados:**

    - **Blind SQL Injection**: sem mensagens de erro, usa tempo de resposta (`SLEEP(5)`) ou comportamentos booleanos para extrair dados bit a bit
    - **Out-of-band injection**: exfiltração via DNS ou HTTP para servidor do atacante
    - **NoSQL injection em APIs GraphQL**: `{users(filter: {password: {$regex: ".*"}})}`)
    - **SSTI via Jinja2/Twig**: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

---

## Código vulnerável vs. seguro

=== "❌ SQL Injection vulnerável"
    ```python
    from flask import Flask, request
    import sqlite3

    app = Flask(__name__)

    @app.route('/login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']

        # PROBLEMA CRÍTICO: concatenação direta de entrada do usuário na query SQL
        # Se username = "admin'--", a query se torna:
        # SELECT * FROM users WHERE username='admin'--' AND password='...'
        # O '--' comenta o resto, então a verificação de senha é ignorada!
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

        conn = sqlite3.connect('app.db')
        cursor = conn.execute(query)
        user = cursor.fetchone()

        if user:
            return "Login bem-sucedido!"
        return "Credenciais inválidas", 401
    ```

=== "✅ SQL com Prepared Statements"
    ```python
    from flask import Flask, request
    import sqlite3
    import hashlib

    app = Flask(__name__)

    @app.route('/login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']

        # SOLUÇÃO: usar parâmetros preparados (prepared statements)
        # O banco de dados trata os '?' como DADOS, nunca como código SQL
        # Mesmo que username = "admin'--", será tratado como texto literal
        query = "SELECT id, username FROM users WHERE username=? AND password_hash=?"

        # Nunca armazenar senhas em texto puro — usar hash seguro
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect('app.db')
        cursor = conn.execute(query, (username, password_hash))  # Parâmetros separados da query
        user = cursor.fetchone()

        if user:
            return "Login bem-sucedido!"
        return "Credenciais inválidas", 401
    ```

=== "✅ ORM seguro (SQLAlchemy)"
    ```python
    from flask import Flask, request
    from flask_sqlalchemy import SQLAlchemy
    from werkzeug.security import check_password_hash

    app = Flask(__name__)
    db = SQLAlchemy(app)

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        password_hash = db.Column(db.String(256), nullable=False)

    @app.route('/login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']

        # ORM usa parâmetros preparados automaticamente — seguro por padrão
        # NUNCA use: db.session.execute(text(f"SELECT * FROM users WHERE username='{username}'"))
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            return "Login bem-sucedido!"
        return "Credenciais inválidas", 401
    ```

=== "❌ OS Command Injection"
    ```python
    import subprocess
    from flask import Flask, request

    app = Flask(__name__)

    @app.route('/ping')
    def ping():
        host = request.args.get('host', '')

        # PROBLEMA: entrada do usuário diretamente em comando de sistema
        # Se host = "google.com; cat /etc/passwd", executa os dois comandos!
        resultado = subprocess.run(
            f"ping -c 1 {host}",
            shell=True,  # shell=True é o problema aqui
            capture_output=True,
            text=True
        )
        return resultado.stdout

    # Correção: usar lista de argumentos (nunca shell=True com input do usuário)
    @app.route('/ping/seguro')
    def ping_seguro():
        host = request.args.get('host', '')

        # Validação da entrada: apenas hostname/IP válido
        import re
        if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
            return "Host inválido", 400

        # Usa lista de argumentos — shell=False por padrão, sem interpolação de shell
        resultado = subprocess.run(
            ["ping", "-c", "1", host],  # Cada argumento é separado — seguro
            capture_output=True,
            text=True,
            timeout=5
        )
        return resultado.stdout
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — SQL Injection clássico"
    **Situação**: Um sistema de e-learning tem um endpoint de busca de cursos:
    `GET /cursos?nome=python`

    A query interna é: `SELECT * FROM cursos WHERE nome LIKE '%python%'`

    **Ataque**:

    1. Atacante envia: `GET /cursos?nome=python' UNION SELECT username,password,NULL,NULL FROM users--`
    2. A query vira: `SELECT * FROM cursos WHERE nome LIKE '%python' UNION SELECT username,password,NULL,NULL FROM users--%'`
    3. O banco retorna os dados dos cursos **MAIS** todos os usuários e senhas do sistema
    4. Atacante extrai a tabela inteira de usuários com um único request

    **Consequência**: Comprometimento total do banco de dados, incluindo credenciais de todos os usuários e administradores.

    **Caso real**: Em 2008, o ataque a sistemas de banco de dados militares dos EUA começou com SQL Injection. A técnica foi usada no caso Heartland Payment Systems (2009) — 130 milhões de cartões comprometidos.

---

## Como prevenir

- [x] **Prepared Statements**: usar parametrização em TODA query ao banco de dados
- [x] **ORM corretamente**: usar o ORM sem raw queries concatenadas
- [x] **Validação de entrada**: validar tipo, tamanho e formato de toda entrada
- [ ] **Princípio do menor privilégio**: o usuário do banco não precisa de DROP TABLE
- [ ] **WAF (Web Application Firewall)**: adicionar camada de proteção contra payloads conhecidos
- [ ] **Stored procedures parametrizadas**: quando necessário usar SQL puro, usar SP com parâmetros
- [ ] **Escape de saída**: para XSS, escapar HTML em toda saída para o navegador
- [ ] **SAST no CI/CD**: ferramentas como Bandit (Python) ou SonarQube detectam SQL concatenado

---

## Exercícios práticos

!!! question "Exercício 1 — Encontre o problema"
    Encontre a vulnerabilidade de injection neste código:

    ```javascript
    // Node.js com MongoDB
    app.post('/usuarios/buscar', async (req, res) => {
      const { email, senha } = req.body;

      // Busca usuário pelo email e senha
      const usuario = await Usuario.findOne({
        email: email,
        senha: senha
      });

      if (usuario) {
        res.json({ token: gerarToken(usuario) });
      } else {
        res.status(401).json({ erro: 'Credenciais inválidas' });
      }
    });
    ```

    ??? success "Ver resposta"
        **Problema**: NoSQL Injection no MongoDB.

        Se o atacante enviar no body JSON:
        ```json
        {
          "email": "admin@empresa.com",
          "senha": {"$gt": ""}
        }
        ```

        A query MongoDB vira: `{email: "admin@empresa.com", senha: {$gt: ""}}` — que significa
        "onde a senha é maior que string vazia" — sempre verdadeiro!

        **Correção**: Validar que os campos recebidos são strings, não objetos:
        ```javascript
        app.post('/usuarios/buscar', async (req, res) => {
          const { email, senha } = req.body;

          // Validar que são strings (não objetos com operadores MongoDB)
          if (typeof email !== 'string' || typeof senha !== 'string') {
            return res.status(400).json({ erro: 'Formato de dados inválido' });
          }

          // Sanitizar e validar formato do email
          if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
            return res.status(400).json({ erro: 'Email inválido' });
          }

          const usuario = await Usuario.findOne({
            email: email,
            senhaHash: hashSenha(senha)  // Comparar hash, nunca senha pura
          });
          // ...
        });
        ```

!!! question "Exercício 2 — Corrija o código"
    Este código PHP tem SQL injection. Corrija usando PDO com prepared statements:

    ```php
    <?php
    $produto = $_GET['produto'];
    $conn = new PDO('mysql:host=localhost;dbname=loja', $user, $pass);

    // Vulnerável: concatenação direta
    $sql = "SELECT * FROM produtos WHERE nome = '$produto'";
    $resultado = $conn->query($sql);

    foreach ($resultado as $row) {
        echo $row['nome'] . ' - R$' . $row['preco'] . '<br>';
    }
    ?>
    ```

    ??? success "Ver solução modelo"
        ```php
        <?php
        $produto = $_GET['produto'];

        // Validação básica de entrada
        if (empty($produto) || strlen($produto) > 100) {
            http_response_code(400);
            echo "Parâmetro inválido";
            exit;
        }

        $conn = new PDO('mysql:host=localhost;dbname=loja', $user, $pass);

        // CORREÇÃO: usar prepared statement com placeholder
        $sql = "SELECT * FROM produtos WHERE nome LIKE :produto";
        $stmt = $conn->prepare($sql);

        // Bind do parâmetro — PDO trata como dado, nunca como SQL
        $stmt->bindValue(':produto', '%' . $produto . '%', PDO::PARAM_STR);
        $stmt->execute();

        $resultados = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($resultados as $row) {
            // Escapa saída para prevenir XSS também
            echo htmlspecialchars($row['nome']) . ' - R$' . number_format($row['preco'], 2) . '<br>';
        }
        ?>
        ```

!!! tip "Desafio extra — Hacksplaining"
    Pratique SQL Injection no ambiente interativo do Hacksplaining:

    - [SQL Injection](https://www.hacksplaining.com/exercises/sql-injection)
    - [NoSQL Injection](https://www.hacksplaining.com/exercises/nosql-injection)
    - [Command Injection](https://www.hacksplaining.com/exercises/command-execution)

    Após completar os exercícios, tente o nível avançado com **Blind SQL Injection**
    usando ferramentas como o SQLMap em ambiente controlado.

---

## Quiz rápido

!!! example "Pergunta 1"
    Por que `' OR '1'='1` consegue bypassar uma verificação de senha quando injetado em SQL?

    ??? note "Ver resposta"
        A query original é: `WHERE username='X' AND password='Y'`

        Com o payload, vira: `WHERE username='admin' AND password='' OR '1'='1'`

        Como `'1'='1'` é sempre verdadeiro, e o `OR` faz com que a condição inteira seja verdadeira,
        o banco retorna o usuário independentemente da senha fornecida.

!!! example "Pergunta 2"
    Qual é a diferença entre **validação** e **sanitização** de entrada?

    ??? note "Ver resposta"
        - **Validação**: verificar se a entrada está no formato/tipo esperado. Exemplo: "é um email válido?", "é um número inteiro?", "tem menos de 100 caracteres?". Se não passar, **rejeita** a entrada.

        - **Sanitização**: modificar a entrada para remover ou escapar caracteres perigosos. Exemplo: converter `<script>` em `&lt;script&gt;` para HTML. Se não passar, **transforma** a entrada.

        Para bancos de dados, **validação + prepared statements** é a abordagem correta.
        Sanitização manual de SQL é propensa a erros e não recomendada.

!!! example "Pergunta 3"
    Por que usar um ORM (como SQLAlchemy ou Django ORM) não garante automaticamente proteção contra SQL injection?

    ??? note "Ver resposta"
        ORMs têm métodos para executar SQL bruto quando necessário, e esses métodos são vulneráveis se mal usados:

        - SQLAlchemy: `db.session.execute(text(f"SELECT * FROM users WHERE id={user_input}"))`
        - Django: `User.objects.raw(f"SELECT * FROM auth_user WHERE id={user_input}")`
        - Hibernate: `session.createNativeQuery(f"FROM User WHERE id={user_input}")`

        Além disso, **second-order injection**: dados armazenados "com segurança" podem ser
        re-utilizados em queries dinâmicas sem sanitização posterior.

---

## Referências

!!! info "Saiba mais"
    **Documentação oficial:**

    - [OWASP A05:2025 — Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
    - [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
    - [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

    **Ferramentas para testar:**

    - **SQLMap** — ferramenta automática de detecção e exploração de SQL injection
    - **Burp Suite** — interceptação e modificação de requisições HTTP
    - **OWASP ZAP** — scanner de vulnerabilidades web com módulo de injection

    **CVEs relevantes:**

    - CVE-2012-2122 — MySQL: bypass de autenticação por falha de comparação
    - CVE-2019-19781 — Citrix ADC: path traversal + command injection
    - CVE-2021-44228 — Log4Shell: JNDI injection em logging (crítico)

    **Prática:**

    - [Hacksplaining — SQL Injection](https://www.hacksplaining.com/exercises/sql-injection)
    - [SQLZoo — SQL Injection tutorial](https://sqlzoo.net/)
    - [DVWA — SQL Injection module](http://www.dvwa.co.uk/)
    - [WebGoat — Injection Flaws](https://github.com/WebGoat/WebGoat)
