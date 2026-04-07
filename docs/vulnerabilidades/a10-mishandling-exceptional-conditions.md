---
title: "A10:2025 — Mishandling of Exceptional Conditions"
description: "Tratamento inadequado de condições excepcionais: quando erros se tornam brechas"
tags: [erros, exceções, tratamento, médio, a10]
---

# A10:2025 — Mishandling of Exceptional Conditions

<span style="background-color: #f39c12; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO MÉDIO</span>

> **Analogia**: Imagine um cofre que, quando a chave errada é inserida, exibe na tela: "Chave incorreta — esperando chave modelo XY-7 com 6 pinos". Em vez de simplesmente negar, o cofre revela informações que facilitam a próxima tentativa do ladrão.

---

## O que é?

=== "🟢 Para leigos"
    Todo sistema tem situações inesperadas — erros de conexão, dados inválidos, falhas de
    rede. **Como o sistema reage** a essas situações é crítico para a segurança.

    Quando um sistema trata mal essas exceções, pode:

    - **Revelar informações demais**: mostrar caminhos de arquivo, nomes de tabelas do banco, versões de software
    - **Falhar de forma insegura**: em vez de negar acesso, conceder por padrão quando algo dá errado
    - **Travar inesperadamente**: uma exceção não tratada pode derrubar o serviço (DoS acidental)
    - **Pular verificações de segurança**: código de tratamento de erro que bypassa autenticação

=== "🟡 Desenvolvedor júnior"
    Mishandling of Exceptional Conditions inclui:

    - **Stack traces expostos**: erros técnicos detalhados exibidos ao usuário
    - **Fail open**: em caso de erro, o sistema concede acesso em vez de negar
    - **Exceções silenciadas**: `except: pass` que oculta erros e permite estados inconsistentes
    - **Tipos de erro distintos**: "usuário não existe" vs "senha incorreta" — permite enumerar usuários
    - **Null pointer dereference**: acessar objeto sem verificar se é null — crash ou comportamento inesperado
    - **Integer overflow/underflow**: cálculos que resultam em valores inesperados (preços negativos!)

=== "🔴 Desenvolvedor sênior"
    Em 2025, essa categoria ganhou destaque porque sistemas modernos têm mais "superfície de erro":
    microsserviços, APIs externas, orquestradores de containers, filas de mensagem — cada componente
    pode falhar de formas inesperadas.

    **Vetores críticos:**

    - **Partial failure em sistemas distribuídos**: serviço de autorização offline → fail open?
    - **Race conditions**: janela de tempo entre verificação e uso (TOCTOU)
    - **Integer overflow em cálculos financeiros**: saldo negativo vira grande positivo
    - **Type confusion**: coerção de tipos inesperada (JavaScript `[] + {}`, PHP `==`)
    - **Error-based information disclosure**: mensagens de erro distintas por caso que revelam lógica interna
    - **Unhandled promise rejections**: em Node.js, podem expor stack traces ou crashar o processo

---

## Código vulnerável vs. seguro

=== "❌ Tratamento inseguro de erros"
    ```python
    @app.route('/usuario/<int:user_id>')
    def perfil_usuario(user_id):
        try:
            # Tenta conectar ao banco de dados
            conn = get_db_connection()
            usuario = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()

        except Exception as e:
            # PROBLEMA: expõe detalhes técnicos ao usuário
            return jsonify({
                'erro': str(e),  # Pode ser: "FATAL ERROR: table 'users' doesn't exist"
                'tipo': type(e).__name__,
                'traceback': traceback.format_exc()  # Caminho de arquivo, linha, etc.
            }), 500

        if not usuario:
            # PROBLEMA: mensagem diferente para usuário inexistente vs sem permissão
            return "Usuário não encontrado", 404  # Confirma que o ID é inexistente!

        return jsonify(dict(usuario))

    def verificar_permissao(user_id, recurso_id):
        try:
            # Verifica permissão em serviço externo
            response = requests.get(f"http://auth-service/check/{user_id}/{recurso_id}")
            return response.json()['permitido']
        except:
            # PROBLEMA CRÍTICO: fail open — em caso de erro, concede acesso!
            return True  # "Se o serviço de auth caiu, deixa passar..."
    ```

=== "✅ Tratamento seguro de erros"
    ```python
    import logging
    from flask import jsonify

    logger = logging.getLogger(__name__)

    @app.route('/usuario/<int:user_id>')
    @login_required
    def perfil_usuario(user_id):
        try:
            conn = get_db_connection()
            usuario = conn.execute(
                "SELECT id, nome, email FROM users WHERE id = ?", (user_id,)
            ).fetchone()

        except DatabaseConnectionError as e:
            # Loga detalhes técnicos internamente (não para o usuário)
            logger.error(f"Erro de banco de dados ao buscar usuário {user_id}: {e}")
            # Retorna mensagem genérica — sem detalhes técnicos
            return jsonify({'erro': 'Serviço temporariamente indisponível'}), 503

        except Exception as e:
            # Captura genérica: loga tudo, mas não expõe nada
            logger.exception(f"Erro inesperado ao buscar usuário {user_id}")
            return jsonify({'erro': 'Ocorreu um erro interno'}), 500

        # Resposta idêntica para "não existe" e "sem permissão"
        # Evita user enumeration
        if not usuario or usuario['id'] != current_user.id:
            return jsonify({'erro': 'Recurso não encontrado'}), 404

        return jsonify({
            'id': usuario['id'],
            'nome': usuario['nome'],
            'email': usuario['email']
        })

    def verificar_permissao(user_id: int, recurso_id: int) -> bool:
        """
        Verifica permissão com FAIL SECURE — em caso de dúvida, nega acesso.
        """
        try:
            response = requests.get(
                f"http://auth-service/check/{user_id}/{recurso_id}",
                timeout=2  # Timeout curto — não bloquear para sempre
            )
            response.raise_for_status()
            return response.json().get('permitido', False)  # Default: False

        except requests.Timeout:
            logger.warning(f"Auth service timeout para user={user_id}, recurso={recurso_id}")
            return False  # FAIL SECURE: timeout = nega acesso

        except requests.RequestException as e:
            logger.error(f"Auth service indisponível: {e}")
            return False  # FAIL SECURE: serviço offline = nega acesso
    ```

=== "❌ Race condition (TOCTOU)"
    ```python
    import os

    def processar_arquivo(nome_arquivo: str, usuario_id: int):
        caminho = f"/uploads/{usuario_id}/{nome_arquivo}"

        # Verifica se arquivo existe (Time Of Check)
        if os.path.exists(caminho):
            # JANELA DE VULNERABILIDADE: atacante pode substituir o arquivo aqui!
            # Time Of Use — pode ser arquivo diferente do verificado
            with open(caminho, 'r') as f:
                conteudo = f.read()
            return conteudo

        return "Arquivo não encontrado", 404
    ```

=== "✅ Sem race condition"
    ```python
    import os

    def processar_arquivo(nome_arquivo: str, usuario_id: int):
        caminho = f"/uploads/{usuario_id}/{nome_arquivo}"

        # Resolver symlinks antes de qualquer verificação
        caminho_real = os.path.realpath(caminho)
        diretorio_permitido = os.path.realpath(f"/uploads/{usuario_id}/")

        # Verificar path traversal
        if not caminho_real.startswith(diretorio_permitido):
            raise SecurityError("Tentativa de path traversal detectada")

        try:
            # Abrir diretamente — EAFP (Easier to Ask Forgiveness than Permission)
            # Evita janela TOCTOU entre verificação e uso
            with open(caminho_real, 'r') as f:
                return f.read()

        except FileNotFoundError:
            return None  # Arquivo não existe
        except PermissionError:
            logger.warning(f"Permissão negada ao ler {caminho_real}")
            return None
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — Integer overflow em e-commerce"
    **Situação**: Uma loja online tem desconto por quantidade. A lógica calcula:
    `preço_total = preco_unitario * quantidade - desconto_percentual`

    **Ataque**:

    1. Atacante descobre que o campo `quantidade` aceita números negativos
    2. Envia carrinho com `quantidade = -1000` para produto de R$100
    3. O cálculo resulta em: `100 * (-1000) = -100.000`
    4. O sistema subtrai um desconto de R$0 e processa pagamento de **-R$100.000**
    5. O sistema de pagamento, sem validação, **credita R$100.000 na conta do atacante**

    **Consequência**: Fraude financeira direta. Variações desse ataque aconteceram em
    casas de câmbio de criptomoedas, onde integer overflow em contratos inteligentes
    resultou em saldos absurdamente grandes.

---

## Como prevenir

- [x] **Mensagens de erro genéricas**: nunca expor detalhes técnicos ao usuário
- [x] **Fail secure (fail closed)**: em caso de erro ou dúvida, negar acesso por padrão
- [x] **Validação de limites**: valores numéricos sempre validados (mín/máx, positivo/negativo)
- [ ] **Logging interno detalhado**: logar detalhes técnicos internamente, não para o usuário
- [ ] **Tipos de resposta consistentes**: mesma mensagem para "não encontrado" e "sem permissão"
- [ ] **Tratamento de exceções específico**: capturar exceções por tipo, nunca silenciar
- [ ] **Timeouts em serviços externos**: não aguardar indefinidamente por APIs externas
- [ ] **Testes de casos de borda**: null, vazio, negativo, overflow, unicode especial

---

## Exercícios práticos

!!! question "Exercício 1 — Identifique o problema"
    O que está errado com este endpoint de busca?

    ```python
    @app.route('/busca')
    def buscar():
        termo = request.args.get('q', '')

        try:
            resultados = db.buscar(termo)
            return jsonify(resultados)

        except Exception as e:
            if 'syntax error' in str(e).lower():
                return jsonify({'erro': f'Erro de sintaxe SQL: {e}'}), 400
            elif 'connection refused' in str(e).lower():
                return jsonify({'erro': f'Banco de dados: {str(e)}'}), 503
            else:
                return jsonify({'erro': str(e)}), 500
    ```

    ??? success "Ver resposta"
        **Problema 1**: Expõe detalhes de erros SQL para o usuário — revela estrutura do banco.

        **Problema 2**: `'syntax error' in str(e)` — detectar SQL injection pelo tipo de erro
        confirma ao atacante que há SQL injection (oracle attack).

        **Problema 3**: Mensagens de erro distintas por tipo de falha permitem fingerprinting
        da infraestrutura (banco de dados, tipo de erro).

        **Correção**:
        ```python
        @app.route('/busca')
        def buscar():
            termo = request.args.get('q', '').strip()

            # Validar entrada antes de qualquer operação
            if not termo or len(termo) > 200:
                return jsonify({'resultados': []}), 200

            try:
                resultados = db.buscar(termo)
                return jsonify({'resultados': resultados})

            except Exception as e:
                # Loga internamente com todos os detalhes
                logger.exception(f"Erro na busca por '{termo[:50]}'")
                # Retorna mensagem genérica — sem informação sobre o erro
                return jsonify({'erro': 'Não foi possível realizar a busca'}), 500
        ```

!!! question "Exercício 2 — Fail secure ou fail open?"
    Para cada cenário abaixo, diga se o sistema deve "fail secure" (negar) ou pode "fail open" (continuar):

    1. Serviço de verificação de fraude fica offline durante uma compra de R$500
    2. Serviço de conversão de moeda fica offline durante exibição de preço
    3. Serviço de autorização fica offline durante acesso a dados médicos
    4. Serviço de antivírus fica offline durante upload de foto de perfil

    ??? success "Ver resposta"
        1. **Fail secure**: compra de R$500 sem verificação de fraude = risco financeiro. Bloquear e pedir ao usuário para tentar novamente.
        2. **Pode aceitar degradação**: mostrar preço em moeda base, ou "preço indisponível". Não é questão de segurança direta.
        3. **Fail secure**: dados médicos são altamente sensíveis. Se autorização está offline, negar todos os acessos até restabelecer.
        4. **Decisão de negócio**: pode aceitar o upload e escanear depois (com quarentena). Depende do risco do contexto.

!!! tip "Desafio extra — Hacksplaining"
    - [Insecure Direct Object References](https://www.hacksplaining.com/exercises/insecure-direct-object-references) — observe como mensagens de erro distintas revelam informações

---

## Quiz rápido

!!! example "Pergunta 1"
    O que é "fail secure" (ou "fail closed") e por que é o comportamento padrão recomendado?

    ??? note "Ver resposta"
        Fail secure significa que, quando o sistema encontra uma condição de erro ou incerteza, ele **nega o acesso** por padrão em vez de conceder. A lógica é: é melhor causar inconveniência temporária (usuário legítimo precisa tentar novamente) do que abrir uma brecha de segurança (atacante obtém acesso não autorizado). O custo de um false negative (negar acesso legítimo) é geralmente muito menor que o custo de um false positive (conceder acesso indevido).

!!! example "Pergunta 2"
    Por que usar a mesma mensagem de erro para "usuário não encontrado" e "senha incorreta" é uma boa prática?

    ??? note "Ver resposta"
        Se o sistema retorna mensagens diferentes, um atacante consegue **enumerar usuários válidos**: testa emails e usa as respostas para descobrir quais existem no sistema (user enumeration). Com uma lista de emails válidos, o atacante pode fazer credential stuffing, phishing direcionado ou força bruta apenas nos emails confirmados. A mensagem genérica "Credenciais inválidas" previne isso sem impactar a experiência do usuário legítimo.

!!! example "Pergunta 3"
    O que é uma race condition (TOCTOU) e como ela pode ser explorada?

    ??? note "Ver resposta"
        TOCTOU (Time Of Check, Time Of Use) é uma race condition onde há uma janela de tempo entre **verificar** uma condição e **usar** o resultado. Um atacante pode modificar o estado do sistema nessa janela. Exemplo clássico: verificar se arquivo é seguro, depois de 1ms o atacante substitui pelo arquivo malicioso, sistema usa o arquivo malicioso. Em segurança web: verificar saldo, exibir tela de confirmação, usuário em paralelo faz outra transação — saldo muda entre verificação e débito (double spending).

---

## Referências

!!! info "Saiba mais"
    - [OWASP A10:2025 — Mishandling of Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_Exceptional_Conditions/)
    - [CWE-754 — Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
    - [CWE-390 — Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
    - [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
    - [Hacksplaining — Error Handling](https://www.hacksplaining.com/exercises/information-leakage)
