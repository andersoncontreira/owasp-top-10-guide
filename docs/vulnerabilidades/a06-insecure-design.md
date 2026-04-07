---
title: "A06:2025 — Insecure Design"
description: "Design inseguro: quando a vulnerabilidade está na arquitetura, não no código"
tags: [design, arquitetura, threat-modeling, alto, a06]
---

# A06:2025 — Insecure Design

<span style="background-color: #e67e22; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO ALTO</span>

> **Analogia**: Não adianta instalar a melhor fechadura do mundo em uma porta de papelão. O problema não é a implementação — é o projeto desde o início. Insecure Design é o equivalente de construir uma casa sem considerar que ela precisará de paredes.

---

## O que é?

=== "🟢 Para leigos"
    Insecure Design é diferente de um bug. Um bug é quando você escreveu código errado.
    Insecure Design é quando você **planejou** o sistema de forma que ele seja inseguro por
    natureza — mesmo que todo o código esteja correto.

    Exemplo: um banco que permite transferências ilimitadas sem confirmação por email/SMS.
    O código funciona perfeitamente, mas o **design** não considerou o caso de uma conta
    ser comprometida. Qualquer invasor transfere tudo antes de ser detectado.

=== "🟡 Desenvolvedor júnior"
    Insecure Design inclui:

    - **Ausência de threat modeling**: nunca perguntou "como isso pode ser abusado?"
    - **Lógica de negócio vulnerável**: fluxos que permitem fraude por design
    - **Sem rate limiting por design**: login sem limite de tentativas, sem CAPTCHA
    - **Confiança implícita**: "só usuários legítimos vão usar essa API"
    - **Dados sensíveis desnecessários**: coletar CPF quando só precisaria de email
    - **Ausência de princípio do menor privilégio**: todos os usuários podem fazer tudo

=== "🔴 Desenvolvedor sênior"
    Insecure Design foi adicionado ao OWASP em 2021 porque o setor percebeu que security
    no nível de código é necessário mas insuficiente. A raiz de muitas vulnerabilidades
    está em decisões arquiteturais tomadas sem considerar ameaças.

    **Práticas de secure design:**

    - **Threat Modeling (STRIDE)**: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege
    - **Security by Design**: segurança é requisito funcional, não afterthought
    - **Privacy by Design**: coletar mínimo necessário, dar controle ao usuário
    - **Defense in Depth**: múltiplas camadas de proteção independentes
    - **Fail Secure**: em caso de erro, o sistema nega acesso (não concede)
    - **Zero Trust Architecture**: nunca confiar, sempre verificar, mesmo em rede interna

---

## Código vulnerável vs. seguro

=== "❌ Design inseguro — recuperação de senha"
    ```python
    # Design inseguro: perguntas de segurança são fracas por design
    # O problema não é o código — é a decisão de usar perguntas de segurança

    @app.route('/recuperar-senha', methods=['POST'])
    def recuperar_senha():
        email = request.form['email']
        resposta_secreta = request.form['resposta_secreta']

        usuario = db.usuarios.find_one({'email': email})

        # Problema 1: perguntas como "nome do seu animal de estimação"
        # são fáceis de descobrir em redes sociais
        if usuario and usuario['resposta_secreta'] == resposta_secreta:
            nova_senha = request.form['nova_senha']
            # Problema 2: sem rate limiting — permite força bruta das respostas
            # Problema 3: sem notificação para o dono da conta
            db.usuarios.update({'email': email}, {'senha': nova_senha})
            return "Senha alterada com sucesso"

        return "Dados inválidos", 400
    ```

=== "✅ Design seguro — recuperação de senha"
    ```python
    import secrets
    from datetime import datetime, timedelta

    @app.route('/solicitar-recuperacao', methods=['POST'])
    @limiter.limit("3 per hour")  # Rate limiting por design
    def solicitar_recuperacao():
        email = request.form['email']

        usuario = db.usuarios.find_one({'email': email})

        # Resposta idêntica independente de o email existir ou não
        # Evita user enumeration — design consciente
        if usuario:
            # Token criptograficamente seguro com expiração curta
            token = secrets.token_urlsafe(32)
            expiracao = datetime.utcnow() + timedelta(minutes=15)

            db.tokens_reset.insert({
                'email': email,
                'token': hash_token(token),  # Guardar hash do token, não o token
                'expiracao': expiracao,
                'usado': False
            })

            # Envia por email — sem link direto para a nova senha
            enviar_email_recuperacao(email, token)

        # Sempre retorna a mesma mensagem — não revela se email existe
        return "Se o email existir, você receberá um link de recuperação."

    @app.route('/resetar-senha/<token>', methods=['POST'])
    def resetar_senha(token):
        # Busca por hash do token — token original nunca é guardado
        registro = db.tokens_reset.find_one({
            'token': hash_token(token),
            'expiracao': {'$gt': datetime.utcnow()},
            'usado': False
        })

        if not registro:
            return "Link inválido ou expirado", 400

        nova_senha = request.form['nova_senha']

        # Invalida o token imediatamente (uso único)
        db.tokens_reset.update(
            {'token': hash_token(token)},
            {'usado': True}
        )

        # Atualiza a senha e notifica o usuário
        db.usuarios.update(
            {'email': registro['email']},
            {'senha': hash_senha(nova_senha)}
        )

        # Notificação de segurança: alerta o usuário que a senha foi alterada
        enviar_email_alerta_senha_alterada(registro['email'])

        return "Senha alterada com sucesso"
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — Lógica de negócio vulnerável"
    **Situação**: Um aplicativo de delivery tem um sistema de cupons. O design permite
    aplicar múltiplos cupons em um pedido sem validar combinações.

    **Ataque**:

    1. Atacante descobre que pode aplicar o cupom "PRIMEIROPEIDO20" múltiplas vezes
    2. Faz pedido com 10x o mesmo cupom: -20% + -20% + ... = pedido gratuito
    3. Sistema aceita porque cada cupom individualmente é válido
    4. O bug não está no código — está no **design** que não considerou esse cenário

    **Caso real**: Em 2018, o Domino's Pizza teve problema similar com cupons. Usuários
    descobriram combinações de cupons que resultavam em pizzas de graça ou custo negativo.

---

## Como prevenir

- [x] **Threat modeling**: para cada feature, perguntar "como isso pode ser abusado?"
- [x] **Security by Design**: incluir requisitos de segurança desde o início do design
- [x] **Princípio do menor privilégio**: usuário tem acesso mínimo necessário para sua função
- [ ] **Defense in depth**: múltiplas camadas — UI, API, banco de dados
- [ ] **Privacy by Design**: coletar apenas dados necessários (data minimization)
- [ ] **Fail secure**: em caso de erro/dúvida, negar acesso
- [ ] **Limites e quotas**: toda operação deve ter limites (rate limiting, max valor, max quantidade)
- [ ] **Revisão de lógica de negócio**: casos de edge e abuso revisados em code review

---

## Exercícios práticos

!!! question "Exercício 1 — Identifique o problema de design"
    Um sistema de e-commerce tem este fluxo de compra:

    1. Usuário adiciona itens ao carrinho
    2. Vai para checkout — preço exibido na tela
    3. Confirma compra — o **preço do carrinho é enviado no formulário POST**
    4. Backend processa o pagamento com o valor recebido

    Qual é o problema de design aqui?

    ??? success "Ver resposta"
        **Problema**: o preço não deve nunca vir do cliente! Qualquer pessoa com ferramentas básicas
        (Burp Suite, curl) pode modificar o valor no formulário POST e pagar R$0,01 por qualquer item.

        **Design correto**: o backend calcula o preço baseado nos itens do carrinho armazenados
        no servidor. O cliente envia apenas "confirmar compra com carrinho ID X", nunca o valor.

        ```python
        # ERRADO
        @app.route('/checkout', methods=['POST'])
        def checkout():
            valor = request.form['valor']  # NUNCA confiar no valor do cliente!
            processar_pagamento(valor)

        # CORRETO
        @app.route('/checkout', methods=['POST'])
        def checkout():
            carrinho_id = request.form['carrinho_id']
            # Calcula o valor sempre no servidor, com os preços do banco de dados
            carrinho = db.carrinhos.find_one({'id': carrinho_id, 'user_id': current_user.id})
            valor = calcular_total_carrinho(carrinho)  # Preços do banco, não do cliente
            processar_pagamento(valor)
        ```

!!! question "Exercício 2 — Faça o threat model básico"
    Para um sistema de publicação de comentários em um blog, liste 3 ameaças de design
    e como mitigá-las.

    ??? success "Ver solução modelo"
        **Ameaça 1 — Spam automatizado**:
        Bots postam milhares de comentários por segundo.
        *Mitigação*: rate limiting por IP e por usuário, CAPTCHA para usuários novos.

        **Ameaça 2 — XSS via comentário**:
        Usuário posta `<script>document.cookie='stolen'</script>`.
        *Mitigação*: escapar HTML em toda saída, CSP no header, sanitização server-side.

        **Ameaça 3 — Impersonação**:
        Usuário escolhe nome "Administrador" e finge ser o admin.
        *Mitigação*: mostrar nome do usuário vindo do banco (não do formulário), badge especial verificado para admins, não permitir nomes reservados.

!!! tip "Desafio extra — Hacksplaining"
    - [Business Logic Flaws](https://www.hacksplaining.com/exercises/business-logic-flaws) — explore vulnerabilidades de lógica de negócio

---

## Quiz rápido

!!! example "Pergunta 1"
    Qual a diferença entre Insecure Design (A06) e Broken Access Control (A01)?

    ??? note "Ver resposta"
        **A01 — Broken Access Control**: o sistema *tem* controle de acesso, mas está implementado incorretamente. O design era correto, mas o código falhou. Exemplo: endpoint de admin que deveria verificar permissão, mas o código não verifica.

        **A06 — Insecure Design**: o sistema *não foi planejado* para ter controle de acesso desde o início. O design em si é o problema. Exemplo: sistema projetado para ser acessível por qualquer usuário logado, sem considerar hierarquia de permissões.

!!! example "Pergunta 2"
    O que é o princípio "Fail Secure" (falha segura)?

    ??? note "Ver resposta"
        Em caso de erro ou condição inesperada, o sistema deve **negar acesso** por padrão, nunca conceder. Exemplo: se um serviço de autorização fica offline, o sistema deve bloquear todas as requisições até que o serviço volte, não deixar todo mundo passar. O oposto seria "fail open" — que deixa tudo passar em caso de erro, o que é perigoso.

!!! example "Pergunta 3"
    O que é STRIDE no contexto de threat modeling?

    ??? note "Ver resposta"
        STRIDE é um framework de categorização de ameaças criado pela Microsoft:
        - **S**poofing — falsificar identidade
        - **T**ampering — modificar dados
        - **R**epudiation — negar ter feito uma ação
        - **I**nformation Disclosure — vazar informações
        - **D**enial of Service — tornar o sistema indisponível
        - **E**levation of Privilege — obter mais permissões que o permitido

        Para cada componente do sistema, você pergunta: qual ameaça de cada categoria se aplica aqui?

---

## Referências

!!! info "Saiba mais"
    - [OWASP A06:2025 — Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
    - [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
    - [Microsoft STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
    - [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)
    - [Hacksplaining — Business Logic Flaws](https://www.hacksplaining.com/exercises/business-logic-flaws)
