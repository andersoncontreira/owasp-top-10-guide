---
title: "A04:2025 — Cryptographic Failures"
description: "Falhas criptográficas: quando dados sensíveis ficam expostos por proteção inadequada"
tags: [criptografia, senhas, tls, crítico, a04]
---

# A04:2025 — Cryptographic Failures

<span style="background-color: #c0392b; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold;">RISCO CRÍTICO</span>

> **Analogia**: Imagine escrever sua senha num papel e guardar dentro de um envelope translúcido. Quem olhar de perto consegue ler. A proteção existe, mas é inadequada para o nível de sensibilidade da informação.

---

## O que é?

=== "🟢 Para leigos"
    Criptografia é o processo de embaralhar informações para que apenas quem tem a "chave"
    consiga ler. Falhas criptográficas acontecem quando:

    - Dados sensíveis (senhas, cartões de crédito, dados de saúde) são guardados ou
      transmitidos **sem proteção** ou com **proteção fraca**
    - A proteção é feita de forma errada — como usar um cadeado que qualquer pessoa consegue abrir

    Exemplos práticos: site que usa HTTP em vez de HTTPS, sistema que guarda senhas sem
    criptografia (em texto puro), ou que usa algoritmos de criptografia ultrapassados.

=== "🟡 Desenvolvedor júnior"
    Cryptographic Failures incluem:

    - **Dados em trânsito sem TLS**: HTTP em vez de HTTPS, protocolos antigos (SSLv3, TLS 1.0)
    - **Senhas em texto puro**: `SELECT * FROM users WHERE password='abc123'`
    - **Hashing fraco de senhas**: MD5, SHA-1 para armazenar senhas (não são para isso!)
    - **Chaves hardcoded**: `SECRET_KEY = "minha_chave_123"` no código-fonte
    - **Geração de números aleatórios insegura**: `random.random()` para tokens de segurança
    - **Algoritmos obsoletos**: DES, RC4, MD5 para dados sensíveis

=== "🔴 Desenvolvedor sênior"
    A diferença entre hashing e criptografia é fundamental:

    - **Hash (one-way)**: para senhas — bcrypt, Argon2, scrypt. Sem reversão possível.
    - **Criptografia simétrica**: AES-256-GCM para dados em repouso.
    - **Criptografia assimétrica**: RSA-2048+, ECDSA para troca de chaves e assinaturas.

    Vetores críticos em 2025:

    - **Key management**: chaves rotacionadas? Armazenadas em HSM ou KMS?
    - **Certificate transparency**: monitorar CT logs para certificados fraudulentos
    - **Post-quantum readiness**: algoritmos como CRYSTALS-Kyber (NIST PQC 2024)
    - **Padding oracle attacks**: AES-CBC sem autenticação (use AES-GCM)
    - **JWT com `alg: none`**: vulnerabilidade clássica em implementações de JWT

---

## Código vulnerável vs. seguro

=== "❌ Senhas em texto puro"
    ```python
    # NUNCA faça isso!
    def criar_usuario(username, password):
        # Armazenar senha em texto puro — catastrófico se banco vazar
        usuario = {
            'username': username,
            'password': password  # "123456" fica como "123456" no banco
        }
        db.usuarios.insert(usuario)

    def verificar_login(username, password):
        # Comparar diretamente com texto puro
        usuario = db.usuarios.find_one({'username': username})
        if usuario and usuario['password'] == password:
            return True
        return False
    ```

=== "✅ Senhas com bcrypt"
    ```python
    from flask_bcrypt import Bcrypt
    import secrets

    bcrypt = Bcrypt()

    def criar_usuario(username, password):
        # bcrypt gera salt automaticamente e aplica múltiplas rodadas de hash
        # O resultado é diferente cada vez, mesmo para a mesma senha
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        usuario = {
            'username': username,
            'password_hash': password_hash  # Guarda apenas o hash, nunca a senha
        }
        db.usuarios.insert(usuario)

    def verificar_login(username, password):
        usuario = db.usuarios.find_one({'username': username})
        if usuario and bcrypt.check_password_hash(usuario['password_hash'], password):
            return True
        return False  # Resposta em tempo constante para evitar timing attacks

    def gerar_token_reset_senha():
        # Para tokens de segurança, SEMPRE usar secrets (criptograficamente seguro)
        # NUNCA usar random.random() ou random.randint()
        return secrets.token_urlsafe(32)  # 256 bits de entropia
    ```

=== "✅ Dados sensíveis com AES-GCM"
    ```python
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    import base64

    def criptografar_dado_sensivel(dado: str, chave: bytes) -> str:
        """
        Criptografa dados sensíveis (CPF, cartão, etc.) para armazenamento.
        Usa AES-256-GCM: autenticado, seguro contra tampering.
        """
        # Nonce deve ser ÚNICO para cada criptografia com a mesma chave
        # 12 bytes é o tamanho recomendado para AES-GCM
        nonce = os.urandom(12)

        aesgcm = AESGCM(chave)
        dado_cifrado = aesgcm.encrypt(nonce, dado.encode(), None)

        # Guarda nonce + dado cifrado juntos (nonce não é segredo)
        return base64.b64encode(nonce + dado_cifrado).decode()

    def descriptografar_dado_sensivel(dado_cifrado_b64: str, chave: bytes) -> str:
        """
        Descriptografa e VERIFICA integridade do dado.
        AES-GCM detecta qualquer modificação no dado cifrado.
        """
        dado_cifrado = base64.b64decode(dado_cifrado_b64)
        nonce = dado_cifrado[:12]
        cifrado = dado_cifrado[12:]

        aesgcm = AESGCM(chave)
        # Se o dado foi modificado, lança InvalidTag — não retorna dado corrompido
        return aesgcm.decrypt(nonce, cifrado, None).decode()

    # A CHAVE deve vir do KMS (AWS KMS, GCP Cloud KMS) ou variável de ambiente
    # NUNCA hardcode: chave = b"minha_chave_secreta"
    chave = bytes.fromhex(os.environ['ENCRYPTION_KEY'])
    ```

---

## Cenário de ataque real

!!! danger "Cenário de ataque real — Vazamento de banco com MD5"
    **Situação**: Um fórum popular armazena senhas usando MD5 simples, sem salt.

    **Ataque**:

    1. Atacante obtém o banco de dados por SQL injection ou acesso indevido
    2. Encontra: `usuario: joao_silva, senha_hash: 5f4dcc3b5aa765d61d8327deb882cf99`
    3. Faz uma busca simples no Google: `"5f4dcc3b5aa765d61d8327deb882cf99"`
    4. Google retorna imediatamente: esse hash é `password`
    5. Usa rainbow tables para crackear 90% das senhas em minutos
    6. Com as senhas, acessa contas do fórum E tenta as mesmas senhas em outros serviços

    **Consequência**: Comprometimento em cascata — usuários que reutilizam senha têm email,
    banco e outros serviços comprometidos. O que deveria ser "só um fórum" se torna um vetor
    para ataques muito mais sérios.

    **Caso real**: RockYou (2009) — 32 milhões de senhas em texto puro vazadas.
    LinkedIn (2012) — 117 milhões de hashes MD5 sem salt, maioria crackada em horas.

---

## Como prevenir

- [x] **HTTPS obrigatório**: TLS 1.2+ em toda comunicação, sem fallback para HTTP
- [x] **bcrypt/Argon2 para senhas**: nunca MD5, SHA-1 ou SHA-256 diretamente para senhas
- [x] **Chaves em variáveis de ambiente**: nunca hardcoded no código ou em repositórios
- [ ] **AES-256-GCM para dados em repouso**: dados sensíveis criptografados no banco
- [ ] **KMS para gerenciamento de chaves**: AWS KMS, GCP Cloud KMS, HashiCorp Vault
- [ ] **Rotação de chaves**: política de rotação periódica de chaves criptográficas
- [ ] **Não inventar criptografia**: usar bibliotecas testadas (libsodium, cryptography.io)
- [ ] **Verificar configuração TLS**: Mozilla SSL Configuration Generator para nginx/apache

---

## Exercícios práticos

!!! question "Exercício 1 — Por que MD5 é inseguro para senhas?"
    Dado que MD5("password") = `5f4dcc3b5aa765d61d8327deb882cf99`, explique por que
    armazenar esse hash é inseguro, mesmo que não seja a senha direta.

    ??? success "Ver resposta"
        **Problema 1 — Rainbow tables**: tabelas pré-computadas com milhões de hashes MD5
        permitem lookup instantâneo. O hash acima é encontrado imediatamente em qualquer
        rainbow table.

        **Problema 2 — Velocidade**: MD5 é extremamente rápido. Uma GPU moderna calcula
        **50 bilhões de MD5 por segundo**. Um atacante com 4 GPUs consegue testar todas as
        senhas de 8 caracteres em poucas horas.

        **Problema 3 — Sem salt**: dois usuários com a mesma senha têm o mesmo hash, permitindo
        identificar facilmente grupos de usuários com senhas comuns.

        **Por que bcrypt funciona**: bcrypt é deliberadamente lento (ajustável com `cost factor`),
        inclui salt automático por design, e uma GPU moderna consegue calcular apenas
        **~5.000 bcrypt/segundo** — tornando ataques de força bruta impraticáveis.

!!! question "Exercício 2 — Corrija o código"
    Este código tem múltiplos problemas criptográficos. Identifique e corrija:

    ```python
    import hashlib
    import random
    import string

    # Chave de criptografia hardcoded
    SECRET_KEY = "chave_super_secreta_123"

    def hash_senha(senha):
        # Usar SHA-256 diretamente para senhas
        return hashlib.sha256(senha.encode()).hexdigest()

    def gerar_token():
        # Gerar token de recuperação de senha
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(16))
    ```

    ??? success "Ver solução modelo"
        ```python
        import bcrypt
        import secrets
        import os

        # Chave vem de variável de ambiente — nunca hardcoded
        # SECRET_KEY = os.environ['SECRET_KEY']

        def hash_senha(senha: str) -> str:
            """
            Usa bcrypt — inclui salt automático, é lento por design,
            e resiste a ataques de GPU.
            """
            # bcrypt gera um salt aleatório internamente
            # O cost factor padrão (12) significa 2^12 = 4096 iterações
            password_bytes = senha.encode('utf-8')
            hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=12))
            return hashed.decode('utf-8')

        def verificar_senha(senha: str, hash_armazenado: str) -> bool:
            """Verificação em tempo constante — evita timing attacks."""
            return bcrypt.checkpw(
                senha.encode('utf-8'),
                hash_armazenado.encode('utf-8')
            )

        def gerar_token() -> str:
            """
            secrets.token_urlsafe usa os.urandom() — fonte segura de aleatoriedade.
            random.choice() NÃO é seguro para fins criptográficos.
            """
            return secrets.token_urlsafe(32)  # 32 bytes = 256 bits de entropia
        ```

!!! tip "Desafio extra — Hacksplaining"
    - [Password Storage](https://www.hacksplaining.com/exercises/password-mismanagement) — pratique a vulnerabilidade de armazenamento inseguro de senhas

---

## Quiz rápido

!!! example "Pergunta 1"
    Qual a diferença entre **hash**, **criptografia** e **encoding** (codificação)?

    ??? note "Ver resposta"
        - **Hash**: processo **irreversível** de gerar uma "impressão digital" de um dado. Mesma entrada sempre gera mesmo hash. Não tem chave. Usado para senhas e verificação de integridade.
        - **Criptografia**: processo **reversível** que usa uma chave. Com a chave certa, você recupera o dado original. Usado para dados que precisam ser lidos depois.
        - **Encoding** (Base64, Hex, URL encoding): apenas **muda o formato de representação**, sem segurança. Base64("abc") pode ser decodificado por qualquer pessoa sem chave.

!!! example "Pergunta 2"
    Por que `random.random()` do Python **não deve** ser usado para gerar tokens de segurança?

    ??? note "Ver resposta"
        `random.random()` usa o algoritmo Mersenne Twister, que é um PRNG (Pseudo-Random Number Generator) — ótimo para simulações e jogos, mas **não criptograficamente seguro**. Com saídas suficientes, é matematicamente possível reconstruir o estado interno e prever números futuros. Use sempre `secrets.token_urlsafe()` ou `os.urandom()` para fins de segurança.

!!! example "Pergunta 3"
    O que é **TLS** e por que versões antigas (SSLv3, TLS 1.0, TLS 1.1) são inseguras?

    ??? note "Ver resposta"
        TLS (Transport Layer Security) é o protocolo que protege a comunicação na internet (o "S" do HTTPS). Versões antigas têm vulnerabilidades conhecidas: SSLv3 tem POODLE, TLS 1.0 tem BEAST, ambas permitem ataques de downgrade. TLS 1.2 e 1.3 são os únicos aceitos hoje. TLS 1.3 (2018) é mais rápido e remove algoritmos inseguros por design.

---

## Referências

!!! info "Saiba mais"
    - [OWASP A04:2025 — Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
    - [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
    - [Mozilla SSL Config Generator](https://ssl-config.mozilla.org/) — gera config TLS segura
    - [Have I Been Pwned](https://haveibeenpwned.com/) — verifique se seu email foi em vazamentos
    - [Hacksplaining — Password Mismanagement](https://www.hacksplaining.com/exercises/password-mismanagement)
    - CVE-2012-6082 — phpBB MD5 password hash weakness
