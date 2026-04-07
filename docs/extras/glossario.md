---
title: "Glossário de Segurança Web"
description: "Definições dos principais termos técnicos usados neste guia"
---

# Glossário de Segurança Web

Definições dos termos técnicos mais usados neste guia, em ordem alfabética.

---

**ACL (Access Control List)**
:   Lista que define quais usuários ou sistemas têm permissão para acessar um recurso e quais operações podem realizar. Exemplo: "usuário A pode ler, usuário B pode ler e escrever".

**API (Application Programming Interface)**
:   Interface que permite que sistemas se comuniquem. Em segurança web, APIs são vetores frequentes de ataque por expor funcionalidades do sistema via HTTP.

**APT (Advanced Persistent Threat)**
:   Tipo de ataque sofisticado, geralmente patrocinado por estados, que busca acesso prolongado e discreto a sistemas. O grupo que atacou a SolarWinds é um exemplo de APT.

**Argon2**
:   Algoritmo vencedor do Password Hashing Competition (2015). Considerado o estado da arte para hash de senhas. Resistente a ataques de GPU por ser configurável em uso de memória. Preferido sobre bcrypt para novos sistemas.

**Attack Surface (Superfície de Ataque)**
:   Conjunto de todos os pontos de entrada de um sistema onde um atacante pode tentar causar dano. Inclui formulários web, APIs, cookies, cabeçalhos HTTP, arquivos de upload, etc.

**Authentication (Autenticação)**
:   Processo de verificar **quem você é**. Feito tipicamente por senha, token, biometria, ou combinação. Diferente de autorização.

**Authorization (Autorização)**
:   Processo de verificar **o que você pode fazer**. Após a autenticação, o sistema decide se o usuário tem permissão para a ação solicitada.

**bcrypt**
:   Algoritmo de hash de senhas baseado em Blowfish. Deliberadamente lento (com fator de custo ajustável) para dificultar ataques de força bruta. Padrão amplamente adotado para armazenamento seguro de senhas.

**CAPTCHA**
:   Teste automático para diferenciar humanos de bots. Usado para prevenir ataques automatizados como force bruta em formulários de login ou criação de contas em massa.

**CIA Triad**
:   Modelo fundamental de segurança: **C**onfidencialidade (apenas autorizados veem), **I**ntegridade (dados não foram alterados), **D**isponibilidade (sistema acessível quando necessário).

**CORS (Cross-Origin Resource Sharing)**
:   Mecanismo HTTP que controla quais origens (domínios) podem fazer requisições para uma API. Configuração incorreta de CORS é uma vulnerabilidade comum.

**CSRF (Cross-Site Request Forgery)**
:   Ataque onde um site malicioso induz o navegador da vítima a fazer requisições autenticadas a outro site sem consentimento. Prevenido com tokens CSRF e verificação de `Referer`/`Origin`.

**CVE (Common Vulnerabilities and Exposures)**
:   Sistema de identificação padronizado de vulnerabilidades de segurança. Cada CVE tem um identificador único (ex: CVE-2021-44228 = Log4Shell). Consultável em nvd.nist.gov.

**DAST (Dynamic Application Security Testing)**
:   Teste de segurança que analisa a aplicação em execução, de fora para dentro, simulando um atacante. Ferramentas: OWASP ZAP, Burp Suite.

**Defense in Depth**
:   Estratégia de segurança com múltiplas camadas de proteção independentes. Se uma camada falha, as outras ainda protegem. Analogia: castelo medieval com muralha, fosso, portão e guarda interna.

**DoS / DDoS (Denial of Service / Distributed DoS)**
:   Ataque que visa tornar um sistema indisponível, geralmente sobrecarregando com tráfego. DDoS usa múltiplos computadores (botnet) para amplificar o ataque.

**Encoding (Codificação)**
:   Transformação de dados para outro formato de representação (Base64, URL encoding, HTML entities). Não é criptografia — qualquer pessoa pode decodificar sem chave.

**Exploit**
:   Código ou técnica que aproveita uma vulnerabilidade para realizar um ataque. Pode ser público (conhecido) ou zero-day (desconhecido).

**FIDO2 / WebAuthn**
:   Padrão aberto para autenticação forte sem senha, usando criptografia de chave pública. Base das Passkeys. Elimina phishing e credential stuffing.

**Fuzzing**
:   Técnica de teste que envia entradas aleatórias ou malformadas para um sistema para descobrir falhas inesperadas. Ferramentas: AFL, Burp Suite Intruder.

**Hash**
:   Função matemática de mão única: transforma qualquer dado em um valor de tamanho fixo. Propriedades: irreversível, determinístico, avalanche effect. MD5 e SHA-1 são **fracos** para uso em segurança.

**HMAC (Hash-based Message Authentication Code)**
:   Código de autenticação de mensagem usando hash + chave secreta. Garante integridade e autenticidade. Diferente de hash simples: precisa da chave para verificar.

**HTTPS**
:   HTTP com TLS (Transport Layer Security). Criptografa e autentica a comunicação entre cliente e servidor. O cadeado no navegador indica HTTPS.

**IDOR (Insecure Direct Object Reference)**
:   Tipo de Broken Access Control onde IDs internos são expostos sem verificação de autorização. Exemplo: `/perfil/123` — atacante troca por `/perfil/124`.

**JWT (JSON Web Token)**
:   Token de autenticação autocontido em formato JSON, assinado digitalmente. Composto por header, payload e assinatura. Vulnerável a ataques se mal implementado (alg: none, chave fraca).

**KMS (Key Management Service)**
:   Serviço gerenciado de armazenamento e rotação de chaves criptográficas. Exemplos: AWS KMS, GCP Cloud KMS, HashiCorp Vault.

**LGPD (Lei Geral de Proteção de Dados)**
:   Lei brasileira (Lei 13.709/2018) que regula o tratamento de dados pessoais. Similar ao GDPR europeu. Prevê multas de até 2% do faturamento por violações.

**Man-in-the-Middle (MitM)**
:   Ataque onde o atacante se posiciona entre cliente e servidor, interceptando ou modificando a comunicação. Prevenido por TLS e certificate pinning.

**MFA / 2FA (Multi-Factor / Two-Factor Authentication)**
:   Autenticação com múltiplos fatores: algo que você sabe (senha), tem (celular/token), ou é (biometria). Aumenta drasticamente a segurança mesmo se a senha vazar.

**OWASP (Open Worldwide Application Security Project)**
:   Fundação sem fins lucrativos focada em segurança de software. Produz o Top 10, ASVS, Cheat Sheets e outros recursos gratuitos.

**Passkeys**
:   Tecnologia de autenticação sem senha baseada em FIDO2/WebAuthn. A chave privada fica no dispositivo do usuário, protegida por biometria. Eliminam phishing e force bruta.

**Path Traversal**
:   Vulnerabilidade onde entrada do usuário permite navegar fora do diretório permitido. Exemplo: `../../etc/passwd` em um parâmetro de arquivo.

**Pentest (Penetration Testing)**
:   Teste de segurança autorizado que simula ataques reais para identificar vulnerabilidades. Realizado por profissionais contratados para o fim.

**PII (Personally Identifiable Information)**
:   Dados pessoais identificáveis: nome, CPF, email, endereço, biometria. Sujeitos a regulações de privacidade (LGPD, GDPR).

**Prepared Statement**
:   Técnica de banco de dados que separa a query SQL dos dados, prevenindo SQL injection. Os dados são tratados como valores literais, nunca como código SQL.

**Rate Limiting**
:   Controle que limita o número de requisições por unidade de tempo. Previne força bruta, DoS e abuso de API.

**RCE (Remote Code Execution)**
:   Vulnerabilidade que permite ao atacante executar código arbitrário no servidor. Geralmente o pior cenário possível — controle total do sistema.

**RBAC (Role-Based Access Control)**
:   Modelo de controle de acesso onde permissões são atribuídas a papéis (roles) e usuários recebem papéis. Exemplo: `admin`, `editor`, `leitor`.

**SAST (Static Application Security Testing)**
:   Análise de segurança do código-fonte sem executá-lo. Ferramentas: Bandit (Python), SonarQube, Semgrep, CodeQL.

**SBOM (Software Bill of Materials)**
:   Lista completa de todos os componentes de software de uma aplicação, incluindo dependências e versões. Essencial para gerenciar supply chain security.

**Session Fixation**
:   Ataque onde o atacante define o ID de sessão da vítima antes do login. Prevenido regenerando o ID de sessão após autenticação bem-sucedida.

**SLSA (Supply chain Levels for Software Artifacts)**
:   Framework de segurança da cadeia de suprimentos de software, define 4 níveis de maturidade. Pronuncia-se "salsa".

**SQL Injection**
:   Vulnerabilidade onde entrada do usuário é inserida diretamente em query SQL, permitindo manipular o banco de dados. Prevenida por prepared statements.

**SRI (Subresource Integrity)**
:   Mecanismo de segurança que permite ao navegador verificar que recursos externos (scripts, CSS) não foram modificados, usando hashes criptográficos.

**SSRF (Server-Side Request Forgery)**
:   Vulnerabilidade que força o servidor a fazer requisições a destinos internos ou externos arbitrários. Pode expor serviços internos inacessíveis diretamente.

**TLS (Transport Layer Security)**
:   Protocolo criptográfico que protege a comunicação na internet. Sucessor do SSL. TLS 1.3 é a versão recomendada. Base do HTTPS.

**Threat Modeling**
:   Processo de identificar, quantificar e priorizar ameaças de segurança em um sistema antes de desenvolver ou como parte do desenvolvimento. Frameworks: STRIDE, PASTA, LINDDUN.

**XSS (Cross-Site Scripting)**
:   Injeção de scripts maliciosos em páginas web que são executados no navegador de outros usuários. Prevento com escape de saída e Content Security Policy (CSP).

**Zero Trust**
:   Arquitetura de segurança baseada no princípio "nunca confiar, sempre verificar". Não assume que qualquer usuário, dispositivo ou rede é confiável por padrão.

**Zero-Day**
:   Vulnerabilidade desconhecida pelo fabricante e para a qual não existe patch. Muito valorizada por atacantes e governos. O "zero" se refere a zero dias para correção.
