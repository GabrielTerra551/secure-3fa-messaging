# 🔐 Sistema de Autenticação 3FA com Criptografia Simétrica

Implementação prática de autenticação de três fatores (3FA) com comunicação segura entre cliente e servidor,
em conformidade com princípios de isolamento de contexto. Desenvolvido para a disciplina de Segurança em Redes (INE5680 - UFSC).

---

## 📋 Descrição

Este projeto demonstra um sistema de autenticação 3FA com criptografia simétrica (AES-GCM). Ele utiliza:

- 🌍 Fator 1: Localização baseada em IP (consulta via IPInfo)
- 🔑 Fator 2: Senha derivada com SCRYPT + salt aleatório
- 🔄 Fator 3: TOTP (Time-based One-Time Password) com secret armazenado cifrado

---

## 🧱 Arquitetura

```
[ CLIENTE ]                             [ SERVIDOR ]
    |                                         |
    | -- POST /register --------------------> |  ← Registro de usuário (dados, secret cifrado)
    |                                         |
    | -- POST /receive ---------------------> |  ← Autenticação 3FA e mensagem cifrada
```

---

## 🗃️ Estrutura do Projeto

```
secure-3fa-messaging/
├── client/               # Código do lado cliente
│   ├── register.py       # Coleta dados e envia cadastro via POST
│   ├── auth.py           # Autenticação e TOTP
│   ├── crypto.py         # Criptografia com AES-GCM
│   ├── send_message.py   # Envia mensagem criptografada ao servidor
│
├── server/               # Código do lado servidor
│   ├── server_app.py     # Endpoints /register e /receive
│   ├── verify_auth.py    # Verificação dos 3 fatores
│   ├── crypto.py         # Decifragem da mensagem recebida
│   └── user_db.json      # Base local de dados do servidor (somente servidor escreve)
│
├── utils/                # Utilitários auxiliares
│   ├── ipinfo_lookup.py  # Localização via IP
│   └── qr_generator.py   # Geração de QR code para TOTP
│
├── run_client.py         # Interface do lado cliente
├── run_server.py         # Inicializa o servidor Flask
├── requirements.txt      # Dependências
└── README.md             # Documentação (este arquivo)
```

---

## 🚀 Como Executar

### 1. Instale as dependências

```bash
pip install -r requirements.txt
```

### 2. Inicie o servidor

```bash
python run_server.py
```

### 3. Execute o cliente

```bash
python run_client.py
```

O menu permite:
- Registrar um novo usuário
- Autenticar e enviar mensagem criptografada

---

## 🔐 Segurança Implementada

- Senhas derivadas com **SCRYPT + salt aleatório**
- Secret TOTP **cifrado com AES-GCM** no lado cliente
- Nenhum arquivo compartilhado entre cliente e servidor
- TOTP validado com `pyotp`
- Criptografia autenticada (AES-GCM) para mensagens
- Chave simétrica derivada dinamicamente a partir do código TOTP (PBKDF2-like)

---

## 🌐 IPInfo

Para usar a localização via IP, crie um token gratuito em https://ipinfo.io/signup e defina a variável de ambiente:

```bash
export IPINFO_TOKEN="seu_token"
```

---

## ✅ Conformidade com o Enunciado

- [x] Isolamento entre cliente e servidor
- [x] Criptografia simétrica autenticada (AES-GCM)
- [x] Chave derivada do TOTP
- [x] Secret TOTP cifrado
- [x] Senha derivada com SCRYPT
- [x] Sem variáveis ou arquivos compartilhados

---

## 🧑‍💻 Autor

Este projeto foi desenvolvido como parte da disciplina INE5680 — Segurança em Redes — UFSC.