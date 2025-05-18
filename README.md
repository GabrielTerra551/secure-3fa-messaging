# 🔐 Sistema de Autenticação 3FA com Criptografia Simétrica

Este projeto implementa uma autenticação segura baseada em **3 fatores (3FA)**, com envio de mensagens criptografadas de forma autenticada. Desenvolvido como atividade prática para a disciplina de Segurança em Redes (INE5680 - UFSC).

---

## ✅ Autenticação 3FA

| Fator                      | Descrição                                      |
|----------------------------|-----------------------------------------------|
| **1. Localização (IP)**    | Consulta país automaticamente via IPInfo      |
| **2. Senha**               | Derivada com SCRYPT + salt aleatório          |
| **3. TOTP**                | Código temporário gerado por app autenticador |

---

## 📦 Estrutura do Projeto

```
secure-3fa-messaging/
├── client/
│   ├── register.py        # Cadastro de usuário e envio ao servidor
│   ├── auth.py            # (Opcional) Fluxo de autenticação
│   ├── crypto.py          # Derivação de chave TOTP + cifragem AES-GCM
│   ├── send_message.py    # Autentica e envia mensagem criptografada
│
├── server/
│   ├── server_app.py      # Servidor Flask com endpoints /register e /receive
│   ├── crypto.py          # Derivação de chave e decifragem AES-GCM
│   ├── verify_auth.py     # Valida senha, TOTP e decifra o secret
│   └── user_db.json       # Armazena os usuários registrados
│
├── run_client.py          # Interface do lado cliente
├── run_server.py          # Inicializa o servidor
├── requirements.txt       # Dependências do projeto
└── README.md              # Este arquivo
```

---

## 🚀 Como executar

### 1. Instale as dependências

```bash
pip install -r requirements.txt
```

### 2. Configure o IPInfo (para geolocalização)

Cadastre-se em https://ipinfo.io/signup e defina o token:

```bash
export IPINFO_TOKEN="seu_token"
```

### 3. Inicie o servidor

```bash
python run_server.py
```

### 4. Execute o cliente

```bash
python run_client.py
```

Você verá um menu com opções para registrar e autenticar.

---

## 🔐 Fluxo detalhado

1. **Registro (`register.py`):**
   - Coleta nome, senha e telefone
   - Gera `secret` TOTP e exibe para escanear no app (Google/Microsoft Authenticator)
   - Deriva senha com SCRYPT
   - Cifra o `secret` com AES-GCM
   - Envia tudo via HTTP POST ao servidor

2. **Autenticação + Envio (`send_message.py`):**
   - Solicita usuário, senha, código TOTP e a mensagem
   - Valida a senha e decifra o `secret` do usuário
   - Deriva a chave com o código TOTP
   - Cifra a mensagem com AES-GCM
   - Envia ao servidor

3. **Servidor (`server_app.py`):**
   - Valida os 3 fatores
   - Deriva a mesma chave a partir do TOTP
   - Decifra a mensagem e retorna ao cliente

---

## 🔎 Segurança aplicada

- Criptografia simétrica autenticada (**AES-GCM**)
- Chave derivada com **PBKDF2 + código TOTP**
- Senha protegida com **SCRYPT** e salt único
- Secret TOTP **nunca salvo em claro**
- Tolerância de tempo com `valid_window=1` para pequenos desvios de relógio

---

## 🛠️ Requisitos atendidos

- [x] Autenticação com 3 fatores
- [x] Criptografia autenticada
- [x] Derivação de chave segura
- [x] Sem arquivos compartilhados entre cliente e servidor
- [x] Secret TOTP cifrado no cadastro
- [x] Servidor validando tudo localmente

---

## 👨‍💻 Autor

Desenvolvido por [Seu Nome] como projeto da disciplina INE5680 - Segurança em Redes.
