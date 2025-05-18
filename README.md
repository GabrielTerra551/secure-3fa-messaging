# 🔐 Sistema de Mensagens Seguras com Autenticação 3FA

Este projeto implementa um sistema seguro de envio de mensagens usando **autenticação multifator (3FA)** e **criptografia simétrica autenticada (AES-GCM)** com **derivação de chaves via SCRYPT e PBKDF2**, conforme exigências da disciplina de Segurança em Redes.

---

## ✅ Funcionalidades

- Autenticação com **3 fatores**:
  1. Senha (derivada com Scrypt)
  2. Código TOTP (Google/Microsoft Authenticator)
  3. Localização (país obtido via IP)

- Cifragem de mensagens com **AES-GCM**
- Chaves derivadas com **PBKDF2HMAC**
- IV (nonce) derivado via **PBKDF2** com salt aleatório
- Nenhum dado compartilhado entre cliente e servidor (persistência isolada)
- Mensagens transmitidas com integridade e confidencialidade

---

## 📦 Estrutura

```
secure-3fa-messaging/
├── client/
│   ├── register.py         # Cadastro de usuários
│   ├── crypto.py           # Derivação de chaves e IV + cifragem
│   ├── send_message.py     # Montagem da requisição de envio
│
├── server/
│   ├── server_app.py       # Flask server com rotas /register e /receive
│   ├── verify_auth.py      # Validação de senha, TOTP e localização
│   ├── crypto.py           # Decifragem da mensagem (PBKDF2 + AES-GCM)
│   ├── user_db.json        # Banco de dados local de usuários
│
├── run_client.py           # Menu principal de operação do lado cliente
├── run_server.py           # Inicializa servidor Flask
├── requirements.txt        # Dependências do projeto
```

---

## 🚀 Como Executar

### 1. Instale as dependências

```bash
pip install -r requirements.txt
```

### 2. Configure o token do IPInfo

Cadastre-se em [ipinfo.io](https://ipinfo.io/signup) e configure a variável:

```bash
export IPINFO_TOKEN="seu_token"
```

### 3. Inicie o servidor

```bash
python run_server.py
```

### 4. No cliente, execute:

```bash
python run_client.py
```

---

## 🛠️ Detalhes Técnicos

### 🔐 Derivação de chaves e IV

| Tipo              | Técnica usada                      | Algoritmo     |
|-------------------|------------------------------------|---------------|
| Chave da senha    | Scrypt                             | 32 bytes      |
| Chave da mensagem | PBKDF2HMAC com código TOTP         | 32 bytes      |
| IV (nonce)        | PBKDF2HMAC com TOTP + salt aleatório | 12 bytes    |

---

## 🧪 Exemplo de Fluxo

1. Usuário se registra com nome, senha e app TOTP.
2. Cliente gera `secret`, criptografa com chave derivada da senha, e envia ao servidor.
3. Mensagem é cifrada com AES-GCM usando chave TOTP + IV derivado via PBKDF2.
4. Servidor autentica o usuário, deriva chave e IV da mesma forma, e decifra a mensagem.

---

## 📄 Observações

- Todos os dados transmitidos via JSON estão codificados em **hex** (não base64).
- O IV **não é aleatório puro** — é derivado com PBKDF2 como exigido no critério II.
- O código TOTP é usado duas vezes: para autenticar e para derivar a chave de criptografia.

---

## 👨‍💻 Autor

Trabalho desenvolvido por Gabriel Terra & Pedro Rushel para a disciplina INE5680 - Segurança em Redes  
Universidade Federal de Santa Catarina – UFSC