# Servidor de Mensageria Segura

O servidor atua como um roteador de mensagens cifradas, garantindo confidencialidade, integridade, autenticidade e sigilo perfeito através de um protocolo criptográfico personalizado.

## Especificações de Segurança

O servidor implementa rigorosamente os seguintes mecanismos:

* **Troca de Chaves:** ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) sobre a curva `prime256v1` (P-256).
* **Autenticação do Servidor:** Assinatura RSA (2048-bit) sobre os parâmetros do handshake (`pk_S || client_id || pk_C || salt`).
* **Derivação de Chaves:** HKDF (baseado em HMAC-SHA256) para derivar chaves de sessão independentes (`c2s` e `s2c`).
* **Cifragem de Transporte:** AES-128-GCM (Authenticated Encryption).
* **Proteção contra Replay:** Validação de números de sequência (`seq_no`) monotônicos.

## Pré-requisitos

* **Node.js**: Versão 16.0.0 ou superior (necessário para suporte nativo a `crypto.hkdf` e `crypto.webcrypto`).
* **NPM** ou **Yarn**.

## Instalação

1.  Clone este repositório:
    ```bash
    git clone [https://github.com/gufernandess/multi-client-messaging.git](https://github.com/gufernandess/multi-client-messaging.git)
    cd multi-client-messaging
    ```

2.  Instale as dependências (apenas `dotenv` é necessária):
    ```bash
    npm install
    ```

## Configuração (.env)

O servidor utiliza variáveis de ambiente para configuração.

1.  Crie um arquivo chamado `.env` na raiz do projeto.
2.  Adicione as seguintes configurações (ajuste conforme necessário):

```env
# Porta onde o servidor escutará conexões TCP
SERVER_PORT=8888

# IP de bind (use 0.0.0.0 para aceitar conexões externas ou 127.0.0.1 para local)
SERVER_HOST=127.0.0.1
