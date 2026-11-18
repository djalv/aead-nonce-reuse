# Demonstração da reutilização de nonce

Os dois algoritmos usam chaves de 32 bytes, nonces de 12 bytes e tags de
16 bytes. A biblioteca retorna corpo e tag concatenados. O programa separa
a tag antes de aplicar XOR; os cálculos são feitos em bytes.

## Casos

Cada algoritmo executa a mesma sequência:

1. Cifração e decifração com entradas válidas.
2. A mesma mensagem cifrada com nonces distintos.
3. Duas mensagens com nonces distintos e tentativa de recuperação.
4. As mesmas mensagens com nonce repetido e nova tentativa.
5. Recuperação parcial, com 16 bytes conhecidos e um alvo de 54 bytes.
6. Alterações de corpo, tag, AAD, chave, nonce e truncamento nos dois contextos.

As entradas são públicas e fixas para reproduzir o exemplo. A reutilização
é deliberada. O caso parcial usa outro nonce para que o texto conhecido maior
de outro cenário não revele o restante da mensagem.

## Recuperação

Se o fluxo S se repete:

```text
C1 = P1 XOR S
C2 = P2 XOR S
C1 XOR C2 = P1 XOR P2
P2 = P1 XOR C1 XOR C2
```

`recover_plaintext` recebe apenas o texto conhecido e os dois corpos
cifrados. As entradas começam na mesma posição do fluxo. A recuperação
termina no menor comprimento disponível. Chave, nonce, tag e texto alvo
não são parâmetros da função. O experimento usa o alvo depois, para conferir
o candidato produzido.

## Resultado

| Caso | AES-256-GCM | ChaCha20-Poly1305 |
|---|---|---|
| Ida e volta | Correta | Correta |
| Ataque com nonces distintos | Não recuperou este alvo | Não recuperou este alvo |
| Ataque com nonce repetido | 33 de 33 bytes | 33 de 33 bytes |
| Conhecimento parcial | 16 de 54 bytes | 16 de 54 bytes |
| Alterações nos dois contextos | Todas rejeitadas | Todas rejeitadas |

Foram rejeitados 24 casos de entradas inválidas. Essas alterações não
constroem uma tag válida substituta; portanto, sua rejeição não demonstra
autenticação segura após repetir nonce. Recuperação de chave e falsificação
de tags não foram implementadas.

## Repetir o exemplo

```bash
python -m nonce_reuse demo
python -m nonce_reuse demo --json --output build/security-demonstrations.json
```

O registro da execução está em `results/raw/security-demonstrations.json`.
O programa exige todos os casos antes de aceitar os resultados. Os valores
originais e as mensagens em inglês foram preservados.

As construções e os efeitos da repetição estão descritos no
[NIST SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D) e na
[RFC 8439, seção 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-4).
