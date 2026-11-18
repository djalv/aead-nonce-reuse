# Vetores de teste AEAD

`aead.json` contém os nove casos publicados usados na suíte.
Chaves, nonces, AAD, textos claros, cifrados e tags foram copiados das fontes
abaixo. As saídas esperadas não foram geradas pela implementação sob teste.
A suíte lê o arquivo local sem baixar referências durante a execução.

## NIST CAVP

Fonte: [vetores GCM](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip), indicados na
[página de modos de bloco do NIST](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes).

Todos usam chave de 256 bits, IV de 96 bits e tag de 128 bits. PT e AAD são
comprimentos em bits. `Count` identifica um registro dentro de seu grupo de
parâmetros, não um identificador global.

| Arquivo de origem | PT em bits | AAD em bits | Count | Resultado |
|---|---:|---:|---:|---|
| `gcmEncryptExtIV256.rsp` | 0 | 0 | 0 | Aceitar |
| `gcmEncryptExtIV256.rsp` | 128 | 0 | 0 | Aceitar |
| `gcmEncryptExtIV256.rsp` | 128 | 160 | 0 | Aceitar |
| `gcmEncryptExtIV256.rsp` | 408 | 160 | 0 | Aceitar |
| `gcmDecrypt256.rsp` | 0 | 160 | 1 | Aceitar |
| `gcmDecrypt256.rsp` | 408 | 160 | 2 | Aceitar |
| `gcmDecrypt256.rsp` | 0 | 0 | 1 | Rejeitar (`FAIL`) |
| `gcmDecrypt256.rsp` | 128 | 160 | 4 | Rejeitar (`FAIL`) |

Seleção: primeiro registro do grupo requerido com aceitação ou rejeição
esperada. São cobertos dados vazios, blocos completos e parciais, AAD não
vazio e falhas publicadas. `plaintext_hex` é `null` nos casos `FAIL`, pois
a fonte não fornece texto claro autenticado.

SHA-256 do ZIP obtido:

```text
f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023
```

SHA-256 dos arquivos originais, incluindo suas terminações de linha:

```text
gcmEncryptExtIV256.rsp
4448b4998c3f58cd9f5542ddf7c573189a721ff3d3ac24cd5177bb4910a787f8

gcmDecrypt256.rsp
ed318735a517d5a85c82d2846c23dcf56e57a352fb0f0a163d9e7617a7bd12ad
```

## RFC 8439

Fonte: [Apêndice A.5](https://www.rfc-editor.org/rfc/rfc8439.html#appendix-A.5).
O [texto da RFC](https://www.rfc-editor.org/rfc/rfc8439.txt) contém todos os valores em hexadecimal.

O caso usa chave de 32 bytes, nonce de 12, AAD de 12, texto claro/cifrado de
265 bytes e tag de 16. O texto claro foi copiado da tabela hexadecimal,
preservando exatamente aspas UTF-8 e barras.

SHA-256 do texto obtido:

```text
25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c
```

## Verificações e limites

O JSON identifica fontes, parâmetros, contagens NIST e fingerprints. Casos
válidos são testados nas duas direções: cifração deve coincidir com corpo e
tag publicados, e decifração com texto claro publicado. Casos `FAIL` devem
gerar `InvalidTag`.

Os testes verificam esse subconjunto; não representam certificação CAVP. O corpus NIST completo não é distribuído nem executado. Todos
os valores são dados públicos de teste, não chaves ou nonces operacionais.
