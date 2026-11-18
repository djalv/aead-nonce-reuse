# Testes

```bash
python -m pytest -q
python -m pytest -q --reverse-order
```

O segundo comando inverte a ordem coletada. Isso ajuda a encontrar
dependências entre testes; não verifica todas as permutações.

## Cifras e recuperação

Os testes usam AES-GCM e ChaCha20-Poly1305 reais. Cobrem mensagens vazias,
curtas, binárias e maiores; AAD presente ou ausente; separação de tags;
XOR; recuperação integral e parcial; nonces distintos; e rejeição de entradas
adulteradas. A função do ataque é exercitada sem chave ou texto alvo.

Há nove vetores publicados: oito NIST CAVP de AES-256-GCM e um da RFC 8439,
Apêndice A.5. Sete casos válidos são verificados nas duas direções e dois
casos NIST FAIL devem produzir `InvalidTag`. As respostas esperadas foram
copiadas das fontes. A [proveniência](../tests/vectors/README.md) registra
parâmetros, seleção e hashes. Esse subconjunto não é uma certificação CAVP.

## Nonces e medições

O contador é testado em valores iniciais inválidos, carry, lotes sucessivos,
últimos valores e esgotamento. Ele não volta a zero. A integração com o
benchmark confere todas as cifragens sob cada chave, inclusive preparação,
aquecimento e calibração.

O relógio controlado permite testar contagens e limites sem exigir uma
velocidade específica. Há também verificações com relógio real. Os testes
conferem o trecho cronometrado, o protocolo, a escrita, a preservação de dados
existentes e a reprodução das estatísticas.

## Comandos e documentos

Os comandos são exercitados com saída de terminal, JSON e falhas de escrita.
A exportação de DOCX/PPTX tem testes de falta do conversor, timeout e
conversão incompleta, preservando PDFs anteriores. O teste com
LibreOffice real é executado quando ele está instalado.

A revisão técnica verificou instalações limpas em Python 3.12, 3.13 e 3.14.
Os limites do contador permanecem os mesmos: execução sequencial, estado
em memória e chave nova em nova execução. Persistência e concorrência não
fazem parte da implementação.
