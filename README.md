# Reutilização de nonce em AES-GCM e ChaCha20-Poly1305

Álvaro Cândido de Oliveira Neto — Criptografia, UFMG, 2026/2.

O projeto mostra como a repetição de um nonce sob a mesma chave permite
recuperar uma mensagem a partir de outra conhecida. Compara os dois algoritmos
com nonces distintos e repetidos, testa entradas adulteradas e mede os tempos
de cifração e decifração para mensagens de 64 B, 4 KiB e 1 MiB.

- [Relatório](report/report.pdf) ([DOCX](report/report.docx)).
- [Apresentação](slides/slides.pdf) ([PPTX](slides/slides.pptx)).
- [Demonstração em seis páginas](slides/demo-backup.pdf) ([PPTX](slides/demo-backup.pptx)).

## Instalação

Use Python 3.12, 3.13 ou 3.14. Na raiz do projeto:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python -m pip install --no-deps -e .
source .venv/bin/activate
```

No Windows, use `.venv\Scripts\python.exe` e ative o ambiente com
`.\.venv\Scripts\Activate.ps1` no PowerShell.
Também é possível instalar com `uv sync --locked` e executar os comandos
abaixo com `uv run`. Depois da instalação, os experimentos funcionam offline.

## Demonstração e medições

```bash
python -m nonce_reuse check
python -m nonce_reuse demo
python -m nonce_reuse demo --json --output build/security-demonstrations.json
```

`check` verifica as cifras e a geração de gráficos. `demo` exibe a recuperação
integral e parcial nos dois algoritmos. Suas chaves e mensagens são dados
públicos de teste. A função de recuperação recebe somente o texto conhecido
e os dois corpos cifrados; o alvo é usado depois para conferir o resultado.

```bash
python -m nonce_reuse analyze --input-dir results/raw --output-dir build/analysis
python -m nonce_reuse benchmark --output-dir build/new-run
```

`analyze` refaz os resumos dos dados arquivados. `benchmark` faz uma nova coleta
com 30 lotes por configuração e alvo de calibração de 20 ms. Use um diretório
novo para cada coleta; o programa recusa sobrescrever dados brutos existentes.
Os tempos de uma nova execução serão diferentes.

O [método](docs/benchmark-method.md) descreve a medição;
os [resultados](docs/benchmark-results.md) discutem os valores obtidos.
Os [casos da demonstração](docs/security-demonstrations.md) detalham a recuperação
e os limites dos testes de adulteração.

## Testes

```bash
python -m pytest -q
python -m pytest -q --reverse-order
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy
```

Os testes usam as cifras reais e nove vetores publicados pelo NIST e pela
RFC 8439. A [descrição da suíte](docs/testing.md) explica a cobertura e a
[origem dos vetores](tests/vectors/README.md) registra a seleção e os hashes.
O teste de integração da exportação de PDFs requer LibreOffice e é ignorado
quando o programa não está instalado. Não há limiar de desempenho para aprovar
os testes.

## Documentos e dados

Os DOCX e PPTX podem ser editados no Google Docs, Google Slides ou LibreOffice.
Para exportar os três PDFs localmente com LibreOffice:

```bash
python -m nonce_reuse docs --output-dir build/documents
```

Confira a exportação antes de substituir os PDFs em `report/` e `slides/`.
As seis imagens em `slides/demo-backup/` correspondem às páginas da demonstração;
o [registro de terminal](slides/demo-transcript.txt) mostra a saída do comando.

Os [dados da coleta](results/README.md) ficam em `results/raw/`, com resumos
em `results/tables/` e gráficos em `results/figures/`. As três
[fontes usadas na medição](results/measurement-source/README.md) foram preservadas
separadamente do código atual em `src/nonce_reuse/`.

## Referências

- [NIST SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D).
- [RFC 8439 — ChaCha20 e Poly1305](https://www.rfc-editor.org/rfc/rfc8439.html).
- [RFC 5116 — interface AEAD](https://www.rfc-editor.org/rfc/rfc5116.html).
- [APIs AEAD de cryptography 50.0.2](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/).
