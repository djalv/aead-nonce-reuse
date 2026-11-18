# Dados do estudo

`raw/` contém o JSON da demonstração, o CSV com todos os lotes e o manifesto
do ambiente. `tables/` e `figures/` contêm a análise original em inglês.
As três fontes exatas identificadas no manifesto estão em
`measurement-source/`.

Esses registros preservam a coleta original. Os gráficos em português do
relatório e dos slides ficam em `slides/figures/` e usam os mesmos valores.

Para conferir a análise sem substituir os arquivos:

```bash
python -m nonce_reuse analyze --input-dir results/raw --output-dir build/analysis
```

Os resumos devem coincidir com os arquivados. Para medir novamente, escolha
outro diretório; os tempos serão diferentes. O hash do manifesto detecta
divergência em relação ao CSV, mas não autentica quem produziu o conjunto.
