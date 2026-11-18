# Código usado na coleta

Estes arquivos são as três fontes identificadas por
`measurement_code_sha256` no manifesto `../raw/benchmark-environment.json`.
Seus bytes foram preservados depois das melhorias no código mantido em
`src/nonce_reuse/`.

Não edite nem reformate estas cópias. Elas permitem conferir de onde vieram
as medições, sem manter duas implementações em paralelo. O código atual
inclui validações posteriores e usa os mesmos dados para refazer a análise.

Para repetir a implementação original, trabalhe em uma cópia isolada,
substitua os três arquivos correspondentes em `src/nonce_reuse/` e grave
em um diretório novo. A repetição não produzirá tempos idênticos.
