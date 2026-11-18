# Método dos benchmarks

O protocolo foi definido antes da coleta. A matriz usa AES-256-GCM e
ChaCha20-Poly1305, cifração e decifração, e textos claros de 64 B, 4 KiB e
1 MiB. São 12 configurações, com 30 lotes medidos em cada uma.

## Preparação

Cada configuração recebe chave aleatória nova e um contador de nonces.
Esse contador continua em todas as fases. As mensagens seguem um padrão
fixo de bytes, com AAD fixo de 27 bytes. As entradas para decifração são
cifradas previamente com nonces distintos. Chaves não são gravadas.

## Tempo medido

`perf_counter_ns` envolve o laço de chamadas AEAD e a atribuição dos resultados
em uma lista pré-alocada. Ficam fora: criação da cifra e da chave, mensagens,
nonces, preparação dos textos cifrados para decifração, validação, escrita,
estatísticas e gráficos.

Toda saída é conferida depois. Resultados de cifração são decifrados e
comparados à mensagem; resultados de decifração são comparados diretamente.
A validação não cifra novamente com o mesmo par chave/nonce.

O intervalo inclui o laço Python, a API, o armazenamento dos retornos e a
alocação nativa das saídas. É uma medida de chamadas repetidas nesse ambiente,
não do custo isolado da primitiva.

## Fases

1. Aquecimento inicial de até 16 operações.
2. Calibração a partir de uma operação, com margem de 10%, até atingir 20 ms
   ou o limite de operações.
3. Três lotes adicionais de aquecimento na contagem calibrada.
4. Trinta rodadas com todas as configurações, invertendo a ordem a cada rodada.

A contagem fica fixa depois da calibração. Há limite de 65.536 operações e
orçamento aproximado de 64 MiB de buffers, calculado com duas vezes o
tamanho da mensagem mais a tag por operação. Objetos Python consomem memória
adicional. O alvo de duração é aproximado; lotes abaixo dele são mantidos.
Nenhuma observação é removida como outlier.

## Registros e validação

O CSV inclui todas as fases. Cada linha registra caso, fase, índice,
operações, nanossegundos e intervalo de nonces `[start, stop)`. Os intervalos
devem ser contínuos e disjuntos sob cada chave. O manifesto reúne ambiente,
configuração, calibração, hash do CSV e hashes das três fontes da medição.

A análise confere esquema, tipos, matriz, fases, calibração, contagens,
ordem e intervalos antes de gerar saídas. Uma coleta usa diretório novo e
um escritor. Arquivos brutos existentes são recusados; falhas de escrita
removem apenas arquivos novos. Uma interrupção abrupta pode deixar uma
coleta incompleta, que deve ser descartada.

## Estatísticas

O tempo de cada lote é dividido pela contagem de operações. Mediana, Q1 e
Q3 são calculados sobre essas médias; os quartis usam interpolação
`inclusive`. As barras mostram Q1–Q3, sem representar intervalos de confiança
ou percentis de chamadas individuais.

A vazão em MiB/s é `bytes * 1e9 / (median_ns * 2**20)`, usando bytes do texto
claro. AAD e tag não entram no numerador. Como a vazão é inversa ao tempo,
Q3 fornece seu limite inferior e Q1 o superior.

Frequência, afinidade e coleta de lixo não são reconfiguradas. Seus estados,
CPU, recursos, versões, relógio e carga disponíveis são registrados. Uma
execução em uma máquina não determina uma ordem universal entre algoritmos.
