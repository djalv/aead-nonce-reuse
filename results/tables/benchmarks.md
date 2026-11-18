# AEAD benchmark results

Median of batch-mean API latencies; IQR bounds are Q1 and Q3 across batches.
Throughput uses plaintext bytes and the median latency. No samples were removed.

| Algorithm | Operation | Plaintext | Median (us/op) | Q1–Q3 (us/op) | MiB/s | Batches |
|---|---|---:|---:|---:|---:|---:|
| AES-256-GCM | encrypt | 64 B | 0.960 | 0.933–0.985 | 63.57 | 30 |
| ChaCha20-Poly1305 | encrypt | 64 B | 1.161 | 1.127–1.179 | 52.58 | 30 |
| AES-256-GCM | decrypt | 64 B | 0.956 | 0.943–0.978 | 63.86 | 30 |
| ChaCha20-Poly1305 | decrypt | 64 B | 1.178 | 1.134–1.198 | 51.80 | 30 |
| AES-256-GCM | encrypt | 4 KiB | 4.693 | 4.527–4.798 | 832.34 | 30 |
| ChaCha20-Poly1305 | encrypt | 4 KiB | 5.877 | 5.658–5.976 | 664.63 | 30 |
| AES-256-GCM | decrypt | 4 KiB | 5.037 | 4.891–5.092 | 775.49 | 30 |
| ChaCha20-Poly1305 | decrypt | 4 KiB | 6.111 | 6.016–6.231 | 639.17 | 30 |
| AES-256-GCM | encrypt | 1 MiB | 868.854 | 851.171–881.085 | 1150.94 | 30 |
| ChaCha20-Poly1305 | encrypt | 1 MiB | 1145.447 | 1130.180–1178.155 | 873.02 | 30 |
| AES-256-GCM | decrypt | 1 MiB | 893.022 | 879.074–906.070 | 1119.79 | 30 |
| ChaCha20-Poly1305 | decrypt | 1 MiB | 1181.311 | 1173.502–1206.124 | 846.52 | 30 |
