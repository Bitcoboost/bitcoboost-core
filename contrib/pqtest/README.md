# BitcoBoost — strumenti di validazione regtest dello schema ibrido bb1z (witness v2)

Provano la regola di consenso quantum-safe (ECDSA + ML-DSA-44) su un nodo regtest.

## Build
Dal vivo in `src/` dopo aver compilato il nodo:
    # libreria ML-DSA
    mkdir -p /tmp/mb && cd /tmp/mb && gcc -O2 -I ../crypto/mldsa -c ../crypto/mldsa/*.c && ar rcs /tmp/libmldsa44.a *.o
    g++ -c support/cleanse.cpp -DHAVE_CONFIG_H -I config -I . -o /tmp/cleanse.o
    # keygen (solo secp256k1 + mldsa)
    g++ -std=c++20 -I crypto/mldsa -I secp256k1/include contrib/pqtest/keygen.cpp /tmp/libmldsa44.a secp256k1/.libs/libsecp256k1.a -o /tmp/keygen
    # signer (consenso + crypto + secp256k1 + mldsa)
    g++ -std=c++20 -I . -I crypto/mldsa -I secp256k1/include contrib/pqtest/signer.cpp /tmp/cleanse.o \
      -Wl,--start-group libbitcoin_consensus.a crypto/.libs/libbitcoin_crypto_base.a crypto/.libs/libbitcoin_crypto_sse41.a \
      crypto/.libs/libbitcoin_crypto_avx2.a crypto/.libs/libbitcoin_crypto_x86_shani.a /tmp/libmldsa44.a secp256k1/.libs/libsecp256k1.a \
      -Wl,--end-group -o /tmp/signer

## Uso
- `keygen` genera ECDSA+ML-DSA, salva le chiavi in /tmp/pqreg_keys/, stampa impronta e scriptPubKey (5220<program>).
- `signer txid vout amount_sat dest_spk_hex send_sat [bad|badec]` produce la transazione di spesa firmata (raw hex).
- Si valida col consenso minando con `generateblock` (ignora la standardita' di mempool).

Esito verificato (3 giugno 2026): valida=ACCETTATA; ML-DSA o ECDSA manomessa=RIFIUTATA.
