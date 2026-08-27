# bb-pqwallet — portafoglio quantum-safe BitcoBoost (guida d'uso)

Strumento di firma per gli indirizzi **bb1z** (resistenti al quantum): genera e custodisce le
**due chiavi** (ECDSA classica + ML-DSA-44 post-quantum), crea le transazioni firmate, e lascia
al nodo solo il compito di trasmetterle. **Il progetto non custodisce mai le chiavi**: stanno solo
nel file di backup, in mano all'utente.

Validato su regtest (4 giugno 2026): generazione, backup cifrato, rilettura, spesa accettata,
manomissioni respinte. Binario installato in `/usr/local/bin/bb-pqwallet`.

---

## I tre comandi

### 1) Creare un nuovo portafoglio
```
bb-pqwallet new <file_backup> <passphrase> [mainnet|regtest]
```
Esempio:
```
bb-pqwallet new mio-portafoglio.bbpq "una-frase-lunga-e-segreta" mainnet
```
Stampa l'**indirizzo bb1z** da dare a chi ti deve pagare, e crea il file di backup **cifrato**.

### 2) Rivedere il proprio indirizzo
```
bb-pqwallet addr <file_backup> <passphrase>
```

### 3) Firmare una spesa
```
bb-pqwallet sign <file_backup> <passphrase> <txid> <vout> <importo_sat> <scriptPubKey_dest_hex> <invio_sat>
```
- `txid` `vout` `importo_sat`: la moneta da spendere (output ricevuto sull'indirizzo bb1z).
- `scriptPubKey_dest_hex`: dove mandare (lo ottieni con `bitcoin-cli getaddressinfo <indirizzo>` campo `scriptPubKey`).
- `invio_sat`: quanto inviare; la **differenza** con `importo_sat` è la commissione di rete.

Lo strumento stampa la transazione firmata (hex). La trasmetti col nodo:
```
bitcoin-cli sendrawtransaction <hex>
```
Le spese v2 sono ora **standard per il relay**: `sendrawtransaction` le accetta e la rete le propaga normalmente (verificato su regtest).

### 4) Trovare le monete ricevute
Lo strumento non tiene un saldo da solo: per scoprire le monete arrivate sull'indirizzo si chiede al nodo.
```
bb-pqwallet desc <file_backup> <passphrase>        # stampa: raw(5220...)
bitcoin-cli scantxoutset start '["raw(5220...)"]'  # elenca le monete (txid, vout, amount)
```

### 5) Pagare combinando più monete
```
bb-pqwallet sign-multi <file_backup> <passphrase> <scriptPubKey_dest_hex> <invio_sat> \
    <txid1:vout1:amount_sat1> <txid2:vout2:amount_sat2> ...
```
Combina più entrate in un'unica transazione (utile per pagamenti che superano una singola moneta o per
consolidare). La commissione è la differenza tra la somma degli importi e `invio_sat`. Si trasmette con
`bitcoin-cli sendrawtransaction <hex>`.

---

## Sicurezza del backup (IMPORTANTE)
- Il file è cifrato con **ChaCha20-Poly1305**; la chiave nasce dalla passphrase con
  **PBKDF2-HMAC-SHA512** (600.000 giri). Passphrase sbagliata = file illeggibile.
- **Senza il file E la passphrase, le monete sono perse per sempre.** Nessuno può recuperarle (è il
  prezzo della resistenza al quantum: nessun custode centrale).
- Conserva il file in più copie sicure e la passphrase separatamente. Usa una passphrase lunga.
- La chiave segreta ML-DSA è grande (2560 byte): per questo il backup pesa ~4 KB. È normale.

---

## Cosa fa dentro (in breve)
- Chiavi generate con il generatore casuale sicuro del sistema operativo (`getrandom`).
- Indirizzo = `bb1z…` (witness versione 2, bech32m). Impronta = SHAKE256(chiave ECDSA ‖ chiave ML-DSA).
- La firma copre lo stesso messaggio (sighash BIP143) con **entrambe** le chiavi; il witness ha 4
  elementi: firma ECDSA, chiave ECDSA, firma ML-DSA, chiave ML-DSA.

---

## Cosa manca per l'uso quotidiano (prossimi passi)
1. **App Windows**: oggi lo strumento è un eseguibile Linux di riferimento. Per gli utenti serve
   o una versione Windows, o rifare la stessa logica nell'app, **controllata contro questo strumento**.
2. **Automatismi nell'app**: mostrare l'indirizzo bb1z, scoprire gli incassi e scegliere le monete in
   automatico (lato nodo è già pronto: `desc` + `scantxoutset` per scoprire, `sign-multi` per combinare).
3. **Limite di dimensione blocco**: verificato che **non** serve alzarlo (sconto SegWit, ~1.000 input
   PQ per blocco).
4. **Audit** del codice di consenso prima di esporre fondi veri.
