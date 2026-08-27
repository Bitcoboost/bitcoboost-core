# BitcoBoost Mainnet Launch — Design Document

> **Versione**: 1.0
> **Data decisioni**: 9 maggio 2026
> **Branch Git**: `mainnet-launch-redesign`
> **Stato**: implementazione in corso

Questo documento descrive le decisioni di design definitive per il lancio della mainnet di BitcoBoost. Ogni scelta è stata presa dopo discussione e ha implicazioni di lungo periodo.

---

## 1. Decisioni strategiche

### 1.1 Hard fork con reset completo (Modo B)

Si abbandona la chain attuale (28.549 blocchi minati durante la fase di sviluppo, da nodo isolato) e si lancia una nuova mainnet con genesis block fresco al momento del lancio pubblico.

**Motivazione**:
- La chain attuale ha bug noti già scritti nei blocchi (powLimit testnet, asserzioni di sicurezza disabilitate, checkpoint Bitcoin reali, chainTxData di Bitcoin)
- Le ~1.4M BB già minate vanno tutte sul pool address `B8GW...`, narrativa ambigua per una community pubblica
- Zero utenti reali sulla chain attuale → il "costo" del reset è praticamente nullo
- Una narrativa "fair launch dal blocco 0 il giorno X" è la più forte possibile

### 1.2 Algoritmo PoW: X16RV2

Eredità della scelta di design già implementata nel codice. **Confermata.**

**Motivazione**:
- Resistenza ASIC: 16 algoritmi crittografici a rotazione rendono economicamente non conveniente costruire ASIC dedicati
- Mining GPU-friendly: chiunque con una scheda video consumer (RTX serie 30+ o equivalenti AMD) può minare competitivamente
- Coerente con la visione "le persone normali devono avere una vera chance"
- Stesso algoritmo di Ravencoin (RVN), una delle coin community più rispettate per fair launch

**Trade-off accettato consapevolmente**: CPU non è competitiva con GPU su X16RV2. Il messaggio pubblico sarà: "minabile da chiunque con qualunque GPU consumer dal 2017 in poi, anche da CPU per chi vuole solo dare una mano alla rete senza puntare a guadagno".

### 1.3 Difficoltà: Bitcoin-style con protezioni early-launch

`powLimit = 0x00000000ffff...` (standard Bitcoin mainnet, NON testnet)

**Protezioni early-launch combinate**:
1. **Difficulty retarget veloce nei primi 2016 blocchi**: ogni 144 blocchi (~1 giorno) invece dei 2016 standard (~2 settimane). Così se l'hashrate cambia bruscamente all'inizio, la chain si auto-aggiusta in 1 giorno invece di 2 settimane
2. **Slow start del block reward**:
   - Blocchi 1-1000: reward = 1 BB
   - Blocchi 1001-2000: reward = 10 BB
   - Blocchi 2001+: reward = 50 BB con halving standard ogni 210.000

**Motivazione**: lo slow start disincentiva mining "mordi e fuggi" da farm professionali a caccia di premine. Solo chi crede nel progetto e mina i primi 1000-2000 blocchi (che valgono poco singolarmente) viene ricompensato. È una protezione contro mining cartels iniziali.

**Effetto sulla supply**: 11.000 BB "persi" rispetto allo standard 50/blocco. Supply massima teorica corretta: **20.961.000 BB** (era 21.000.000). Aggiustamento nel codice: lasciamo `MAX_MONEY = 21000000 * COIN` per evitare cascate di modifiche, l'effetto pratico è solo che la supply circolante reale arriverà a 20.961k invece di 21M.

### 1.4 Founder Reward: 5% per 4 anni

Il 5% di ogni block reward (dopo lo slow start) va a un address dichiarato pubblicamente, di proprietà di **Primaris Group SRLS** (P.IVA italiana del fondatore).

**Periodo**: dal blocco 2001 (fine slow start) al blocco 210.000 (primo halving) ≈ 4 anni.

**Implementazione tecnica**: il coinbase del miner deve obbligatoriamente includere un output al founder address di valore esatto = `5% * GetBlockSubsidy(height)`. Senza quel output, il blocco viene rifiutato come `bad-cb-founder-reward`.

**Trasparenza**:
- L'address del founder reward è hardcoded nel codice (visibile a chiunque scarichi il binario)
- Dichiarato esplicitamente nel whitepaper
- Visibile pubblicamente sull'explorer
- Tassato come reddito d'impresa di Primaris Group SRLS (IRES 24%)

**Motivazione**:
- Onestà: tutto pubblico, niente premine nascosti
- Sostenibilità: finanzia sviluppo continuativo, server costs, marketing nei primi 4 anni
- Modello consolidato: Zcash usa lo stesso schema (20% per 4 anni nel loro caso, BitcoBoost 5% più conservativo)

**Numeri attesi (block reward 50 BB nominali)**:
- Founder reward giornaliero: 50 × 0.05 × 144 = 360 BB/giorno
- Founder reward annuo: ~131k BB/anno per i primi 4 anni
- Founder reward totale 4 anni: ~525k BB (~2.5% del supply totale)

### 1.5 Strategia mining iniziale

Il fondatore minerà attivamente fino all'arrivo della community. Le protezioni early-launch (difficulty retarget veloce + slow start) garantiscono auto-regolazione: quando il fondatore si ritira, la difficoltà si abbassa rapidamente per permettere ai pochi miner rimanenti di trovare comunque blocchi ogni ~10 minuti.

### 1.6 Seed nodes

Self-hosted: 2-3 VPS dedicate con `bitcoboostd` always-on, configurate come seed nodes pubblici per il primo onboarding di nuovi nodi.

**DNS pubblici da registrare prima del lancio**:
- `seed1.bitcoboost.com` → IP VPS 1
- `seed2.bitcoboost.com` → IP VPS 2
- `seed3.bitcoboost.com` → IP VPS 3 (opzionale)

---

## 2. Parametri tecnici della chain

### Genesis block

| Campo | Valore |
|---|---|
| Timestamp message | "Bitcoboost mainnet launch - [DATA_LANCIO_REALE]" |
| Genesis time | da definire al momento del lancio (timestamp Unix del momento di compilazione finale) |
| Genesis nonce | da computare (loop fino a hash valido) |
| Genesis nBits | 0x1d00ffff (standard Bitcoin mainnet) |
| Genesis reward | 50 BB (testimonial, primo blocco non spendibile) |

### Consensus parameters

| Parametro | Valore | Note |
|---|---|---|
| `nSubsidyHalvingInterval` | 210000 | Standard Bitcoin |
| `powLimit` | `00000000ffff...` | Bitcoin mainnet style |
| `nPowTargetTimespan` | 14 * 24 * 60 * 60 | 2 settimane standard |
| `nPowTargetSpacing` | 10 * 60 | Blocco ogni 10 minuti |
| `fPowAllowMinDifficultyBlocks` | false | No min-diff (no testnet style) |
| `fPowNoRetargeting` | false | Retargeting attivo |
| **Custom: `nFastRetargetPeriod`** | 144 | Retarget veloce primi 2016 blocchi |
| **Custom: `nFastRetargetUntilHeight`** | 2016 | Termina dopo |

### Block reward (custom GetBlockSubsidy)

```cpp
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams) {
    // Slow start
    if (nHeight <= 1000) return 1 * COIN;
    if (nHeight <= 2000) return 10 * COIN;

    // Standard reward con halving
    int halvings = (nHeight - 2001) / consensusParams.nSubsidyHalvingInterval;
    if (halvings >= 64) return 0;

    CAmount nSubsidy = 50 * COIN;
    nSubsidy >>= halvings;
    return nSubsidy;
}
```

### Founder reward validation (custom in ConnectBlock)

```cpp
// Dopo il check standard "bad-cb-amount":
if (pindex->nHeight >= FOUNDER_REWARD_START_HEIGHT &&
    pindex->nHeight < FOUNDER_REWARD_END_HEIGHT) {

    CAmount expectedFounderReward = GetBlockSubsidy(pindex->nHeight, ...) * 5 / 100;
    CScript founderScript = GetScriptForFounderAddress();

    bool foundFounderOutput = false;
    for (const auto& output : block.vtx[0]->vout) {
        if (output.scriptPubKey == founderScript &&
            output.nValue >= expectedFounderReward) {
            foundFounderOutput = true;
            break;
        }
    }

    if (!foundFounderOutput) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-cb-founder-reward");
    }
}
```

Costanti:
- `FOUNDER_REWARD_START_HEIGHT = 2001` (subito dopo slow start)
- `FOUNDER_REWARD_END_HEIGHT = 210000` (primo halving)
- `FOUNDER_REWARD_PERCENT = 5`
- `FOUNDER_REWARD_ADDRESS = "bb1q..."` (placeholder, da definire al lancio)

### Magic bytes (network identifier)

Cambiati rispetto alla chain attuale per evitare confusione P2P:
- Vecchia chain: `0xFB 0xC0 0xB0 0x57`
- Nuova mainnet: `0xBB 0x07 0x14 0x57` (hex "BB" + data simbolica + "W")

### Default ports

- P2P: **38210** (mantenuto, non standard, ok)
- RPC: **8332** (mantenuto)

### Address prefixes (mantenuti)

- PUBKEY_ADDRESS: 25 (lettera 'B' iniziale)
- SCRIPT_ADDRESS: 85
- SECRET_KEY (WIF): 153
- EXT_PUBLIC_KEY (xpub): 0x04 0xBB 0x61 0xB0
- EXT_SECRET_KEY (xprv): 0x04 0xBB 0x5A 0xC0
- bech32 HRP: `bb` (es. `bb1q...`)

---

## 3. Sicurezza — verifiche già fatte

### CVE storici di Bitcoin: protetto ✅

- **CVE-2010-5139** (Value Overflow Incident): fix presente in `consensus/tx_check.cpp`, check `MoneyRange()` triple-layer
- **CVE-2018-17144** (Duplicate Inputs): fix presente in validation, comment esplicito nel codice
- Eredità di 15 anni di security audit di Bitcoin Core 27.1

### Asserzioni di sicurezza da riattivare al lancio ⚠️

Nella chain attuale sono disabilitate per facilitare la generazione del genesis durante lo sviluppo:
- `assert(consensus.hashGenesisBlock == uint256S(...))` — verifica che il binario sia legato al genesis previsto
- `assert(genesis.hashMerkleRoot == uint256S(...))` — verifica integrità merkle root

Vanno **riattivate prima della compilazione del binario di lancio**, con i valori reali del genesis nuovo.

---

## 4. File modificati / da modificare

| File | Tipo | Stato |
|---|---|---|
| `src/kernel/chainparams.cpp` | RISCRITTURA totale `CMainParams` | TODO |
| `src/validation.cpp` `GetBlockSubsidy` | Modifica per slow start | TODO |
| `src/validation.cpp` `ConnectBlock` | Aggiunta check founder reward | TODO |
| `src/consensus/params.h` | Aggiunta `nFastRetargetPeriod`, `nFastRetargetUntilHeight` | TODO |
| `src/pow.cpp` `GetNextWorkRequired` | Logica retarget veloce | TODO |
| `src/clientversion.h` | Bump versione a 28.0.0 | TODO |
| `src/hash.cpp`, `src/hash.h`, `src/primitives/block.cpp` | X16RV2 esistente | OK (rimuovere solo `BB_X16RV2_ACTIVATION_TIME`, sempre attivo dal blocco 1) |

---

## 5. Cosa serve PRIMA della compilazione finale del binario di lancio

Checklist obbligatoria:

- [ ] Address del founder reward (Primaris Group SRLS) generato e inserito in `chainparams.cpp`
- [ ] Genesis block timestamp = data del lancio reale, nonce computato
- [ ] DNS `seed1.bitcoboost.com`, `seed2.bitcoboost.com` registrati e puntati
- [ ] 2-3 VPS aggiuntive comprate e configurate come seed nodes
- [ ] Asserzioni di sicurezza riattivate con i valori reali del nuovo genesis
- [ ] Whitepaper pubblicato con tutti i parametri sopra dichiarati
- [ ] Privacy policy + Terms of Service sul sito
- [ ] Versione inglese del sito pronta
- [ ] Code-signing certificato Authenticode per il binario Windows
- [ ] Annunci preparati per BitcoinTalk, Reddit, ecc.
- [ ] Consulenza legale MiCA con avvocato (registrazione OAM, eventuale autorizzazione CASP)

---

## 6. Riferimenti ai progetti che ispirano scelte di design

- **Ravencoin (RVN)**: algoritmo X16R/X16RV2, fair launch
- **Zcash (ZEC)**: founder reward 20% per 4 anni (BitcoBoost: 5%, più conservativo)
- **Litecoin (LTC)**: difficulty retarget veloce iniziale
- **Monero (XMR)**: filosofia anti-ASIC, GPU/CPU-friendly
- **Bitcoin (BTC)**: codebase di partenza, 21M supply cap

---

*Documento maintained-by: Massimiliano Cescon, fondatore. Ultima revisione: 9 maggio 2026.*
