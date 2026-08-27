# Bitcoboost Core – Node implementation (fork of Bitcoin Core v27.1.0)

Bitcoboost Core è il nodo ufficiale del progetto Bitcoboost, basato sul codice di Bitcoin Core v27.1.0 con parametri modificati, branding dedicato e configurazioni personalizzate.

## Funzionalità principali
- Pieno supporto P2P, RPC e mempool
- Mining CPU (generatetoaddress)
- Tag miner (Node A / Node B) integrati
- Compatibilità con Explorer, Dashboard e MyMiner
- Parametri e porte personalizzate Bitcoboost

## Requisiti
- Ubuntu 22.04+
- Build tools: automake, autoconf, libtool, pkg-config, gcc/g++
- Librerie: libevent-dev, libboost, libsqlite3-dev, libminiupnpc-dev

## Compilazione
1. Installare dipendenze:
   sudo apt update
   sudo apt install build-essential libtool autotools-dev automake pkg-config libevent-dev \
   libboost-system-dev libboost-filesystem-dev libboost-test-dev libboost-thread-dev libsqlite3-dev

2. Generare configurazione:
   ./autogen.sh
   ./configure

3. Compilare:
   make -j$(nproc)

I binari risultanti sono in:
- src/bitcoind
- src/bitcoin-cli

## Configurazione del nodo
File di configurazione:
~/.bitcoboost/bitcoin.conf

Esempio:
server=1
daemon=1
txindex=1

rpcuser=utente_rpc
rpcpassword=pass_rpc
rpcport=8332

listen=1
port=38210

addnode=141.227.135.198

## Avvio del nodo
bitcoind -datadir=$HOME/.bitcoboost

Controllo blocchi:
bitcoin-cli -datadir=$HOME/.bitcoboost getblockchaininfo

## Struttura del repository
- src/      → codice sorgente principale
- doc/      → documentazione
- depends/  → build cross-platform
- contrib/  → strumenti aggiuntivi
- test/     → test suite
- share/    → risorse
- bb_icons/ → elementi di branding Bitcoboost

## Componenti ufficiali Bitcoboost
Sito:           https://bitcoboost.com
Dashboard:      https://bitcoboost.com/dashboard/
Explorer:       https://explorer.bitcoboost.com
Downloads:      https://bitcoboost.com/downloads/
Network:        https://bitcoboost.com/network/
How to Mine:    https://bitcoboost.com/how-to-mine/

## Licenza
Il progetto mantiene la licenza MIT ereditata da Bitcoin Core.

