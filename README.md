# BitcoBoost Core

**BitcoBoost (BCBO)** is an independent Proof-of-Work Layer-1 cryptocurrency, built as a fork of Bitcoin Core 27.1, mineable on consumer hardware (CPU and GPU) with the **X16RV2** algorithm. Mainnet has been live since June 2026. No ICO, no presale, no premine: every BCBO in existence was mined on the public chain.

- Website: https://bitcoboost.com
- Block explorer: https://explorer.bitcoboost.com
- Exchange / listing information: https://bitcoboost.com/listing/
- Exchange Integration Guide: https://bitcoboost.com/developers/exchange-integration/
- Whitepaper: https://bitcoboost.com/whitepaper/ · Tokenomics: https://bitcoboost.com/tokenomics/
- Technical specifications: https://bitcoboost.com/developers/specifications/
- Security policy: https://bitcoboost.com/security/
- Public APIs: https://bitcoboost.com/api/v1/supply · https://bitcoboost.com/api/v1/network

## Releases

Official binaries are published on the [Releases](https://github.com/Bitcoboost/bitcoboost-core/releases) page with `SHA256SUMS`.
Latest: **v1.0.0 "Exchange Stable"** — Linux x86_64 (`.tar.gz`) and Windows x64 (`.zip`), `bitcoind` + `bitcoin-cli`.

Verify a download:
```
sha256sum -c SHA256SUMS
```

## Network parameters (mainnet)

| Parameter | Value |
|---|---|
| Ticker | BCBO |
| Consensus | Proof-of-Work, X16RV2 |
| Max supply | **21,010,999.9769 BCBO** — 21,000,000 from the halving schedule (which starts at block 2,001) plus the 11,000 emitted during the launch slow-start. Like Bitcoin, the figure is not round because a few satoshi are lost to rounding at each halving. |
| Block time | 600 s |
| Difficulty adjustment | LWMA-1, recalculated at **every block** over a 90-block window, active since block 20,118 (12 September 2026). Blocks before that used Bitcoin's original 2,016-block retarget; the change was a scheduled consensus upgrade (`LwmaGetNextWorkRequired` in `src/pow.cpp`, `nLwmaWindow` in `src/kernel/chainparams.cpp`). |
| Block subsidy | 50 BCBO (slow start: blocks 1–1,000 = 1 BCBO, 1,001–2,000 = 10 BCBO) |
| Halving | every 210,000 blocks; first halving at block 212,001 |
| Project reward | 5% of the subsidy, blocks 2,001–209,999 only (`GetFounderRewardForBlock` in `src/validation.cpp`) |
| Coinbase maturity | 100 blocks |
| P2P / RPC port | 38210 / 18332 |
| Address format | bech32, HRP `bb`: **`bb1q…`** (witness v0, ECDSA) and **`bb1z…`** (witness v2, quantum-safe — ML-DSA key derived from the same 12-word phrase as the ECDSA one, witness program = `shake256(ecdsaPub ‖ mldsaPub)`); legacy P2PKH version 25 |
| Message magic | `0xBB160626` |
| Genesis block | `00008e92cdd72d798964ea9833c612371e93ddbcbb6a8a1ffe71e591f5b017df` |

The emission schedule is enforced by consensus (`GetBlockSubsidy` in `src/validation.cpp`) and can be verified against any node with `gettxoutsetinfo`.

## Building from source (Linux)

Tested on Ubuntu 22.04 and later. Install the dependencies first:

```
sudo apt update
sudo apt install build-essential libtool autotools-dev automake pkg-config \
  libevent-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev \
  libboost-thread-dev libsqlite3-dev libminiupnpc-dev
```

Then build:

```
git clone https://github.com/Bitcoboost/bitcoboost-core.git
cd bitcoboost-core
./autogen.sh
./configure --disable-tests --disable-bench --with-gui=no
make -j$(nproc)
```
Binaries are produced in `src/` (`bitcoind`, `bitcoin-cli`). See `doc/build-*.md` for other platforms (inherited from Bitcoin Core).

## Running a node

```
bitcoind -daemon
bitcoin-cli getblockchaininfo
```

Configuration file: `bitcoin.conf` in the data directory. A working example:

```
server=1
daemon=1
txindex=1

rpcuser=your_rpc_user
rpcpassword=your_long_rpc_password
rpcport=18332

listen=1
port=38210
```

`txindex=1` is recommended for exchanges and block explorers. Peers are found automatically through the
DNS seeds (`seed1.bitcoboost.com`, `seed2.bitcoboost.com`, `seed3.bitcoboost.com`); no `addnode` line is
needed.

## Repository layout

| Directory | Contents |
|---|---|
| `src/` | node source code |
| `doc/` | documentation inherited from Bitcoin Core |
| `depends/` | cross-platform build system |
| `contrib/` | additional tools |
| `test/` | test suite |
| `share/` | resources |
| `bb_icons/` | BitcoBoost branding assets |

## Repository history

Repository migrated to the official **BitcoBoost** GitHub account on 21 August 2026. Earlier development took place in `Primarisgroup/bitcoboost`; this repository contains a clean snapshot of the source tree at v1.0.0 and is the canonical one going forward.

## License

MIT — see [LICENSE](LICENSE). BitcoBoost Core is derived from [Bitcoin Core](https://github.com/bitcoin/bitcoin) (MIT).

## Contact

Primaris Group S.r.l.s., Turin, Italy · support@bitcoboost.com · Security reports: see https://bitcoboost.com/security/
