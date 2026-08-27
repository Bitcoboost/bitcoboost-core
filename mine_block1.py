#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, time, struct, json, binascii, hashlib, requests

# ===== Utils =====

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def be_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def le_hex(b: bytes) -> str:
    return binascii.hexlify(b[::-1]).decode()

def pack_u32le(x: int) -> bytes: return struct.pack("<I", x)
def pack_u64le(x: int) -> bytes: return struct.pack("<Q", x)

def varint(n: int) -> bytes:
    if n < 0xfd: return struct.pack("B", n)
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

def ser_push(data: bytes) -> bytes:
    n = len(data)
    if n < 0x4c: return bytes([n]) + data
    if n <= 0xff: return b"\x4c" + bytes([n]) + data
    if n <= 0xffff: return b"\x4d" + struct.pack("<H", n) + data
    return b"\x4e" + struct.pack("<I", n) + data

def ser_bip34_height(h: int) -> bytes:
    v, out = h, b""
    while True:
        out += bytes([v & 0xff])
        v >>= 8
        if v == 0: break
    return ser_push(out)

def bits_to_target(bits_hex: str) -> int:
    n = int(bits_hex, 16)
    exp, mant = n >> 24, n & 0xffffff
    return mant * (1 << (8 * (exp - 3)))

def txid_from_raw(raw: bytes) -> bytes:
    # Non-SegWit: semplice doppio sha256 su tutto
    # SegWit: txid è sempre senza witness; ma qui includiamo solo NON-SegWit
    return sha256d(raw)[::-1]  # big-endian

def is_segwit_raw(raw: bytes) -> bool:
    # Heuristica standard: dopo 4 byte di version, se c’è 0x00 seguito da 0x01 è marker/flag
    if len(raw) < 6: return False
    return raw[4] == 0x00 and raw[5] == 0x01

def merkle_root_be(txids_be: list[bytes]) -> bytes:
    # txids_be: lista di txid in big-endian
    if not txids_be: return b"\x00"*32
    layer = [x[::-1] for x in txids_be]  # little-endian interno
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i] if i+1 == len(layer) else layer[i+1]
            nxt.append(sha256d(a + b))
        layer = nxt
    return layer[0][::-1]  # torna big-endian

# ===== RPC =====

class SimpleRPC:
    def __init__(self, url, auth=None, timeout=60):
        self.url, self.auth, self.timeout = url, auth, timeout
    def call(self, method, params=None):
        payload = {"jsonrpc":"1.0","id":"bb","method":method,"params":params or []}
        r = requests.post(self.url, data=json.dumps(payload), auth=self.auth, timeout=self.timeout)
        if r.status_code != 200:
            raise RuntimeError(f"RPC HTTP {r.status_code}: {r.content!r}")
        j = r.json()
        if j.get("error"): raise RuntimeError(f"RPC error {j['error']}")
        return j["result"]

def guess_datadir():
    env = os.environ.get("BB_DATADIR")
    if env and os.path.isdir(env): return env
    here = os.path.abspath(os.path.dirname(__file__))
    cand = os.path.join(here, "bb_main")
    if os.path.isdir(cand): return cand
    appdata = os.environ.get("APPDATA")
    if appdata:
        cand = os.path.join(appdata, "Bitcoin")
        if os.path.isdir(cand): return cand
    return os.getcwd()

def read_bitcoin_conf(p):
    conf = {}
    if not os.path.isfile(p): return conf
    with open(p,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#"): continue
            if "=" in line:
                k,v=line.split("=",1)
                conf[k.strip()]=v.strip()
    return conf

def make_rpcs():
    datadir = guess_datadir()
    conf = read_bitcoin_conf(os.path.join(datadir, "bitcoin.conf"))
    host = conf.get("rpcconnect","127.0.0.1")
    port = int(conf.get("rpcport","8332"))
    user, pw = conf.get("rpcuser"), conf.get("rpcpassword")
    if not (user and pw):
        cookie = os.path.join(datadir, ".cookie")
        if os.path.exists(cookie):
            user, pw = open(cookie,"r",encoding="utf-8").read().strip().split(":",1)
    if not (user and pw): raise RuntimeError("Manca rpcuser/rpcpassword o .cookie")
    base = f"http://{host}:{port}"
    print(f"[BB] RPC auth mode: conf  host={host} port={port}")
    wallet = os.environ.get("BB_WALLET","bb_wallet")
    return SimpleRPC(base,(user,pw)), SimpleRPC(f"{base}/wallet/{wallet}",(user,pw))

# ===== Costruzione TX/Blocco =====

def build_coinbase_tx(height: int, payout_spk_hex: str, coinbase_value_sats: int) -> bytes:
    version   = pack_u32le(2)
    prevout   = b"\x00"*32 + pack_u32le(0xffffffff)
    ss        = ser_bip34_height(height) + ser_push(b"bb")
    scriptsig = varint(len(ss)) + ss
    sequence  = pack_u32le(0xffffffff)
    value     = pack_u64le(coinbase_value_sats)
    spk       = binascii.unhexlify(payout_spk_hex)
    vout      = value + varint(len(spk)) + spk
    locktime  = pack_u32le(0)
    return version + varint(1) + prevout + scriptsig + sequence + varint(1) + vout + locktime

def build_header(version, prevhash_hex, merkle_be_hex, nTime, bits_hex, nonce):
    ver  = pack_u32le(version)
    prev = binascii.unhexlify(prevhash_hex)[::-1]
    mrkl = binascii.unhexlify(merkle_be_hex)[::-1]
    tm   = pack_u32le(nTime)
    bits = binascii.unhexlify(bits_hex)[::-1]
    nn   = pack_u32le(nonce)
    return ver + prev + mrkl + tm + bits + nn

def assemble_block(header_bytes, txs_bytes_list):
    return header_bytes + varint(len(txs_bytes_list)) + b"".join(txs_bytes_list)

# ===== MAIN =====

def main():
    rpc_core, rpc_wallet = make_rpcs()

    # Payout su indirizzo legacy del wallet (così le future tx possono restare non-segwit)
    try:
        addr = rpc_wallet.call("getnewaddress", ["", "legacy"])
    except RuntimeError as e:
        if "Requested wallet does not exist" in str(e):
            rpc_core.call("loadwallet", [os.environ.get("BB_WALLET","bb_wallet")])
            addr = rpc_wallet.call("getnewaddress", ["", "legacy"])
        else:
            raise
    spk_hex = rpc_wallet.call("getaddressinfo", [addr])["scriptPubKey"]
    print(f"[BB] payout -> wallet={os.environ.get('BB_WALLET','bb_wallet')}  addr={addr}  spk={spk_hex}")

    # Template con regola segwit attiva (obbligatoria)
    gbt = rpc_core.call("getblocktemplate", [ { "rules": ["segwit"] } ])

    version  = int(gbt["version"])
    height   = int(gbt["height"])
    prevhash = gbt["previousblockhash"]
    nTime    = int(gbt.get("curtime", int(time.time())))
    bits_hex = gbt["bits"]

    # Calcola subsidy + fees
    all_fees = sum(int(t.get("fee", 0)) for t in gbt.get("transactions", []))
    subsidy  = int(gbt["coinbasevalue"]) - all_fees

    # Seleziona dal template SOLO le tx NON-SegWit per restare semplici e validi
    selected = []
    for t in gbt.get("transactions", []):
        raw = binascii.unhexlify(t["data"])
        if not is_segwit_raw(raw):
            selected.append({"raw": raw, "fee": int(t.get("fee",0))})
    fees_included = sum(t["fee"] for t in selected)

    # Valore coinbase coerente con le tx incluse
    coinbase_value = subsidy + fees_included

    # Costruisci coinbase e lista tx del blocco
    cb_tx   = build_coinbase_tx(height, spk_hex, coinbase_value)
    cb_txid = txid_from_raw(cb_tx)           # big-endian
    block_txs = [cb_tx] + [t["raw"] for t in selected]

    # Merkle root (di txid big-endian)
    txids_be = [cb_txid] + [txid_from_raw(t["raw"]) for t in selected]
    mrkl_be  = merkle_root_be(txids_be)

    target = bits_to_target(bits_hex)
    print(f"[BB] height={height} bits={bits_hex} target=0x{target:064x}")
    print(f"[BB] prevhash(be)={prevhash}")
    print(f"[BB] coinbase txid (be)={be_hex(cb_txid)}")
    print(f"[BB] merkle(be)={be_hex(mrkl_be)}")
    print(f"[BB] includo {len(selected)} tx non-segwit dal template, fees={fees_included} sat")

    # Mining loop
    found_header = None
    for nonce in range(0, 0xffffffff):
        hdr = build_header(version, prevhash, be_hex(mrkl_be), nTime, bits_hex, nonce)
        h   = sha256d(hdr)
        hv  = int.from_bytes(h[::-1], "big")
        if nonce < 5:
            print(f" .. nonce={nonce} hash={be_hex(h[:4])}...")
        if hv <= target:
            print(f"[BB] FOUND nonce={nonce} hash={le_hex(h)}")
            found_header = hdr
            break

    if not found_header:
        print("[BB] Nessun nonce trovato (improbabile). Riprova.")
        return

    # Submit
    block_hex = be_hex(assemble_block(found_header, block_txs))
    res = rpc_core.call("submitblock", [block_hex])
    print(f"[BB] submitblock result: {repr(res)}")

    best = rpc_core.call("getbestblockhash")
    print(f"[BB] best: {best}")

if __name__ == "__main__":
    main()
