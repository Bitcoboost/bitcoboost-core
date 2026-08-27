import hashlib, struct, time

def sha256d(b): 
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def varint(n):
    if n < 0xfd:   return struct.pack("<B", n)
    if n <= 0xffff:return b"\xfd"+struct.pack("<H", n)
    if n <= 0xffffffff:return b"\xfe"+struct.pack("<I", n)
    return b"\xff"+struct.pack("<Q", n)

# PubKey e scriptPubKey stile genesis Bitcoin (va benissimo anche per la tua chain)
GENESIS_PUBKEY = bytes.fromhex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
    "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
    "de5c384df7ba0b8d578a4c702b6bf11d5f"
)

def build_coinbase_tx(psz_timestamp:str, reward_sats:int):
    # scriptSig = 0x04ffff001d0104 + <len(timestamp)> + <timestamp>
    ts_bytes = psz_timestamp.encode("utf-8")
    if len(ts_bytes) > 0x4b: 
        raise ValueError("timestamp troppo lungo (max 75 byte)")
    scriptSig = bytes.fromhex("04ffff001d0104") + bytes([len(ts_bytes)]) + ts_bytes

    # input: prevout = 32*00 + 0xffffffff, scriptSig, sequence=0xffffffff
    vin  = b"\x00"*32 + struct.pack("<I", 0xffffffff) + varint(len(scriptSig)) + scriptSig + struct.pack("<I", 0xffffffff)

    # output: value (8B little-endian), scriptPubKey = OP_PUSH65 <pubkey> OP_CHECKSIG
    scriptPubKey = b"\x41" + GENESIS_PUBKEY + b"\xac"
    vout = struct.pack("<Q", reward_sats) + varint(len(scriptPubKey)) + scriptPubKey

    # tx = version(4) + vin_count + vin + vout_count + vout + locktime(4)
    tx  = struct.pack("<I", 1) + varint(1) + vin + varint(1) + vout + struct.pack("<I", 0)
    txid = sha256d(tx)
    return tx, txid

def bits_to_target(bits):
    # "compact" -> target integer
    # bits: 0x1e0ffff0 (esempio) o 0x207fffff (molto facile)
    exp = bits >> 24
    mant = bits & 0xffffff
    target = mant * (1 << (8*(exp-3)))
    return target

def header_hash(version, prev_hash, merkle_root, nTime, nBits, nNonce):
    hdr = struct.pack("<I", version) \
        + prev_hash[::-1] \
        + merkle_root[::-1] \
        + struct.pack("<I", nTime) \
        + struct.pack("<I", nBits) \
        + struct.pack("<I", nNonce)
    return sha256d(hdr)

def mine_genesis(psz, nTime, nBits, version=1, reward_sats=50_0000_0000, start_nonce=0, max_nonce=0xffffffff):
    tx, txid = build_coinbase_tx(psz, reward_sats)
    merkle = txid
    target = bits_to_target(nBits)
    print(f"[i] MerkleRoot = {merkle[::-1].hex()}")
    best = None

    for nonce in range(start_nonce, max_nonce+1):
        h = header_hash(version, b"\x00"*32, merkle, nTime, nBits, nonce)
        hv = int.from_bytes(h, "big")  # confronto big-endian con target
        if best is None or hv < best[0]:
            best = (hv, nonce, h)
        if hv <= target:
            print(f"[FOUND] nonce={nonce}  hash={h[::-1].hex()}")
            return {
                "psz": psz,
                "nTime": nTime,
                "nBits": nBits,
                "version": version,
                "reward_sats": reward_sats,
                "nonce": nonce,
                "hash_be": h.hex(),
                "hash": h[::-1].hex(),            # formato "stampa" classico
                "merkle": merkle[::-1].hex()
            }
        if nonce % 2500000 == 0 and nonce > 0:
            print(f"[... mining] nonce={nonce} best={best[2][::-1].hex()}")

    raise RuntimeError("Nonce non trovato nel range")

if __name__ == "__main__":
    # *** MODIFICA QUI per ogni rete ***
    # Esempio mainnet super-facile per test: nBits=0x207fffff (target altissimo)
    # Scegli una frase TUA e un time (epoch). Qui metto una di default:
    psz = "Bitcoboost genesis — 2025-10-17"
    nTime = 1758067200       # 2025-10-17 00:00:00 UTC (esempio)
    nBits = 0x207fffff       # facilissimo per trovare subito un nonce
    version = 1
    reward = 50_0000_0000    # 50 * COIN (in satoshi)

    res = mine_genesis(psz, nTime, nBits, version, reward)
    print("\n=== RISULTATI ===")
    for k,v in res.items():
        print(f"{k}: {v}")
