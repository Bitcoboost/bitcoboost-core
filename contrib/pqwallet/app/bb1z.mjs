// bb1z.mjs — indirizzi e firma quantum-safe (witness v2) per l'app BitcoBoost.
// Chiave ECDSA dal percorso BIP84 + chiave ML-DSA derivata DALLA STESSA frase (12 parole).
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { BIP32Factory } from 'bip32';
import bip39 from 'bip39';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';
const bip32 = BIP32Factory(ecc);

const PATH = "m/84'/0'/0'/0/0";
const CTX = new TextEncoder().encode('BitcoBoost-bb1z-v2');
const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;

function sha256(...bufs){ const h=createHash('sha256'); for(const b of bufs) h.update(b); return h.digest(); }
function shake256_32(...bufs){ const h=createHash('shake256',{outputLength:32}); for(const b of bufs) h.update(b); return new Uint8Array(h.digest()); }

// Da frase -> {seed, child ECDSA, chiavi ML-DSA, program, scriptPubKey}
export function chiaviDaFrase(frase, network){
  const seed = bip39.mnemonicToSeedSync(frase);
  const child = bip32.fromSeed(seed, network).derivePath(PATH);
  // seme ML-DSA deterministico dalla stessa frase
  const mseed = sha256(seed, Buffer.from('bb1z-mldsa-v2'));
  const mk = ml_dsa44.keygen(new Uint8Array(mseed));
  const ecdsaPub = Buffer.from(child.publicKey);            // 33
  const program = shake256_32(ecdsaPub, Buffer.from(mk.publicKey)); // 32
  const scriptPubKey = bitcoin.script.compile([bitcoin.opcodes.OP_2, Buffer.from(program)]); // 5220<program>
  return { seed, child, mk, ecdsaPub, program, scriptPubKey };
}

export function indirizzoBB1Z(frase, network, hrp){
  const k = chiaviDaFrase(frase, network);
  return {
    address: bitcoin.address.toBech32(Buffer.from(k.program), 2, hrp),
    program: Buffer.from(k.program).toString('hex'),
    scriptPubKey: Buffer.from(k.scriptPubKey).toString('hex'),
  };
}

// Firma una spesa da uno o piu UTXO v2 verso una destinazione (con eventuale resto al proprio indirizzo).
// utxos: [{txid, vout, valoreSat}]; destScriptHex: scriptPubKey destinazione; importoSat/feeSat interi (o BigInt)
export function firmaBB1Z({ frase, network, utxos, destScriptHex, importoSat, feeSat }){
  const k = chiaviDaFrase(frase, network);
  const scriptCode = Buffer.from(k.scriptPubKey); // OP_2<program>, uguale allo scriptPubKey
  const tx = new bitcoin.Transaction();
  tx.version = 2;
  let totale = 0n;
  for (const u of utxos){
    const hash = Uint8Array.from(Buffer.from(u.txid,'hex').reverse());
    tx.addInput(hash, u.vout, 0xffffffff);
    totale += BigInt(u.valoreSat);
  }
  const fee = BigInt(feeSat);
  let invio, resto;
  if (importoSat === 'tutto'){ invio = totale - fee; resto = 0n; }
  else { invio = BigInt(importoSat); resto = totale - invio - fee; }
  if (invio <= 0n) throw new Error('Importo troppo basso rispetto alla commissione.');
  if (resto < 0n) throw new Error('Fondi insufficienti per importo piu commissione.');
  tx.addOutput(Uint8Array.from(Buffer.from(destScriptHex,'hex')), invio);
  if (resto > 0n) tx.addOutput(Uint8Array.from(k.scriptPubKey), resto); // resto al proprio bb1z
  for (let i=0;i<utxos.length;i++){
    const sh = tx.hashForWitnessV0(i, scriptCode, BigInt(utxos[i].valoreSat), SIGHASH_ALL);
    const compact = k.child.sign(sh);                                   // ECDSA 64B (low-S)
    const esig = bitcoin.script.signature.encode(Buffer.from(compact), SIGHASH_ALL); // DER+01
    const msig = ml_dsa44.sign(new Uint8Array(sh), k.mk.secretKey, { context: CTX }); // 2420
    tx.setWitness(i, [ Uint8Array.from(esig), Uint8Array.from(k.ecdsaPub), msig, k.mk.publicKey ]);
  }
  return tx.toHex();
}
