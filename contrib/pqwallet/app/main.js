const { app, BrowserWindow, ipcMain, safeStorage, shell } = require('electron');
const https = require('https');
const APP_VERSION = '0.1.0';
const VERSION_URL = 'https://bitcoboost.com/downloads/versione.json';
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const os = require('os');
const wallet = require('./wallet');

// --- quantum-safe (bb1z): polyfill crypto per Node + caricamento modulo ESM ---
if (!globalThis.crypto) { try { globalThis.crypto = require('crypto').webcrypto; } catch (e) {} }
let _bb1z = null;
async function getBB1Z() {
  if (!_bb1z) { const u = require('url').pathToFileURL(path.join(__dirname, 'bb1z.mjs')).href; _bb1z = await import(u); }
  return _bb1z;
}

const RPC_PORT = 8332;
const RPC_USER = 'bbminer';
const STRATUM_PORT = 3333;

let mainWindow;
let nodeProc = null;
let minerProc = null;
let bridgeProc = null;
let miningOn = false;
let rpcPass = null;
let minerVariantOk = null;
let saldoCache = '0,000000';
let scanning = false;
let lastScan = 0;
let inArrivoCache = '0,000000';
let maturaTra = null;
let precCache = '0,000000';
let precLista = [];
let sessioneCache = '0,000000';
let sessioneAltezzaBase = null;   // altezza catena quando ho premuto Avvia (saldo gia allineato)
let sessioneBaseAddr = null;
let sessioneArmata = false;       // diventa true solo quando il saldo iniziale e stato letto davvero
let reteInIBD = false;            // true se il nodo sta ancora riscaricando la catena
let minerHashrate = '';
let minerLastAt = 0;

const userData = () => app.getPath('userData');
const walletFile = () => path.join(userData(), 'wallet.dat');
const chainDir   = () => path.join(userData(), 'chain');
const passFile   = () => path.join(userData(), 'rpc.pass');

// --- dove stanno i binari (nodo + motore di mining) ---
function binBase() {
  const dev = path.join(__dirname, 'bin');                          // sviluppo: <progetto>/bin
  const packed = path.join(process.resourcesPath || __dirname, 'bin'); // app impacchettata
  return fs.existsSync(dev) ? dev : packed;
}
function nodeExe()  { return path.join(binBase(), 'node', 'bitcoboostd.exe'); }
function minerDir() { return path.join(binBase(), 'miner'); }

// varianti del motore, dalla piu potente alla piu compatibile
const MINER_VARIANTS = [
  'cpuminer-avx512-sha-vaes.exe', 'cpuminer-avx512.exe',
  'cpuminer-avx2-sha-vaes.exe', 'cpuminer-avx2-sha.exe', 'cpuminer-avx2.exe',
  'cpuminer-avx.exe', 'cpuminer-aes-sse42.exe', 'cpuminer-sse2.exe',
];

// ---------------- finestra ----------------
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 560, height: 760, minWidth: 460, minHeight: 600, resizable: true, maximizable: true, title: 'BitcoBoost Miner',
    icon: path.join(__dirname, 'renderer', 'assets', 'app.ico'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false },
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

// ---------------- portafoglio (come prima) ----------------
const addrPubFile = () => path.join(userData(), 'indirizzo.txt');   // indirizzo pubblico in chiaro (come un IBAN), serve per minare da bloccato
const addrFile    = () => path.join(userData(), 'indirizzi.json');  // elenco indirizzi pubblici (per i 'saldi altri portafogli')

function walletExists() { try { return fs.existsSync(walletFile()); } catch (e) { return false; } }
function leggiIndirizzi() { try { return JSON.parse(fs.readFileSync(addrFile(), 'utf8')); } catch (e) { return []; } }
function aggiungiIndirizzo(a) { try { const l = leggiIndirizzi(); if (a && !l.includes(a)) { l.push(a); fs.writeFileSync(addrFile(), JSON.stringify(l)); } } catch (e) {} }
function indirizzoPubblico() { try { return fs.readFileSync(addrPubFile(), 'utf8').trim(); } catch (e) { return null; } }
const settingsFile = () => path.join(userData(), 'impostazioni.json');
function leggiImpostazioni() { try { return JSON.parse(fs.readFileSync(settingsFile(), 'utf8')); } catch (e) { return {}; } }
function scriviImpostazioni(o) { try { fs.writeFileSync(settingsFile(), JSON.stringify(o)); } catch (e) {} }
// percentuale CPU scelta (default 100 = turbo)
let cpuPercent = (function(){ const s = leggiImpostazioni(); return (s && s.cpuPercent) ? s.cpuPercent : 100; })();
function coresDaUsare() {
  const tot = Math.max(1, os.cpus().length);
  let n = Math.round(tot * cpuPercent / 100);
  if (n < 1) n = 1;
  if (n > tot) n = tot;
  return n;
}
function formatoNuovo() {
  try { const c = fs.readFileSync(walletFile(), 'utf8'); const j = JSON.parse(c); return !!(j && j.v && j.salt && j.iv && j.tag && j.dati); }
  catch (e) { return false; }
}

// --- cifratura delle 12 parole con la PASSWORD dell'utente (PBKDF2 + AES-256-GCM) ---
// Formato file (JSON): { v, salt, iv, tag, dati }  tutto in base64. Senza password e illeggibile.
function cifraFrase(frase, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, 200000, 32, 'sha256');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([c.update(Buffer.from(frase, 'utf8')), c.final()]);
  const tag = c.getAuthTag();
  return JSON.stringify({ v: 1, salt: salt.toString('base64'), iv: iv.toString('base64'), tag: tag.toString('base64'), dati: enc.toString('base64') });
}
function decifraFrase(contenuto, password) {
  const j = JSON.parse(contenuto);
  const salt = Buffer.from(j.salt, 'base64');
  const iv = Buffer.from(j.iv, 'base64');
  const tag = Buffer.from(j.tag, 'base64');
  const dati = Buffer.from(j.dati, 'base64');
  const key = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, 200000, 32, 'sha256');
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  const dec = Buffer.concat([d.update(dati), d.final()]); // se la password e sbagliata, qui lancia errore
  return dec.toString('utf8');
}

// sessione sbloccata in memoria (non su disco): le parole restano qui solo finche l'app e aperta e sbloccata
let fraseSbloccata = null;

function saveMnemonic(frase, password) {
  if (!password || String(password).length < 8) throw new Error('La password deve avere almeno 8 caratteri.');
  // rete di sicurezza: copia del portafoglio precedente prima di sostituirlo
  try {
    if (fs.existsSync(walletFile())) {
      const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
      fs.copyFileSync(walletFile(), path.join(userData(), 'wallet-precedente-' + stamp + '.bbkey'));
    }
  } catch (e) {}
  fs.writeFileSync(walletFile(), cifraFrase(frase, password));
  try {
    const addr = wallet.indirizzoDaFrase(frase);
    fs.writeFileSync(addrPubFile(), addr);
    aggiungiIndirizzo(addr);
  } catch (e) {}
  fraseSbloccata = frase; // resta sbloccato per questa sessione
}
function sbloccaConPassword(password) {
  const contenuto = fs.readFileSync(walletFile(), 'utf8');
  const frase = decifraFrase(contenuto, password); // lancia se password errata
  fraseSbloccata = frase;
  return frase;
}
function loadMnemonic() {
  if (fraseSbloccata) return fraseSbloccata;
  throw new Error('Portafoglio bloccato: serve la password.');
}

// ---------------- RPC verso il nodo locale ----------------
function ensureRpcPass() {
  if (rpcPass) return rpcPass;
  try { rpcPass = fs.readFileSync(passFile(), 'utf8').trim(); } catch (e) {}
  if (!rpcPass) { rpcPass = crypto.randomBytes(16).toString('hex'); fs.writeFileSync(passFile(), rpcPass); }
  return rpcPass;
}
function rpc(method, params = []) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '1.0', id: 'bb', method, params });
    const auth = 'Basic ' + Buffer.from(RPC_USER + ':' + rpcPass).toString('base64');
    const req = http.request(
      { host: '127.0.0.1', port: RPC_PORT, method: 'POST', path: '/',
        headers: { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(body), 'Authorization': auth } },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => {
        try { const j = JSON.parse(d); if (j.error) reject(new Error(j.error.message || 'errore RPC')); else resolve(j.result); }
        catch (e) { reject(e); }
      }); });
    req.on('error', reject);
    req.setTimeout(20000, () => req.destroy(new Error('RPC scaduto')));
    req.write(body); req.end();
  });
}

// ---------------- nodo ----------------
function startNode() {
  if (nodeProc) return;
  if (!fs.existsSync(nodeExe())) throw new Error('Manca il programma del nodo (bin/node/bitcoboostd.exe).');
  ensureRpcPass();
  fs.mkdirSync(chainDir(), { recursive: true });
  const args = [
    '-datadir=' + chainDir(), '-server=1', '-listen=1', '-disablewallet=1',
    '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1',
    '-rpcport=' + RPC_PORT, '-rpcuser=' + RPC_USER, '-rpcpassword=' + rpcPass,
    '-addnode=seed1.bitcoboost.com:38210', '-addnode=seed2.bitcoboost.com:38210', '-addnode=seed3.bitcoboost.com:38210', '-dnsseed=1', '-maxtipage=2592000000',
  ];
  nodeProc = spawn(nodeExe(), args, { windowsHide: true });
  nodeProc.on('exit', () => { nodeProc = null; });
  nodeProc.on('error', () => { nodeProc = null; });
}
async function nodeReady(timeoutMs = 90000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try { await rpc('getblockchaininfo'); return true; }
    catch (e) { await new Promise(r => setTimeout(r, 1500)); }
  }
  return false;
}

// ---------------- motore di mining ----------------
function onMinerOut(buf) {
  const s = buf.toString();
  minerLastAt = Date.now();
  const m = s.match(/([\d.]+)\s*(H|kH|KH|MH|GH)\/s/i);
  if (m) minerHashrate = m[1] + ' ' + m[2] + '/s';
}
function tentaVariante(exeName, addr) {
  return new Promise((resolve) => {
    const exe = path.join(minerDir(), exeName);
    if (!fs.existsSync(exe)) return resolve(null);
    const args = ['-a', 'x16rv2', '-o', 'stratum+tcp://127.0.0.1:' + STRATUM_PORT, '-u', 'x', '-p', 'x', '-t', String(coresDaUsare())];
    let p;
    try { p = spawn(exe, args, { windowsHide: true }); } catch (e) { return resolve(null); }
    if (p.stdout) p.stdout.on('data', onMinerOut);
    if (p.stderr) p.stderr.on('data', onMinerOut);
    let deciso = false;
    const guard = setTimeout(() => { if (!deciso) { deciso = true; resolve({ proc: p, exe: exeName }); } }, 3000);
    p.on('exit', () => { if (!deciso) { deciso = true; clearTimeout(guard); resolve(null); } });
    p.on('error', () => { if (!deciso) { deciso = true; clearTimeout(guard); resolve(null); } });
  });
}
let minerGen = 0;  // contatore generazioni: serve a ignorare l'uscita ritardata di un motore vecchio
async function startMiner(addr) {
  if (minerProc) return true;
  const ordine = minerVariantOk ? [minerVariantOk, ...MINER_VARIANTS.filter(v => v !== minerVariantOk)] : MINER_VARIANTS;
  for (const v of ordine) {
    const r = await tentaVariante(v, addr);
    if (r) {
      const gen = ++minerGen;
      minerProc = r.proc; minerVariantOk = r.exe;
      minerProc.on('exit', () => { if (gen === minerGen) minerProc = null; });
      return true;
    }
  }
  return false;
}
function attesaMorte(proc, ms = 4000) {
  return new Promise((resolve) => {
    if (!proc || proc.killed || proc.exitCode !== null) return resolve();
    let fatto = false;
    const fine = () => { if (!fatto) { fatto = true; resolve(); } };
    proc.once('exit', fine);
    setTimeout(fine, ms);
  });
}

function startBridge(addr) {
  if (bridgeProc) { try { bridgeProc.kill(); } catch (e) {} bridgeProc = null; }
  const script = path.join(__dirname, 'minerbridge.js');
  const env = Object.assign({}, process.env, {
    ELECTRON_RUN_AS_NODE: '1',
    BB_RPCPORT: String(RPC_PORT), BB_RPCUSER: RPC_USER, BB_RPCPASS: rpcPass,
    BB_PAYOUT: addr, BB_STRATUM_PORT: String(STRATUM_PORT),
    BB_LOG: path.join(userData(), 'minerbridge.log'),
  });
  bridgeProc = spawn(process.execPath, [script], { env, windowsHide: true });
  bridgeProc.on('exit', () => { bridgeProc = null; });
  bridgeProc.on('error', () => { bridgeProc = null; });
}
function stopBridge() { if (bridgeProc) { try { bridgeProc.kill(); } catch (e) {} bridgeProc = null; } }

let avvioInCorso = false;
async function startMining() {
  if (minerProc) { await stopMining(); }   // pulizia di sicurezza se era rimasto qualcosa
  const addr = indirizzoPubblico() || wallet.indirizzoDaFrase(loadMnemonic());
  sessioneBaseAddr = addr;
  sessioneAltezzaBase = null;   // verra fissata in refreshSaldo quando la catena e davvero allineata
  sessioneArmata = false;
  sessioneCache = '0,000000';
  startNode();
  if (!(await nodeReady())) throw new Error('Il nodo non si e avviato in tempo. Riprova tra poco.');
  startBridge(addr);
  if (!(await startMiner(addr))) throw new Error('Nessuna versione del motore e riuscita a partire (controlla la cartella bin/miner).');
  miningOn = true;
  avviaWatchdog();
}
async function stopMining() {
  minerGen++;                 // invalida la generazione attuale: eventuali 'exit' tardivi non toccheranno il nuovo motore
  const vecchio = minerProc;
  minerProc = null;
  if (vecchio) { try { vecchio.kill(); } catch (e) {} await attesaMorte(vecchio); }
  { const ponte = bridgeProc; bridgeProc = null; if (ponte) { try { ponte.kill(); } catch (e) {} await attesaMorte(ponte); } }
  miningOn = false;
  minerHashrate = '';
  minerLastAt = 0;
  fermaWatchdog();
}

// ---------------- WATCHDOG: sorveglia e auto-recupera mentre si mina ----------------
let watchdogTimer = null;
let recuperoInCorso = false;
async function watchdogTick() {
  if (!miningOn || recuperoInCorso) return;
  recuperoInCorso = true;
  try {
    // a) il nodo e vivo?
    if (!nodeProc) {
      startNode();
      await nodeReady(60000);
    }
    // b) il nodo risponde? (se internet e caduto puo non rispondere)
    let nodoOk = false;
    try { await rpc('getblockchaininfo'); nodoOk = true; } catch (e) { nodoOk = false; }

    if (nodoOk) {
      // c) ha peer? se 0, riprova a collegarsi ai seed
      try {
        const n = await rpc('getconnectioncount');
        if (!n || n === 0) {
          for (const s of ['seed1.bitcoboost.com:38210','seed2.bitcoboost.com:38210','seed3.bitcoboost.com:38210']) {
            try { await rpc('addnode', [s, 'onetry']); } catch (e) {}
          }
        }
      } catch (e) {}

      // d) il ponte e vivo? se no, riavvialo
      const addr = indirizzoPubblico() || sessioneBaseAddr;
      if (!bridgeProc && addr) { startBridge(addr); }

      // e) il motore e vivo e sta LAVORANDO? (muto da troppo tempo = bloccato)
      const mutoDaSec = minerLastAt ? (Date.now() - minerLastAt) / 1000 : 9999;
      if (!minerProc || mutoDaSec > 120) {
        // riavvia il motore pulito
        minerGen++;
        const vecchio = minerProc; minerProc = null;
        if (vecchio) { try { vecchio.kill(); } catch (e) {} await attesaMorte(vecchio); }
        if (addr) { try { await startMiner(addr); } catch (e) {} }
      }
    }
  } catch (e) {
    // non bloccare mai: il prossimo giro riprova
  } finally {
    recuperoInCorso = false;
  }
}
function avviaWatchdog() {
  if (watchdogTimer) return;
  watchdogTimer = setInterval(watchdogTick, 15000);
}
function fermaWatchdog() {
  if (watchdogTimer) { clearInterval(watchdogTimer); watchdogTimer = null; }
}

// ---------------- saldo (senza wallet, scansione UTXO) ----------------
function sincronizzandoRete(r) { return reteInIBD; } // non fissare il punto di partenza mentre la catena si sta ancora allineando
async function refreshSaldo(addr) {
  if (scanning || Date.now() - lastScan < 12000) return;
  scanning = true;
  try {
    const fmt = (v) => Number(v).toFixed(6).replace('.', ',');
    const tutti = leggiIndirizzi().slice();
    if (addr && !tutti.includes(addr)) tutti.push(addr);
    const desc = tutti.map((a) => 'addr(' + a + ')');
    try { const bc0 = await rpc('getblockchaininfo'); reteInIBD = !!bc0.initialblockdownload; } catch (e) {}
    const r = await rpc('scantxoutset', ['start', desc]);
    if (r && r.unspents) {
      const tip = r.height || 0;
      const perAddr = {};
      let immature = 0, soonest = null;
      for (const u of r.unspents) {
        const m = /addr\((bb1[0-9a-z]+)\)/.exec(u.desc || '');
        const a = m ? m[1] : null;
        if (a) perAddr[a] = (perAddr[a] || 0) + u.amount;
        if (a === addr && u.coinbase && (tip - u.height) < 99) {
          immature += u.amount;
          const rem = (u.height + 99) - tip;
          if (soonest === null || rem < soonest) soonest = rem;
        }
      }
      const cur = perAddr[addr] || 0;
      let prec = 0; const lista = [];
      for (const a of tutti) { if (a !== addr) { const v = perAddr[a] || 0; prec += v; if (v > 0) lista.push({ indirizzo: a, saldo: fmt(v) }); } }
      saldoCache = fmt(cur);
      inArrivoCache = fmt(immature);
      maturaTra = (immature > 0) ? Math.max(0, soonest) : null;
      precCache = fmt(prec);
      precLista = lista;
      // --- guadagno di QUESTA sessione: somma dei premi dei MIEI blocchi trovati DOPO l'avvio ---
      if (miningOn && sessioneBaseAddr === addr && !sincronizzandoRete(r)) {
        if (!sessioneArmata) {
          // fissa il punto di partenza solo ora che la catena e allineata (saldo reale gia letto)
          sessioneAltezzaBase = tip;
          sessioneArmata = true;
          sessioneCache = '0,000000';
        } else {
          let guadagno = 0;
          for (const u of r.unspents) {
            const m = /addr\((bb1[0-9a-z]+)\)/.exec(u.desc || '');
            if (m && m[1] === addr && u.coinbase && u.height > sessioneAltezzaBase) guadagno += u.amount;
          }
          sessioneCache = fmt(guadagno);
        }
      }
    }
  } catch (e) {} finally { scanning = false; lastScan = Date.now(); }
}

// ---------------- canali verso la grafica ----------------
ipcMain.handle('app:stato', async () => {
  const esiste = walletExists();
  let indirizzo = esiste ? indirizzoPubblico() : null;
  if (esiste && !indirizzo) { try { indirizzo = wallet.indirizzoDaFrase(loadMnemonic()); } catch (e) {} }
  if (indirizzo && nodeProc) { refreshSaldo(indirizzo); } // in sottofondo, non blocca
  const formatoVecchio = esiste && !formatoNuovo();
  return { haWallet: esiste, bloccato: !fraseSbloccata, formatoVecchio, indirizzo, mining: miningOn, saldo: esiste ? saldoCache : '0,000000', inArrivo: esiste ? inArrivoCache : '0,000000', maturaTra: esiste ? maturaTra : null, precedenti: esiste ? precCache : '0,000000', precLista: esiste ? precLista : [], sessione: esiste ? sessioneCache : '0,000000', minandoSessione: (miningOn && sessioneArmata) };
});
ipcMain.handle('mining:info', async () => {
  const info = {
    mining: miningOn,
    motoreVivo: !!minerProc,
    hashrate: minerHashrate || null,
    ultimaAttivitaSec: minerLastAt ? Math.round((Date.now() - minerLastAt) / 1000) : null,
    peers: null, blocchi: null, sincronizzando: null,
  };
  if (nodeProc) {
    try { const bc = await rpc('getblockchaininfo'); info.blocchi = bc.blocks; info.sincronizzando = !!bc.initialblockdownload; reteInIBD = !!bc.initialblockdownload; info.difficolta = bc.difficulty; } catch (e) {}
    try { info.peers = await rpc('getconnectioncount'); } catch (e) {}
    try { const mi = await rpc('getmininginfo'); info.hashrateRete = mi.networkhashps; } catch (e) {}
    try { info.rete = datiRete(info.blocchi); } catch (e) {}
  }
  return info;
});
// --- calcolo dati di rete dalle REGOLE della moneta (precisi, senza scansioni lente) ---
const MAX_SUPPLY = 21000000;
function premioBlocco(h) {
  if (h <= 0) return 0;
  if (h <= 1000) return 1;
  if (h <= 2000) return 10;
  const halvings = Math.floor((h - 2001) / 210000);
  if (halvings >= 64) return 0;
  return 50 / Math.pow(2, halvings);
}
function totaleMinato(tip) {
  // somma dei premi dei blocchi 1..tip (il genesi non e spendibile)
  let t = 0;
  const n = Math.max(0, tip || 0);
  for (let h = 1; h <= n; h++) {
    if (h <= 1000) t += 1;
    else if (h <= 2000) t += 10;
    else {
      const halvings = Math.floor((h - 2001) / 210000);
      t += (halvings >= 64) ? 0 : 50 / Math.pow(2, halvings);
    }
  }
  return t;
}
function prossimoDimezzamento(tip) {
  if (tip <= 2000) return { blocco: 2001, mancano: 2001 - tip, premioOra: premioBlocco(Math.max(1, tip)), premioDopo: 10 < 50 ? premioBlocco(2001) : 50 };
  const halvings = Math.floor((tip - 2001) / 210000);
  const prossimo = 2001 + (halvings + 1) * 210000;
  return { blocco: prossimo, mancano: prossimo - tip, premioOra: premioBlocco(tip), premioDopo: premioBlocco(prossimo) };
}
function datiRete(tip) {
  if (tip == null) return null;
  const minato = totaleMinato(tip);
  const dim = prossimoDimezzamento(tip);
  return {
    minato, maxSupply: MAX_SUPPLY,
    percentuale: (minato / MAX_SUPPLY) * 100,
    premioOra: premioBlocco(Math.max(1, tip)),
    prossimoDimezzamentoBlocco: dim.blocco,
    mancanoAlDimezzamento: dim.mancano,
    premioDopoDimezzamento: dim.premioDopo,
  };
}
ipcMain.handle('wallet:crea', () => {
  const frase = wallet.generaFrase();
  return { frase, indirizzo: wallet.indirizzoDaFrase(frase) };
});
ipcMain.handle('wallet:salva', (e, frase, password) => {
  try {
    saveMnemonic(frase, password);
    return { ok: true, indirizzo: wallet.indirizzoDaFrase(frase) };
  } catch (err) { return { ok: false, messaggio: err.message }; }
});
ipcMain.handle('wallet:importa', (e, frase, password) => {
  const f = wallet.normalizzaFrase(frase);
  if (!wallet.validaFrase(f)) {
    return { ok: false, messaggio: 'Le parole non sembrano valide. Controlla di averle scritte tutte, in minuscolo e nell\'ordine giusto (di solito sono 12).' };
  }
  try {
    saveMnemonic(f, password);
    return { ok: true, indirizzo: wallet.indirizzoDaFrase(f) };
  } catch (err) { return { ok: false, messaggio: err.message }; }
});
ipcMain.handle('wallet:frase', () => {
  try {
    const f = loadMnemonic();
    fraseSbloccata = null;            // opzione 3: subito ri-bloccato dopo l'uso
    return { ok: true, frase: f };
  }
  catch (e) { return { ok: false, bloccato: true }; }
});
ipcMain.handle('wallet:sblocca', (e, password) => {
  try { sbloccaConPassword(password); return { ok: true, indirizzo: indirizzoPubblico() }; }
  catch (err) { return { ok: false, messaggio: 'Password errata.' }; }
});
ipcMain.handle('wallet:blocca', () => { fraseSbloccata = null; return { ok: true }; });
ipcMain.handle('wallet:reset', () => {
  // NON cancella: archivia i file attuali, cosi nulla va perso, e libera l'app per ripartire
  try {
    const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
    for (const f of ['wallet.dat', 'indirizzo.txt']) {
      const p = path.join(userData(), f);
      if (fs.existsSync(p)) fs.renameSync(p, p + '.archiviato-' + stamp);
    }
  } catch (e) {}
  fraseSbloccata = null;
  try { stopMining(); } catch (e) {}
  saldoCache = '0,000000'; inArrivoCache = '0,000000'; maturaTra = null; precCache = '0,000000'; precLista = [];
  return { ok: true };
});
ipcMain.handle('wallet:fileRecupero', async () => {
  try {
    if (!fraseSbloccata) return { ok: false, messaggio: 'Sblocca prima il portafoglio.' };
    const contenuto = fs.readFileSync(walletFile(), 'utf8'); // gia cifrato con la password utente
    const { dialog } = require('electron');
    const r = await dialog.showSaveDialog(mainWindow, {
      title: 'Salva il file di recupero',
      defaultPath: 'bitcoboost-recupero.bbkey',
      filters: [{ name: 'File di recupero BitcoBoost', extensions: ['bbkey'] }],
    });
    if (r.canceled || !r.filePath) return { ok: false, messaggio: 'Salvataggio annullato.' };
    fs.writeFileSync(r.filePath, contenuto);
    return { ok: true, percorso: r.filePath };
  } catch (err) { return { ok: false, messaggio: err.message }; }
});
ipcMain.handle('cpu:stato', () => ({ percent: cpuPercent, cores: coresDaUsare(), totale: os.cpus().length }));
ipcMain.handle('cpu:imposta', async (e, percent) => {
  const p = (Number(percent) === 80) ? 80 : 100;
  cpuPercent = p;
  const s = leggiImpostazioni(); s.cpuPercent = p; scriviImpostazioni(s);
  // se sta minando, riavvia SOLO il motore con la nuova impostazione (nodo e bridge restano su)
  if (miningOn && minerProc) {
    minerGen++;
    const vecchio = minerProc; minerProc = null;
    try { vecchio.kill(); } catch (e2) {}
    await attesaMorte(vecchio);
    const addr = indirizzoPubblico();
    try { await startMiner(addr); } catch (e2) {}
  }
  return { ok: true, percent: cpuPercent, cores: coresDaUsare(), totale: os.cpus().length };
});
ipcMain.handle('mining:toggle', async () => {
  if (avvioInCorso) return { ok: true, mining: miningOn };  // ignora i doppi clic ravvicinati
  avvioInCorso = true;
  try {
    if (miningOn) { await stopMining(); }
    else { await startMining(); }
    return { ok: true, mining: miningOn };
  } catch (e) {
    await stopMining();
    return { ok: false, mining: false, errore: e.message };
  } finally {
    avvioInCorso = false;
  }
});
ipcMain.handle('invio:invia', async (e, dati) => {
  try {
    if (!nodeProc) return { ok: false, messaggio: 'Per inviare, avvia prima il mining (serve il nodo acceso).' };
    if (!dati || !dati.indirizzo) return { ok: false, messaggio: 'Manca l\'indirizzo del destinatario.' };
    let frase; try { frase = loadMnemonic(); } catch (err) { return { ok: false, messaggio: 'Portafoglio bloccato: inserisci la password per inviare.' }; }
    const mio = wallet.indirizzoDaFrase(frase);
    const riblocca = () => { fraseSbloccata = null; };
    const info = await rpc('getblockchaininfo');
    const altezza = info.blocks;
    const scan = await rpc('scantxoutset', ['start', ['addr(' + mio + ')']]);
    const utxos = [];
    for (const u of (scan.unspents || [])) {
      if (u.coinbase && (altezza - u.height) < 100) continue; // premio non ancora maturo
      utxos.push({ txid: u.txid, vout: u.vout, valoreSat: Math.round(u.amount * 1e8), scriptHex: u.scriptPubKey });
    }
    if (utxos.length === 0) return { ok: false, messaggio: 'Non hai ancora BB disponibili da inviare. I premi appena minati diventano spendibili dopo 100 blocchi.' };
    const tutto = !!dati.tutto;
    const nOut = tutto ? 1 : 2;
    const vbytes = Math.ceil(10.5 + 68 * utxos.length + 31 * nOut);
    const feeSat = Math.max(200, vbytes); // circa 1 sat per vByte, minimo 200
    const importoSat = tutto ? 'tutto' : Math.round(Number(String(dati.importo).replace(',', '.')) * 1e8);
    if (!tutto && (!Number.isFinite(importoSat) || importoSat <= 0)) return { ok: false, messaggio: 'Importo non valido.' };
    const hex = wallet.creaTransazione({ frase, utxos, destinazione: dati.indirizzo, importoSat, feeSat });
    const txid = await rpc('sendrawtransaction', [hex]);
    riblocca();   // opzione 3: ri-blocca subito dopo l'invio
    return { ok: true, messaggio: 'Inviato! Codice transazione: ' + txid, txid };
  } catch (err) {
    fraseSbloccata = null;   // ri-blocca anche in caso di errore
    return { ok: false, messaggio: 'Non e stato possibile inviare: ' + err.message };
  }
});

// ---------------- quantum-safe (bb1z) ----------------
ipcMain.handle('bb1z:indirizzo', async () => {
  try {
    const frase = loadMnemonic();
    const bb = await getBB1Z();
    const r = bb.indirizzoBB1Z(frase, wallet.BB, wallet.BB.bech32);
    return { ok: true, indirizzo: r.address, scriptPubKey: r.scriptPubKey };
  } catch (err) { return { ok: false, messaggio: err.message }; }
});
ipcMain.handle('bb1z:saldo', async () => {
  try {
    if (!nodeProc) return { ok: false, messaggio: "Avvia il mining per leggere il saldo." };
    const frase = loadMnemonic();
    const bb = await getBB1Z();
    const r = bb.indirizzoBB1Z(frase, wallet.BB, wallet.BB.bech32);
    const scan = await rpc('scantxoutset', ['start', ['raw(' + r.scriptPubKey + ')']]);
    return { ok: true, indirizzo: r.address, saldoSat: Math.round((scan.total_amount || 0) * 1e8), monete: (scan.unspents || []).length };
  } catch (err) { return { ok: false, messaggio: err.message }; }
});
ipcMain.handle('bb1z:invia', async (e, dati) => {
  try {
    if (!nodeProc) return { ok: false, messaggio: "Per inviare, avvia prima il mining (serve il nodo acceso)." };
    if (!dati || !dati.indirizzo) return { ok: false, messaggio: "Manca l'indirizzo del destinatario." };
    let frase; try { frase = loadMnemonic(); } catch (err) { return { ok: false, messaggio: "Portafoglio bloccato: inserisci la password per inviare." }; }
    const bb = await getBB1Z();
    const info = bb.indirizzoBB1Z(frase, wallet.BB, wallet.BB.bech32);
    const chain = await rpc('getblockchaininfo');
    const altezza = chain.blocks;
    const scan = await rpc('scantxoutset', ['start', ['raw(' + info.scriptPubKey + ')']]);
    const utxos = [];
    for (const u of (scan.unspents || [])) {
      if (u.coinbase && (altezza - u.height) < 100) continue;
      utxos.push({ txid: u.txid, vout: u.vout, valoreSat: Math.round(u.amount * 1e8) });
    }
    if (utxos.length === 0) { fraseSbloccata = null; return { ok: false, messaggio: "Non hai BB quantum-safe disponibili da inviare." }; }
    const bitcoin = require('bitcoinjs-lib');
    let destScriptHex;
    try { destScriptHex = Buffer.from(bitcoin.address.toOutputScript(dati.indirizzo, wallet.BB)).toString('hex'); }
    catch (err2) { fraseSbloccata = null; return { ok: false, messaggio: "Indirizzo destinatario non valido." }; }
    const tutto = !!dati.tutto;
    const nOut = tutto ? 1 : 2;
    const vbytes = Math.ceil(11 + 1020 * utxos.length + 31 * nOut);
    const feeSat = Math.max(500, vbytes);
    const importoSat = tutto ? 'tutto' : Math.round(Number(String(dati.importo).replace(',', '.')) * 1e8);
    if (!tutto && (!Number.isFinite(importoSat) || importoSat <= 0)) { fraseSbloccata = null; return { ok: false, messaggio: "Importo non valido." }; }
    const hex = bb.firmaBB1Z({ frase, network: wallet.BB, utxos, destScriptHex, importoSat, feeSat });
    const txid = await rpc('sendrawtransaction', [hex]);
    fraseSbloccata = null;
    return { ok: true, messaggio: "Inviato (quantum-safe)! Codice transazione: " + txid, txid };
  } catch (err) {
    fraseSbloccata = null;
    return { ok: false, messaggio: "Non e stato possibile inviare: " + err.message };
  }
});

// ---------------- ciclo di vita ----------------
function cmpVer(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) { if ((pa[i]||0) > (pb[i]||0)) return 1; if ((pa[i]||0) < (pb[i]||0)) return -1; }
  return 0;
}
let aggiornamento = null;
function controllaVersione() {
  try {
    https.get(VERSION_URL, { timeout: 8000 }, (res) => {
      let d = '';
      res.on('data', (c) => d += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(d);
          if (j && j.versione && cmpVer(j.versione, APP_VERSION) > 0) {
            aggiornamento = { versione: j.versione, url: j.url || 'https://bitcoboost.com/downloads/', note: j.note || '' };
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('app:aggiornamento', aggiornamento);
          }
        } catch (e) {}
      });
    }).on('error', () => {});
  } catch (e) {}
}
ipcMain.handle('app:apriLink', (e, url) => { try { shell.openExternal(url); } catch (e) {} return true; });
ipcMain.handle('app:versione', () => ({ versione: APP_VERSION, aggiornamento }));

app.whenReady().then(() => {
  createWindow();
  // avvia il nodo in sottofondo (solo per mostrare le statistiche), senza minare
  try { if (walletExists()) startNode(); } catch (e) {}
  // controlla se c'e una versione piu recente
  setTimeout(controllaVersione, 4000);
});
app.on('before-quit', () => {
  try { if (minerProc) minerProc.kill(); } catch (e) {}
  try { if (nodeProc) nodeProc.kill(); } catch (e) {}
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
