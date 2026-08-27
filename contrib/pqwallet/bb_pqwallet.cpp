// bb-pqwallet — portafoglio di firma quantum-safe per BitcoBoost (indirizzi bb1z, witness v2)
// Custodisce ECDSA(secp256k1) + ML-DSA-44, backup cifrato (PBKDF2-HMAC-SHA512 + ChaCha20-Poly1305).
// Comandi:
//   new   <file> <passphrase> [mainnet|regtest]
//   addr  <file> <passphrase>
//   sign  <file> <passphrase> <txid> <vout> <amount_sat> <dest_spk_hex> <send_sat> [bad|badec]
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <sys/random.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <streams.h>
#include <span.h>
#include <uint256.h>
#include <util/transaction_identifier.h>
#include <crypto/hmac_sha512.h>
#include <crypto/chacha20poly1305.h>
#include <secp256k1.h>
extern "C" {
#include "api.h"
#include "fips202.h"
}

static const int MPKB = 1312, MSKB = 2560, EPKB = 33, ESKB = 32;
static const uint32_t ITERS = 600000;
static const char* MAGIC = "BBPQ";

static void rnd(uint8_t* p, size_t n){
    size_t g=0;
    while(g<n){ ssize_t r=getrandom(p+g,n-g,0); if(r<=0){ FILE*f=fopen("/dev/urandom","rb"); if(f){ if(fread(p+g,1,n-g,f)){} fclose(f);} break;} g+=(size_t)r; }
}
static std::vector<uint8_t> readf(const char*p){
    FILE*f=fopen(p,"rb"); if(!f){fprintf(stderr,"impossibile aprire %s\n",p);exit(5);}
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    std::vector<uint8_t> v(n>0?n:0); if(n>0 && fread(v.data(),1,n,f)!=(size_t)n){} fclose(f); return v;
}
static void writef(const char*p,const uint8_t*d,size_t n){ FILE*f=fopen(p,"wb"); if(!f){fprintf(stderr,"impossibile scrivere %s\n",p);exit(5);} fwrite(d,1,n,f); fclose(f); }
static std::vector<uint8_t> hexb(const std::string&h){ std::vector<uint8_t> v; for(size_t i=0;i+1<h.size();i+=2) v.push_back((uint8_t)strtol(h.substr(i,2).c_str(),0,16)); return v; }
static void phex(const uint8_t*d,size_t n){ for(size_t i=0;i<n;i++) printf("%02x",d[i]); }
static uint256 parse_txid(const std::string&h){ auto b=hexb(h); std::reverse(b.begin(),b.end()); uint256 r; memcpy(r.begin(),b.data(),32); return r; }

// --- PBKDF2-HMAC-SHA512 -> 32 byte ---
static void pbkdf2(const uint8_t*pass,size_t pl,const uint8_t*salt,size_t sl,uint32_t iters,uint8_t out32[32]){
    uint8_t U[64],T[64];
    { CHMAC_SHA512 h(pass,pl); h.Write(salt,sl); uint8_t idx[4]={0,0,0,1}; h.Write(idx,4); h.Finalize(U); memcpy(T,U,64); }
    for(uint32_t i=1;i<iters;i++){ CHMAC_SHA512 h(pass,pl); h.Write(U,64); h.Finalize(U); for(int k=0;k<64;k++) T[k]^=U[k]; }
    memcpy(out32,T,32);
}
static AEADChaCha20Poly1305::Nonce96 mk_nonce(const uint8_t n[12]){
    uint32_t a; uint64_t b; memcpy(&a,n,4); memcpy(&b,n+4,8); return {a,b};
}

// --- bech32m (BIP350) ---
static const char* CH="qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static uint32_t polymod(const std::vector<int>&v){
    static const uint32_t G[5]={0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3}; uint32_t c=1;
    for(int x:v){ int b=c>>25; c=((c&0x1ffffff)<<5)^x; for(int i=0;i<5;i++) if((b>>i)&1) c^=G[i]; } return c;
}
static std::vector<int> hrpexp(const std::string&h){ std::vector<int> r; for(char c:h) r.push_back((uint8_t)c>>5); r.push_back(0); for(char c:h) r.push_back((uint8_t)c&31); return r; }
static std::vector<int> cksum(const std::string&hrp,const std::vector<int>&d){
    std::vector<int> v=hrpexp(hrp); v.insert(v.end(),d.begin(),d.end()); for(int i=0;i<6;i++) v.push_back(0);
    uint32_t p=polymod(v)^0x2bc830a3u; std::vector<int> r; for(int i=0;i<6;i++) r.push_back((p>>(5*(5-i)))&31); return r;
}
static std::vector<int> convertbits(const std::vector<uint8_t>&data){
    int acc=0,bits=0; std::vector<int> ret; int maxv=31;
    for(uint8_t v:data){ acc=(acc<<8)|v; bits+=8; while(bits>=5){ bits-=5; ret.push_back((acc>>bits)&maxv);} }
    if(bits) ret.push_back((acc<<(5-bits))&maxv); return ret;
}
static std::string bb1z_addr(const std::string&hrp,const uint8_t program[32]){
    std::vector<int> data; data.push_back(2);
    auto bits=convertbits(std::vector<uint8_t>(program,program+32));
    data.insert(data.end(),bits.begin(),bits.end());
    auto c=cksum(hrp,data); data.insert(data.end(),c.begin(),c.end());
    std::string s=hrp+"1"; for(int d:data) s+=CH[d]; return s;
}

// stato chiavi in chiaro (dopo decifratura)
struct Keys { uint8_t esk[32],epk[33]; std::vector<uint8_t> msk,mpk; uint8_t program[32]; uint8_t net; };

static void compute_program(const uint8_t epk[33],const std::vector<uint8_t>&mpk,uint8_t program[32]){
    std::vector<uint8_t> km; km.insert(km.end(),epk,epk+33); km.insert(km.end(),mpk.begin(),mpk.end());
    shake256(program,32,km.data(),km.size());
}
static std::string hrp_for(uint8_t net){ return net==1?std::string("bcrt"):std::string("bb"); }

// --- backup: [MAGIC(4)][ver(1)=1][net(1)][iters(4 BE)][salt(16)][nonce(12)][cipher] ---
// plaintext = esk(32)|epk(33)|msk(2560)|mpk(1312) = 3937
static void save_backup(const char*file,const std::string&pass,const Keys&k){
    std::vector<uint8_t> pt; pt.insert(pt.end(),k.esk,k.esk+32); pt.insert(pt.end(),k.epk,k.epk+33);
    pt.insert(pt.end(),k.msk.begin(),k.msk.end()); pt.insert(pt.end(),k.mpk.begin(),k.mpk.end());
    uint8_t salt[16],nonce[12]; rnd(salt,16); rnd(nonce,12);
    uint8_t key[32]; pbkdf2((const uint8_t*)pass.data(),pass.size(),salt,16,ITERS,key);
    std::vector<uint8_t> hdr; hdr.insert(hdr.end(),MAGIC,MAGIC+4); hdr.push_back(1); hdr.push_back(k.net);
    uint8_t it[4]={(uint8_t)(ITERS>>24),(uint8_t)(ITERS>>16),(uint8_t)(ITERS>>8),(uint8_t)ITERS};
    hdr.insert(hdr.end(),it,it+4); hdr.insert(hdr.end(),salt,salt+16); hdr.insert(hdr.end(),nonce,nonce+12);
    std::vector<std::byte> kb(32); memcpy(kb.data(),key,32); AEADChaCha20Poly1305 aead{Span<const std::byte>(kb.data(),kb.size())};
    std::vector<std::byte> ptb(pt.size()); memcpy(ptb.data(),pt.data(),pt.size());
    std::vector<std::byte> aadb(hdr.size()); memcpy(aadb.data(),hdr.data(),hdr.size());
    std::vector<std::byte> ct(pt.size()+AEADChaCha20Poly1305::EXPANSION);
    aead.Encrypt(ptb, aadb, mk_nonce(nonce), ct);
    std::vector<uint8_t> out=hdr; for(auto b:ct) out.push_back((uint8_t)b);
    writef(file,out.data(),out.size());
}
static bool load_backup(const char*file,const std::string&pass,Keys&k){
    auto in=readf(file);
    if(in.size()<38 || memcmp(in.data(),MAGIC,4)!=0){ fprintf(stderr,"file backup non valido\n"); return false; }
    k.net=in[5];
    uint32_t iters=(in[6]<<24)|(in[7]<<16)|(in[8]<<8)|in[9];
    const uint8_t*salt=in.data()+10; const uint8_t*nonce=in.data()+26;
    std::vector<uint8_t> hdr(in.begin(),in.begin()+38);
    std::vector<uint8_t> ct(in.begin()+38,in.end());
    uint8_t key[32]; pbkdf2((const uint8_t*)pass.data(),pass.size(),salt,16,iters,key);
    std::vector<std::byte> kb(32); memcpy(kb.data(),key,32); AEADChaCha20Poly1305 aead{Span<const std::byte>(kb.data(),kb.size())};
    std::vector<std::byte> ctb(ct.size()); memcpy(ctb.data(),ct.data(),ct.size());
    std::vector<std::byte> aadb(hdr.size()); memcpy(aadb.data(),hdr.data(),hdr.size());
    std::vector<std::byte> pt(ct.size()-AEADChaCha20Poly1305::EXPANSION);
    uint8_t nb[12]; memcpy(nb,nonce,12);
    if(!aead.Decrypt(ctb,aadb,mk_nonce(nb),pt)){ fprintf(stderr,"passphrase errata o file corrotto\n"); return false; }
    std::vector<uint8_t> p(pt.size()); for(size_t i=0;i<pt.size();i++) p[i]=(uint8_t)pt[i];
    if(p.size()!=(size_t)(ESKB+EPKB+MSKB+MPKB)){ fprintf(stderr,"backup di dimensione inattesa\n"); return false; }
    size_t o=0; memcpy(k.esk,p.data()+o,32); o+=32; memcpy(k.epk,p.data()+o,33); o+=33;
    k.msk.assign(p.begin()+o,p.begin()+o+MSKB); o+=MSKB; k.mpk.assign(p.begin()+o,p.begin()+o+MPKB);
    compute_program(k.epk,k.mpk,k.program);
    return true;
}

int main(int argc,char**argv){
    if(argc<3){ fprintf(stderr,"uso: new|addr|sign <file> <passphrase> ...\n"); return 2; }
    std::string cmd=argv[1], file=argv[2];
    secp256k1_context*ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

    if(cmd=="new"){
        if(argc<4){ fprintf(stderr,"uso: new <file> <passphrase> [mainnet|regtest]\n"); return 2; }
        std::string pass=argv[3]; std::string net=(argc>4?argv[4]:"mainnet");
        Keys k; k.net=(net=="regtest")?1:0;
        do{ rnd(k.esk,32); }while(!secp256k1_ec_seckey_verify(ctx,k.esk));
        secp256k1_pubkey pk; if(!secp256k1_ec_pubkey_create(ctx,&pk,k.esk)){fprintf(stderr,"pubkey fallita\n");return 3;}
        size_t l=33; secp256k1_ec_pubkey_serialize(ctx,k.epk,&l,&pk,SECP256K1_EC_COMPRESSED);
        k.msk.resize(MSKB); k.mpk.resize(MPKB);
        if(PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(k.mpk.data(),k.msk.data())!=0){ fprintf(stderr,"keygen ML-DSA fallito\n"); return 3; }
        compute_program(k.epk,k.mpk,k.program);
        save_backup(file.c_str(),pass,k);
        printf("INDIRIZZO %s\n", bb1z_addr(hrp_for(k.net),k.program).c_str());
        printf("PROGRAM "); phex(k.program,32); printf("\n");
        printf("SCRIPTPUBKEY 5220"); phex(k.program,32); printf("\n");
        printf("BACKUP %s (cifrato; conserva passphrase e file: senza, i fondi sono persi)\n",file.c_str());
        return 0;
    }
    if(cmd=="addr"){
        if(argc<4){ fprintf(stderr,"uso: addr <file> <passphrase>\n"); return 2; }
        Keys k; if(!load_backup(file.c_str(),argv[3],k)) return 4;
        printf("%s\n", bb1z_addr(hrp_for(k.net),k.program).c_str());
        return 0;
    }
    if(cmd=="sign"){
        if(argc<9){ fprintf(stderr,"uso: sign <file> <pass> <txid> <vout> <amount_sat> <dest_spk_hex> <send_sat> [bad|badec]\n"); return 2; }
        Keys k; if(!load_backup(file.c_str(),argv[3],k)) return 4;
        std::string txid=argv[4]; uint32_t vout=(uint32_t)atoi(argv[5]); int64_t amount=atoll(argv[6]);
        std::vector<uint8_t> dest=hexb(argv[7]); int64_t send=atoll(argv[8]);
        std::string mode=(argc>9?argv[9]:""); bool bad=(mode=="bad"), badec=(mode=="badec");
        CMutableTransaction mtx; mtx.nVersion=2;
        CTxIn in; in.prevout=COutPoint(Txid::FromUint256(parse_txid(txid)),vout); in.nSequence=0xffffffff; mtx.vin.push_back(in);
        CTxOut out; out.nValue=send; out.scriptPubKey=CScript(dest.begin(),dest.end()); mtx.vout.push_back(out);
        CScript scriptCode; scriptCode << OP_2; scriptCode << std::vector<unsigned char>(k.program,k.program+32);
        const CTransaction txc(mtx);
        uint256 sighash=SignatureHash(scriptCode,txc,0,SIGHASH_ALL,(CAmount)amount,SigVersion::WITNESS_V0,nullptr);
        secp256k1_ecdsa_signature sig;
        if(!secp256k1_ecdsa_sign(ctx,&sig,sighash.begin(),k.esk,nullptr,nullptr)){ fprintf(stderr,"firma ECDSA fallita\n"); return 3; }
        unsigned char der[80]; size_t dl=80; secp256k1_ecdsa_signature_serialize_der(ctx,der,&dl,&sig);
        std::vector<unsigned char> esig(der,der+dl); esig.push_back(0x01); if(badec) esig[5]^=0xff;
        static const unsigned char CTX[]="BitcoBoost-bb1z-v2";
        std::vector<unsigned char> msig(PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES); size_t ml=0;
        if(PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(msig.data(),&ml,sighash.begin(),32,CTX,sizeof(CTX)-1,k.msk.data())!=0){ fprintf(stderr,"firma ML-DSA fallita\n"); return 4; }
        msig.resize(ml); if(bad) msig[10]^=0xff;
        std::vector<unsigned char> epk(k.epk,k.epk+33);
        mtx.vin[0].scriptWitness.stack={esig,epk,msig,k.mpk};
        DataStream ss; ss << TX_WITH_WITNESS(CTransaction(mtx));
        const unsigned char*pp=(const unsigned char*)ss.data();
        for(size_t i=0;i<ss.size();i++) printf("%02x",pp[i]); printf("\n");
        fprintf(stderr,"sighash=%s raw=%zuB\n",sighash.GetHex().c_str(),ss.size());
        return 0;
    }
    if(cmd=="desc"){
        // descrittore per scantxoutset: trova le monete ricevute sull'indirizzo
        if(argc<4){ fprintf(stderr,"uso: desc <file> <passphrase>\n"); return 2; }
        Keys k; if(!load_backup(file.c_str(),argv[3],k)) return 4;
        printf("raw(5220"); phex(k.program,32); printf(")\n");
        return 0;
    }
    if(cmd=="sign-multi"){
        // sign-multi <file> <pass> <dest_spk_hex> <invio_sat> <txid:vout:amount_sat> [altri...]
        if(argc<7){ fprintf(stderr,"uso: sign-multi <file> <pass> <dest_spk_hex> <invio_sat> <txid:vout:amount_sat> [...]\n"); return 2; }
        Keys k; if(!load_backup(file.c_str(),argv[3],k)) return 4;
        std::vector<uint8_t> dest=hexb(argv[4]); int64_t send=atoll(argv[5]);
        struct In{ std::string txid; uint32_t vout; int64_t amt; };
        std::vector<In> ins;
        for(int a=6;a<argc;a++){
            std::string s=argv[a]; size_t p1=s.find(':'), p2=s.rfind(':');
            if(p1==std::string::npos || p1==p2){ fprintf(stderr,"input malformato: %s (usa txid:vout:amount_sat)\n",s.c_str()); return 2; }
            In in; in.txid=s.substr(0,p1); in.vout=(uint32_t)atoi(s.substr(p1+1,p2-p1-1).c_str()); in.amt=atoll(s.substr(p2+1).c_str()); ins.push_back(in);
        }
        CMutableTransaction mtx; mtx.nVersion=2;
        for(auto&in:ins){ CTxIn ti; ti.prevout=COutPoint(Txid::FromUint256(parse_txid(in.txid)),in.vout); ti.nSequence=0xffffffff; mtx.vin.push_back(ti); }
        CTxOut out; out.nValue=send; out.scriptPubKey=CScript(dest.begin(),dest.end()); mtx.vout.push_back(out);
        CScript scriptCode; scriptCode << OP_2; scriptCode << std::vector<unsigned char>(k.program,k.program+32);
        const CTransaction txc(mtx);
        static const unsigned char CTX[]="BitcoBoost-bb1z-v2";
        std::vector<unsigned char> epk(k.epk,k.epk+33);
        for(size_t i=0;i<ins.size();i++){
            uint256 sh=SignatureHash(scriptCode,txc,(unsigned int)i,SIGHASH_ALL,(CAmount)ins[i].amt,SigVersion::WITNESS_V0,nullptr);
            secp256k1_ecdsa_signature sig;
            if(!secp256k1_ecdsa_sign(ctx,&sig,sh.begin(),k.esk,nullptr,nullptr)){ fprintf(stderr,"firma ECDSA fallita\n"); return 3; }
            unsigned char der[80]; size_t dl=80; secp256k1_ecdsa_signature_serialize_der(ctx,der,&dl,&sig);
            std::vector<unsigned char> esig(der,der+dl); esig.push_back(0x01);
            std::vector<unsigned char> msig(PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES); size_t ml=0;
            if(PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(msig.data(),&ml,sh.begin(),32,CTX,sizeof(CTX)-1,k.msk.data())!=0){ fprintf(stderr,"firma ML-DSA fallita\n"); return 4; }
            msig.resize(ml);
            mtx.vin[i].scriptWitness.stack={esig,epk,msig,k.mpk};
        }
        DataStream ss; ss << TX_WITH_WITNESS(CTransaction(mtx));
        const unsigned char*pp=(const unsigned char*)ss.data();
        for(size_t i=0;i<ss.size();i++) printf("%02x",pp[i]); printf("\n");
        int64_t tot=0; for(auto&in:ins) tot+=in.amt;
        fprintf(stderr,"input=%zu totale=%lld invio=%lld commissione=%lld raw=%zuB\n",ins.size(),(long long)tot,(long long)send,(long long)(tot-send),ss.size());
        return 0;
    }
    fprintf(stderr,"comando sconosciuto: %s\n",cmd.c_str()); return 2;
}
