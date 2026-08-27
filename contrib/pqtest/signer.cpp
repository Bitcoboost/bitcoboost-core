#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <streams.h>
#include <uint256.h>
#include <util/transaction_identifier.h>
#include <secp256k1.h>
extern "C" {
#include "api.h"
}
static std::vector<unsigned char> readf(const char*p){
    FILE*f=fopen(p,"rb"); fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    std::vector<unsigned char> v(n>0?n:0); if(n>0 && fread(v.data(),1,n,f)!=(size_t)n){} fclose(f); return v;
}
static std::vector<unsigned char> hexb(const std::string&h){
    std::vector<unsigned char> v; for(size_t i=0;i+1<h.size();i+=2) v.push_back((unsigned char)strtol(h.substr(i,2).c_str(),0,16)); return v;
}
static uint256 parse_txid(const std::string&h){
    auto b=hexb(h); std::reverse(b.begin(),b.end()); uint256 r; memcpy(r.begin(),b.data(),32); return r;
}
int main(int argc,char**argv){
    if(argc<6){fprintf(stderr,"args: txid vout amount_sat dest_spk_hex send_sat [bad]\n");return 2;}
    std::string txid=argv[1]; uint32_t vout=(uint32_t)atoi(argv[2]); int64_t amount=atoll(argv[3]);
    std::vector<unsigned char> dest=hexb(argv[4]); int64_t send=atoll(argv[5]);
    std::string mode=(argc>6?argv[6]:""); bool bad=(mode=="bad"); bool badec=(mode=="badec");
    auto esk=readf("/tmp/pqreg_keys/ecdsa_sk");
    auto epk=readf("/tmp/pqreg_keys/ecdsa_pk");
    auto msk=readf("/tmp/pqreg_keys/mldsa_sk");
    auto mpk=readf("/tmp/pqreg_keys/mldsa_pk");
    auto program=readf("/tmp/pqreg_keys/program");
    CMutableTransaction mtx; mtx.nVersion=2;
    CTxIn in; in.prevout=COutPoint(Txid::FromUint256(parse_txid(txid)),vout); in.nSequence=0xffffffff;
    mtx.vin.push_back(in);
    CTxOut out; out.nValue=send; out.scriptPubKey=CScript(dest.begin(),dest.end());
    mtx.vout.push_back(out);
    CScript scriptCode; scriptCode << OP_2; scriptCode << std::vector<unsigned char>(program.begin(),program.end());
    const CTransaction txc(mtx);
    uint256 sighash=SignatureHash(scriptCode,txc,0,SIGHASH_ALL,(CAmount)amount,SigVersion::WITNESS_V0,nullptr);
    secp256k1_context*ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_signature sig;
    if(!secp256k1_ecdsa_sign(ctx,&sig,sighash.begin(),esk.data(),nullptr,nullptr)){fprintf(stderr,"ecdsa fail\n");return 3;}
    unsigned char der[80]; size_t derlen=80;
    secp256k1_ecdsa_signature_serialize_der(ctx,der,&derlen,&sig);
    std::vector<unsigned char> ecdsa_sig(der,der+derlen); ecdsa_sig.push_back(0x01); if(badec) ecdsa_sig[5]^=0xff;
    static const unsigned char CTX[]="BitcoBoost-bb1z-v2";
    std::vector<unsigned char> mldsa_sig(PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES); size_t mslen=0;
    if(PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(mldsa_sig.data(),&mslen,sighash.begin(),32,CTX,sizeof(CTX)-1,msk.data())!=0){fprintf(stderr,"mldsa fail\n");return 4;}
    mldsa_sig.resize(mslen);
    if(bad) mldsa_sig[10]^=0xff;
    mtx.vin[0].scriptWitness.stack={ecdsa_sig,epk,mldsa_sig,mpk};
    DataStream ss; ss << TX_WITH_WITNESS(CTransaction(mtx));
    const unsigned char*p=(const unsigned char*)ss.data();
    for(size_t i=0;i<ss.size();i++) printf("%02x",p[i]);
    printf("\n");
    fprintf(stderr,"sighash=%s ecdsa_sig=%zuB mldsa_sig=%zuB\n",sighash.GetHex().c_str(),ecdsa_sig.size(),mldsa_sig.size());
    return 0;
}
