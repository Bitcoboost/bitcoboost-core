#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <secp256k1.h>
extern "C" {
#include "api.h"
#include "fips202.h"
}
static void wr(const char*p,const unsigned char*d,size_t n){FILE*f=fopen(p,"wb");fwrite(d,1,n,f);fclose(f);}
static void ph(const char*lab,const unsigned char*d,size_t n){printf("%s ",lab);for(size_t i=0;i<n;i++)printf("%02x",d[i]);printf("\n");}
int main(){
  unsigned char sk[32];
  FILE*u=fopen("/dev/urandom","rb"); if(fread(sk,1,32,u)!=32){return 9;}
  secp256k1_context*ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
  while(!secp256k1_ec_seckey_verify(ctx,sk)){ if(fread(sk,1,32,u)!=32) return 9; }
  fclose(u);
  secp256k1_pubkey pub; if(!secp256k1_ec_pubkey_create(ctx,&pub,sk)) return 8;
  unsigned char epk[33]; size_t epl=33;
  secp256k1_ec_pubkey_serialize(ctx,epk,&epl,&pub,SECP256K1_EC_COMPRESSED);
  const int MPKB=PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
  const int MSKB=PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
  unsigned char*mpk=(unsigned char*)malloc(MPKB);
  unsigned char*msk=(unsigned char*)malloc(MSKB);
  if(PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(mpk,msk)!=0) return 7;
  size_t kl=33+MPKB; unsigned char*km=(unsigned char*)malloc(kl);
  memcpy(km,epk,33); memcpy(km+33,mpk,MPKB);
  unsigned char program[32]; shake256(program,32,km,kl);
  system("mkdir -p /tmp/pqreg_keys");
  wr("/tmp/pqreg_keys/ecdsa_sk",sk,32);
  wr("/tmp/pqreg_keys/ecdsa_pk",epk,33);
  wr("/tmp/pqreg_keys/mldsa_sk",msk,MSKB);
  wr("/tmp/pqreg_keys/mldsa_pk",mpk,MPKB);
  wr("/tmp/pqreg_keys/program",program,32);
  ph("PROGRAM",program,32);
  ph("ECDSAPUB",epk,33);
  printf("SCRIPTPUBKEY 5220"); for(int i=0;i<32;i++)printf("%02x",program[i]); printf("\n");
  printf("MPKB %d MSKB %d\n",MPKB,MSKB);
  return 0;
}
