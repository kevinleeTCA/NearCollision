/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of reduced version of Grain v1
	Used to verify the near collision attack
*/

#include "stdafx.h"
#include "head.h"
//state load function
void grain_state_load_reduce(ECRYPT_ctx_reduce* ctx_reduce, u8* state){
	for(int i=0;i<4;i++){
		for (int j=0;j<8;++j) {
			ctx_reduce->NFSR[i*8+j]=((state[i]>>j)&1);  
		}
	}
	for(int i=4;i<8;i++){
		for (int j=0;j<8;++j) {
			ctx_reduce->LFSR[(i-4)*8+j]=((state[i]>>j)&1);  
		}
	}
}
//state read function
void grain_state_read_reduce(ECRYPT_ctx_reduce* ctx_reduce, u8* state){
	for(int i=0;i<4;i++){
		state[i]=0;
		for (int j=0;j<8;++j) {
			state[i]+=(ctx_reduce->NFSR[i*8+j])<<j;
			//ctx_reduce->NFSR[i*8+j]=((state[i]>>j)&1);  
		}
	}
	for(int i=4;i<8;i++){
		state[i]=0;
		for (int j=0;j<8;++j) {
			state[i]+=(ctx_reduce->LFSR[(i-4)*8+j])<<j;
			//ctx_reduce->LFSR[(i-4)*8+j]=((state[i]>>j)&1);  
		}
	}
}

//backward function
u8 grain_keystream_backward_reduce(ECRYPT_ctx_reduce* ctx_reduce){
	u8 L0,N0,outbit,L31,N31;
	//先保存当前的LFSR[79]和NFSR[79]
	L31=ctx_reduce->LFSR[(ctx_reduce->keysize)-1];
	N31=ctx_reduce->NFSR[(ctx_reduce->keysize)-1];
	//然后再循环移位寄存器 到上一个状态
	for (int i=(ctx_reduce->keysize)-1;i>0;--i) {
		ctx_reduce->NFSR[i]=ctx_reduce->NFSR[i-1];
		ctx_reduce->LFSR[i]=ctx_reduce->LFSR[i-1];
	}
	//利用当前LFSR[31]和NFSR[31]计算 上一个时刻的LFSR[0]和NFSR[0]
	L0=L_R(2)^L_R(7)^L_R(16)^L31;
	//N0=N31^L0^N(18)^N(66)^NFTable[(N(17)<<9) | (N(20)<<8) | (N(28)<<7) | (N(35)<<6) | (N(43)<<5) | (N(47)<<4) | (N(52)<<3) | (N(59)<<2) | (N(65)<<1) | N(71)];
	N0=N31^L0^N_R(7)^N_R(9)^N_R(17)^N_R(24)^N_R(7)&N_R(9)^N_R(17)&N_R(24)
		^N_R(7)&N_R(9)&N_R(17)^N_R(9)&N_R(17)&N_R(24)^N_R(7)&N_R(9)&N_R(17)&N_R(24);
	//更新LFSR[0]和NFSR[0]
	ctx_reduce->NFSR[0]=N0;
	ctx_reduce->LFSR[0]=L0;
	//计算上一个时刻的输出bit
	outbit = N_R(31)^N_R(28)^N_R(22)^N_R(11)^boolTable[(X4_R<<4) | (X3_R<<3) | (X2_R<<2) | (X1_R<<1) | X0_R];
	return outbit;
}

void ECRYPT_init_reduce(void){}

//keystream generate function
u8 grain_keystream_reduce(ECRYPT_ctx_reduce* ctx_reduce) {
	u8 i,NBit,LBit,outbit;
	/* Calculate feedback and output bits */
	outbit = N_R(31)^N_R(28)^N_R(22)^N_R(11)^boolTable[(X4_R<<4) | (X3_R<<3) | (X2_R<<2) | (X1_R<<1) | X0_R];
	//NBit=L(80)^N(18)^N(66)^N(80)^NFTable[(N(17)<<9) | (N(20)<<8) | (N(28)<<7) | (N(35)<<6) | (N(43)<<5) | (N(47)<<4) | (N(52)<<3) | (N(59)<<2) | (N(65)<<1) | N(71)];
	NBit=L_R(32)^N_R(7)^N_R(9)^N_R(17)^N_R(24)^N_R(32)^N_R(7)&N_R(9)^N_R(17)&N_R(24)
		^N_R(7)&N_R(9)&N_R(17)^N_R(9)&N_R(17)&N_R(24)^N_R(7)&N_R(9)&N_R(17)&N_R(24);
	LBit=L_R(2)^L_R(7)^L_R(16)^L_R(32);
	/* Update registers */
	for (i=1;i<(ctx_reduce->keysize);++i) {
		ctx_reduce->NFSR[i-1]=ctx_reduce->NFSR[i];
		ctx_reduce->LFSR[i-1]=ctx_reduce->LFSR[i];
	}
	ctx_reduce->NFSR[(ctx_reduce->keysize)-1]=NBit;
	ctx_reduce->LFSR[(ctx_reduce->keysize)-1]=LBit;
	return outbit;
}


void ECRYPT_keysetup_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  const u8* key, 
  u32 keysize,                /* Key size in bits. */ 
  u32 ivsize)				  /* IV size in bits. */ 
{
	ctx_reduce->p_key=key;
	ctx_reduce->keysize=keysize;
	ctx_reduce->ivsize=ivsize;
}


void ECRYPT_ivsetup_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  const u8* iv)
{
	u32 i,j;
	u8 outbit;
	/* load registers */
	for (i=0;i<(ctx_reduce->ivsize)/8;++i) {
		for (j=0;j<8;++j) {
			ctx_reduce->NFSR[i*8+j]=((ctx_reduce->p_key[i]>>j)&1);  
			ctx_reduce->LFSR[i*8+j]=((iv[i]>>j)&1);
		}
	}
	for (i=(ctx_reduce->ivsize)/8;i<(ctx_reduce->keysize)/8;++i) {
		for (j=0;j<8;++j) {
			ctx_reduce->NFSR[i*8+j]=((ctx_reduce->p_key[i]>>j)&1);
			ctx_reduce->LFSR[i*8+j]=1;
		}
	}
	/* do initial clockings */
	for (i=0;i<INITCLOCKS_REDUCED;++i) {
		outbit=grain_keystream_reduce(ctx_reduce);
		ctx_reduce->LFSR[31]^=outbit;
		ctx_reduce->NFSR[31]^=outbit;             
	}
}


void ECRYPT_keystream_bytes_reduce(
  ECRYPT_ctx_reduce* ctx_reduce,
  u8* keystream,
  u32 length)
{
	u32 i,j;
	for (i = 0; i < length; ++i) {
		keystream[i]=0;
		for (j = 0; j < 8; ++j) {
			keystream[i]|=(grain_keystream_reduce(ctx_reduce)<<j);
		}
	}
}

void ECRYPT_keystream_backward_bytes_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  u8* keystream, 
  u32 msglen)
{
	u32 i,j;
	for (i = 0; i < msglen; ++i) {
		keystream[i]=0;
		for (j = 0; j < 8; ++j) {
			keystream[i]|=(grain_keystream_backward_reduce(ctx_reduce)<<j);
			//grain_keystream_backward(ctx);
		}

	}
	/*//正向输出
	for (i = 0; i < msglen; ++i) {
		keystream[i]=0;
		for (j = 0; j < 8; ++j) {
			//keystream[i]|=(grain_keystream_backward(ctx)<<j);
			keystream[i]|=(grain_keystream(ctx)<<j);
		}

	}
	*/	
}



void ECRYPT_encrypt_bytes_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen)
{
	u32 i,j;
	u8 k;
	for (i = 0; i < msglen; ++i) {
		k=0;
		for (j = 0; j < 8; ++j) {	
			k|=(grain_keystream_reduce(ctx_reduce)<<j);
		}
		ciphertext[i]=plaintext[i]^k;
	}
}

void ECRYPT_decrypt_bytes_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen)
{
	u32 i,j;
	u8 k=0;
	for (i = 0; i < msglen; ++i) {
		k=0;
		for (j = 0; j < 8; ++j) {
			k|=(grain_keystream_reduce(ctx_reduce)<<j);
		}
		plaintext[i]=ciphertext[i]^k;
	}
}
