/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of reduced version of Grain v1
	Sampling resistance of reduced Grain v1  (key:32-bit  IV:24-bit)
*/

#include "stdafx.h"
#include "head.h"

/*
	需要测试和maple代码中Grain reduce实现的一致性
	NFSR:32 bits
	LFSR:32 bits
	Given:	LFSR[3],LFSR[4],LFSR[5],LFSR[6],LFSR[7],LFSR[8],LFSR[9],LFSR[10]
			LFSR[11],LFSR[12],LFSR[13],LFSR[14],LFSR[15],LFSR[16],LFSR[17],LFSR[18],
			LFSR[19],LFSR[20],LFSR[21],LFSR[22],LFSR[23],LFSR[24],LFSR[25],LFSR[26],
			LFSR[27],LFSR[28],LFSR[29],LFSR[30],LFSR[31],LFSR[0],LFSR[1],LFSR[2],
			(all 32 LFSR bits)
			NFSR[1],NFSR[2],NFSR[3],NFSR[4],NFSR[5],NFSR[6],NFSR[7],NFSR[8],
			NFSR[9],NFSR[21],NFSR[22],NFSR[23],NFSR[24],NFSR[25],NFSR[26],NFSR[27],
			NFSR[28],NFSR[29],NFSR[30],NFSR[31],NFSR[0],
			(21 NFSR bits)
	确定:	NFSR[10],NFSR[11],NFSR[12],NFSR[13],NFSR[14],NFSR[15],NFSR[16],NFSR[17],
			NFSR[18],NFSR[19],NFSR[20]
			(11 NFSR bits)
	pattern: 11个0 （输出密钥流）
*/
void grain_reduce_sampling_resistance(ECRYPT_ctx_reduce* ctx_reduce,
	u32 *L,u32 *N){
	//利用已知的结果计算未知的结果。
	N[10]=N[1]^N[4]^N[21]^L[11]^N[24]^L[3]&L[25]^L[21]&L[25]^L[25]&N[24]^L[3]&L[11]&L[21]
		^L[3]&L[21]&L[25]^L[3]&L[21]&N[24]^L[11]&L[21]&N[24]^L[21]&L[25]&N[24];
	N[11]=N[2]^N[5]^N[22]^L[12]^N[25]^L[4]&L[26]^L[22]&L[26]^L[26]&N[25]^L[4]&L[12]&L[22]
		^L[4]&L[22]&L[26]^L[4]&L[22]&N[25]^L[12]&L[22]&N[25]^L[22]&L[26]&N[25];
	N[12]=N[3]^N[6]^N[23]^L[13]^N[26]^L[5]&L[27]^L[23]&L[27]^L[27]&N[26]^L[5]&L[13]&L[23]
		^L[5]&L[23]&L[27]^L[5]&L[23]&N[26]^L[13]&L[23]&N[26]^L[23]&L[27]&N[26];
	N[13]=N[4]^N[7]^N[24]^L[14]^N[27]^L[6]&L[28]^L[24]&L[28]^L[28]&N[27]^L[6]&L[14]&L[24]
		^L[6]&L[24]&L[28]^L[6]&L[24]&N[27]^L[14]&L[24]&N[27]^L[24]&L[28]&N[27];
	N[14]=N[5]^N[8]^N[25]^L[15]^N[28]^L[7]&L[29]^L[25]&L[29]^L[29]&N[28]^L[7]&L[15]&L[25]
		^L[7]&L[25]&L[29]^L[7]&L[25]&N[28]^L[15]&L[25]&N[28]^L[25]&L[29]&N[28];
	N[15]=N[6]^N[9]^N[26]^L[16]^N[29]^L[8]&L[30]^L[26]&L[30]^L[30]&N[29]^L[8]&L[16]&L[26]
		^L[8]&L[26]&L[30]^L[8]&L[26]&N[29]^L[16]&L[26]&N[29]^L[26]&L[30]&N[29];
	N[16]=N[7]^N[10]^N[27]^L[17]^N[30]^L[9]&L[31]^L[27]&L[31]^L[31]&N[30]^L[9]&L[17]&L[27]
		^L[9]&L[27]&L[31]^L[9]&L[27]&N[30]^L[17]&L[27]&N[30]^L[27]&L[31]&N[30];
	u32 t_1=(L[0]^L[16]^L[25]^L[30]);
	N[17]=N[8]^N[11]^N[28]^L[18]^N[31]^L[10]&(t_1)^L[28]&(t_1)
		^(t_1)&N[31]^L[10]&L[18]&L[28]^L[10]&L[28]&(t_1)
		^L[10]&L[28]&N[31]^L[18]&L[28]&N[31]^L[28]&(t_1)&N[31];
	
	u32 t_2=(L[1]^L[17]^L[26]^L[31]);
	u32 t_3=L[0]^N[25]^N[23]^N[15]^N[8]^N[0]^N[25]&N[23]^N[15]&N[8]^N[25]&N[23]&N[15]^N[23]&N[15]&N[8]^N[25]&N[23]&N[15]&N[8];
	N[18]=N[9]^N[12]^N[18]^N[29]^L[19]^L[0]^N[25]^N[23]^N[15]^N[8]^N[0]^N[25]&N[23]^N[15]&N[8]^N[25]&N[23]&N[15]^N[23]&N[15]&N[8]
		^N[25]&N[23]&N[15]&N[8]^L[11]&(t_2)^L[29]&(t_2)^(t_2)&(t_3)
		^L[11]&L[19]&L[29]^L[11]&L[29]&(t_2)^L[11]&L[29]&(t_3)
		^L[19]&L[29]&(t_3)^L[29]&(t_2)&(t_3);

	u32 t_4=L[2]^L[18]^L[27]^L[0]^L[16]^L[25]^L[30];
	u32 t_5=L[1]^N[26]^N[24]^N[16]^N[9]^N[1]^N[26]&N[24]^N[16]&N[9]^N[26]&N[24]&N[16]^N[24]&N[16]&N[9]^N[26]&N[24]&N[16]&N[9];
	N[19]=N[10]^N[13]^N[19]^N[30]^L[20]^t_5
		^L[12]&(t_4)^L[30]&(t_4)^(t_4)&(t_5)
		^L[12]&L[20]&L[30]^L[12]&L[30]&(t_4)^L[12]&L[30]&(t_5)
		^L[20]&L[30]&(t_5)^L[30]&(t_4)&(t_5);

	u32 t_6=L[3]^L[19]^L[28]^L[1]^L[17]^L[26]^L[31];
	u32 t_7=L[2]^N[27]^N[25]^N[17]^N[10]^N[2]^N[27]&N[25]^N[17]&N[10]^N[27]&N[25]&N[17]^N[25]&N[17]&N[10]^N[27]&N[25]&N[17]&N[10];
	N[20]=N[11]^N[14]^N[20]^N[31]^L[21]^t_7^L[13]&(t_6)
		^L[31]&(t_6)^(t_6)&(t_7)
		^L[13]&L[21]&L[31]^L[13]&L[31]&(t_6)^L[13]&L[31]&(t_7)^L[21]&L[31]&(t_7)
		^L[31]&(t_6)&(t_7);
	//assemble the state
	for(int i=0;i<32;i++){
		ctx_reduce->LFSR[i]=L[i];
		ctx_reduce->NFSR[i]=N[i];
	}
	ctx_reduce->keysize=32;
	ctx_reduce->ivsize=24;
}

//给定53个内部状态之后，输出11个0之外的 比特流
void grain_reduce_sampling_resistance_genKSBytes(ECRYPT_ctx_reduce* ctx_reduce,
  u8* keystream,
  u32 length){
	//首先输出11个全0的pattern
	//for(int k=1;k<=11;k++)
		//grain_keystream_reduce(ctx_reduce);
	//然后输出的密钥流作为真正的密钥流
	ECRYPT_keystream_bytes_reduce(ctx_reduce,keystream,length);
}