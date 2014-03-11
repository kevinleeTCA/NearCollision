// Grain_v1_crypt.cpp : 定义控制台应用程序的入口点。
/*
	Created by Kevin Lee 2012/6/18
	This is an implemention of Grain v1
*/

#include "stdafx.h"
#include "head.h"

//string 2 byte array
void string2byte(u8* bArray,u32 bLen,string str){
	for(int i=0;i<bLen;i++){
		u8 high=str.at(i*2);
		u8 low=str.at(i*2+1);
		if(high-'a'>=0)
			high=high-'a'+10;
		else
			high=high-'0';
		if(low-'a'>=0)
			low=low-'a'+10;
		else
			low=low-'0';
		bArray[i]=(high<<4)+low;
	}
}



//kevin edit. for byte to string (hex)
string char2HexString(u8* bArray,u32 bLen){
	string res="";
	for(int i=0;i<bLen;i++){
		u8 high=bArray[i]>>4;
		u8 low=bArray[i]&(0x0f);
		if(high<10)
			res+='0'+high;
		else
			res+='a'+(high-10);
		if(low<10)
			res+='0'+low;
		else
			res+='a'+(low-10);
	}
	return res;
}

string int_2_string(int a){
	string out;
	stringstream ss;
	ss<<a;
	ss>>out;
	return out;
}
//kevin edit. for string to byte (hex)
//这个函数速度明显比char2HexString快得多
unsigned long long char_2_long(u8 *arr,u32 Len){
	unsigned long long res=0;
	for(int i=0;i<Len;i++){
		res+=((unsigned long long)arr[i])<<(i*8);
	}
	return res;
}

int comp(const void *a,const void *b){
	unsigned long long val_a=*(unsigned long long*)a;
	unsigned long long val_b=*(unsigned long long*)b;
	for(int i=3;i>=0;i--){
		unsigned int part_a=(val_a>>(i*16))&0xffff;
		unsigned int part_b=(val_b>>(i*16))&0xffff;
		if(part_a>part_b)
			return 1;
		else if(part_a<part_b)
			return -1;
		else
			continue;
	}
	return 0;
}

int comp_struct(const void *a,const void *b){
	Online_Data_Reduce* val_a=(Online_Data_Reduce*)a;
	Online_Data_Reduce* val_b=(Online_Data_Reduce*)b;
	u8 *KS_a=val_a->KS;
	u8 *KS_b=val_b->KS;
	for(int i=KSLen_Reduced-1;i>=0;i--){
		if(KS_a[i]>KS_b[i])
			return 1;
		else if(KS_a[i]<KS_b[i])
			return -1;
		else
			continue;
	}
	return 0;
}

string long_to_hexString(unsigned long long val,const u32 charLen){
	u8 *arr=new u8[charLen]();
	for(int i=0;i<charLen;i++){
		arr[i]=(val>>(i*8))&0xff;
	}
	string res=char2HexString(arr,charLen);
	delete [] arr;
	return res;
}


//用于NCA线上阶段攻击
bool state_comp(u8 *state,u32 state_Len,string str_state){
	for(int i=0;i<state_Len;i++){
		string res="";
		u8 high=(state[i]>>4)&0x0f;
		u8 low=(state[i])&0x0f;
		if(high<10){
			res+=high+'0';
		}else{
			res+=(high-10)+'a';
		}
		if(low<10){
			res+=low+'0';
		}else{
			res+=(low-10)+'a';
		}
		if(res.compare(str_state.substr(i*2,2)))
			return false;
	}
	return true;
}