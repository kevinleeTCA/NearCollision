/*
	Created by Kevin Lee 2012/12/18
	This is an test file for NCA 3.0
*/

#include "stdafx.h"
#include "head.h"

void analyze_collected_data(u32 d){
	rc4_setup();
	//random select a key and IV and run the initial phase
	ECRYPT_ctx_reduce* ctx_reduce=new ECRYPT_ctx_reduce;
	u8* key_R=new u8[4]();
	u8* IV_R=new u8[3]();
	for(int i=0;i<4;i++){
		key_R[i]= rc4();
	}
	for(int i=0;i<3;i++){
		IV_R[i]= rc4();
	}
	ECRYPT_keysetup_reduce(ctx_reduce,key_R,32,24);
	ECRYPT_ivsetup_reduce(ctx_reduce,IV_R);
	unsigned long long set_size=ceil(pow((double)2,DATA_SET));
	cout<<"Data set size:2^{"<<DATA_SET<<"}"<<endl;
	Online_Data_Reduce *data_A=new Online_Data_Reduce[set_size];
	Online_Data_Reduce *data_B=new Online_Data_Reduce[set_size];
	collect_sets_v3_with_prefix(ctx_reduce,data_A,data_B,1,set_size);
	//分析已收集的数据
	string part="Analyze_data";
	string curr_DIR=DIR_REDUCE_TEST_V3+part+"_KSD_"+int_2_string(MAX_KSD)+"_HM_"
		+int_2_string(MAX_KSD_HM)+"_(l,d)_("+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")"+WITH_PREFIX+"\\";
	//建立目录，如果不存在则自动建立目录
	char *tag;
	for(tag=(char*)curr_DIR.c_str();*tag;tag++){
		if(*tag=='\\'){
			char buf[1024],path[1024];
			strcpy(buf,curr_DIR.c_str());
			buf[strlen(curr_DIR.c_str())-strlen(tag)+1]=NULL;
			strcpy(path,buf);
			if(access(path,6)==-1)
				mkdir(path);
		}
	}
	for(int i=0;i<set_size;i++){
		if((i+1) % 20000 ==0){
			cout<<"Analyze proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
		}
		for(int j=0;j<set_size;j++){
			//计算当前输出差分
			u8 curr_KS_Diff[KSLen_Reduced];
			for(int k=0;k<KSLen_Reduced;k++)
				curr_KS_Diff[k]=((data_A[i]).KS[k])^((data_B[j]).KS[k]);
			//计算当前对应的状态差分
			u8 curr_state_Diff[STATE_BYTE];
			for(int k=0;k<STATE_BYTE;k++)
					curr_state_Diff[k]=((data_A[i]).state[k])^((data_B[j]).state[k]);
			curr_state_Diff[1]&=0x03;
			curr_state_Diff[2]&=0xe0;
			if(Hamming_weight_of_state(curr_KS_Diff,KSLen_Reduced)<=MAX_KSD_HM
				&& Hamming_weight_of_state(curr_state_Diff,STATE_BYTE)<=d){
			/*if(Hamming_weight_of_state(curr_KS_Diff,KSLen_Reduced)<=MAX_KSD_HM){*/
				//把满足这样条件的KSD和ISD都记录下来
				string KSD=char2HexString(curr_KS_Diff,KSLen_Reduced);
				string ISD=char2HexString(curr_state_Diff,STATE_BYTE);
				string fileName=curr_DIR+KSD+".txt";
				ofstream outfile;
				outfile.open(fileName.c_str(),ofstream::app);
				outfile<<fixed<<showpoint;
				if(outfile){
					outfile<<ISD<<"\n";
				}
				outfile.close();
			}
		}
	}
	cout<<"Analyze complete."<<endl;
}