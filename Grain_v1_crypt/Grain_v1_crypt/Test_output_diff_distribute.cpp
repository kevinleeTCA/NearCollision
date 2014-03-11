
#include "stdafx.h"
#include "head.h"
//kevin edit, 代码存在内存泄露的问题
/*参数：
L:输入差分的最大汉明重量
KSLen:输出密钥流的截断长度(byte)
sam_N:随机选择汉明重量为L的输入差分的个数
test_Num:每一个差分对应的测试样本的数量
*/
//统计前向密钥流差分的BW-KSD Characteristic
void inputOutputDiff(u32 L,u32 sam_N){
	srand((unsigned)time(NULL));
	rc4_setup();
	u32 average_Diff_Num=0;
	double average_Diff_prop=0.0;
	double average_KW_KSD_CH=0.0;
	map<string,u32> counter;
	for(int D=1;D<=sam_N;D++){

		//随机选取160bit 状态的差分位置 NFSR从0~79，LFSR从80~159
		u32* pos=new u32[L]();
		for(int j=0;j<L;j++){
			//pos[j]=rc4() % 160;
			pos[j]=(rc4() % 80)+80;			//只给LFSR中引入差分
		}
		//初始化 输入差分为全0
		u8 diff_state[LEN];
		for(int j=0;j<LEN;j++){
			diff_state[j]=0;
		}
		for(int j=0;j<L;j++){
				u32 p=posIdx(pos[j]);
				u32 r=rotateIdx(pos[j]);
				diff_state[p]=diff_state[p]^(1<<r);
		}
		
		cout<<"\n-------------State Differential-"<<D<<":"<<ends;
		for(int j=0;j<20;j++){
				printf("%x ",diff_state[j]);
		}
		cout<<"-----------"<<endl;
		
		//随机选取M个状态，计算在差分下的另外M个状态，分别运行Grain 并输出长度为l的密钥流，统计其差分的分布特征
		//cout<<"\nOutput Differential:"<<endl;
		//计算BW-KSD characteristic
		u8 And_logic[KSLen];   //用来确定前向差分中全1的位置
		u8 Or_logic[KSLen];		//用来确定前向差分中全0的位置
		//初始化 and 和 or logic
		for(int i=0;i<KSLen;i++){
			And_logic[i]=255;
			Or_logic[i]=0;
		}
		for(int i=0;i<T_NUM;i++){
			/*if(i % 20000==0)
				cout<<"proceed "<<setprecision(3)<<(double)i*100/T_NUM<<"%..."<<endl;*/
			//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
			u8 rnd_state_1[LEN];
			for(int j=0;j<LEN;j++){
				rnd_state_1[j]=rc4();
			}
			
			//根据差分位置，得到另一个状态rud_state_2
			u8 rnd_state_2[LEN];
			for(int j=0;j<LEN;j++){
				rnd_state_2[j]=rnd_state_1[j]^diff_state[j];
			}
			//分别代入Grain中
			ECRYPT_ctx ctx_1;
			ctx_1.keysize=80;
			ctx_1.ivsize=64;
			u8 keyStream_1[KSLen];

			ECRYPT_ctx ctx_2;
			ctx_2.keysize=80;
			ctx_2.ivsize=64;
			u8 keyStream_2[KSLen];
			//将状态代入grain中,获得对应的长度为KSLen的密钥流，并输出其差分
			grain_state_load(&ctx_1,rnd_state_1);
			grain_state_load(&ctx_2,rnd_state_2);
			/*cout<<"输出前正向输入状态1："<<endl;
			for(int j=10;j<20;j++){
				printf("%x ",rnd_state_1[j]);
			}
			cout<<endl;
			*/
			ECRYPT_keystream_bytes(&ctx_1,keyStream_1,KSLen);
			ECRYPT_keystream_bytes(&ctx_2,keyStream_2,KSLen);
			//ECRYPT_keystream_backward_bytes(&ctx_1,keyStream_1,KSLen);
			//ECRYPT_keystream_backward_bytes(&ctx_2,keyStream_2,KSLen);
			//计算输出差分
			u8 Diff_KS[KSLen];
			for(int j=0;j<KSLen;j++){
				Diff_KS[j]=keyStream_1[j]^keyStream_2[j];
			}
			//计算BW-KSD characteristic
			for(int j=0;j<KSLen;j++){
				And_logic[j]&=Diff_KS[j];
				Or_logic[j]|=Diff_KS[j];
			}
			//统计各个差分出现的频率
			//string str=char2HexString(Diff_KS,KSLen);
			//map<string,u32>::iterator it=counter.find(str);
			//if(it!=counter.end()){//已存在这个差分
			//	it->second+=1;
			//}else
			//	counter.insert(make_pair(str,1));
			////结构体ctx_1和ctx_2的内存释放
			//if(ctx_1){
			//	delete [] ctx_1->LFSR,ctx_1->NFSR;
			//	//delete ctx_1->p_key;
			//}
			//ctx_1=NULL;
			//if(ctx_2){
			//	delete [] ctx_2->LFSR,ctx_2->NFSR;
			//	//delete ctx_2->p_key;
			//}
			//ctx_1=NULL;
		}
		//输出当前输入差分，对应输出差分的分布
	/*	map<string,u32>::iterator beg=counter.begin();
		map<string,u32>::iterator end=counter.end();
		for(;beg!=end;beg++){
			cout<<beg->first<<"  "<<setprecision(3)<<(float)beg->second*100/T_NUM<<"%"<<endl;
		}*/
		//计算当前输入差分对应的BW-KSD的characteristic  And逻辑确定全1的位置  Or逻辑确定全0的位置  剩下的就是不确定的位置
		string KSD_character="";
		int KW_KSD_CH=0;
		for(int i=0;i<KSLen;i++){
			u8 t_and=And_logic[i];
			u8 t_or=Or_logic[i];
			for(int j=0;j<8;j++){
				if((t_and>>j)&0x01){
					average_KW_KSD_CH++;
					KW_KSD_CH++;
					KSD_character.append("1");
				}
				else if(!( (t_or>>j)&0x01 )){
					average_KW_KSD_CH++;
					KW_KSD_CH++;
					KSD_character.append("0");
				}
				else
					KSD_character.append("*");
			}
		}
		if(KW_KSD_CH>15){
			cout<<"前向输出差分的BW-KSD characteristic为:"<<KSD_character<<endl;
			cout<<" 固定位置的个数："<<KW_KSD_CH<<endl<<endl;
		}
		
		//统计输出差分，占所有差分的比例
		// cout<<"Diff prop:"<<setprecision(3)<<(double)counter.size()*100/pow(2.0,(double)KSLen*8)<<"%"<<endl;
		//average_Diff_Num+=counter.size();
		//memory release
		//counter.clear();
		delete [] pos;
	}
	
	//average_Diff_prop=(double)average_Diff_Num*100/sam_N/pow(2.0,(double)KSLen*8);
	//average_Diff_prop=(double)average_Diff_Num/sam_N;
	average_KW_KSD_CH=(double)average_KW_KSD_CH/sam_N;
		//average_Diff_prop=(double)average_Diff_Num*100/sam_N/T_NUM;
	//cout<<"The average differential Num (d,l):("<<L<<","<<KSLen<<") is "<<setprecision(3)<<average_Diff_prop<<endl;
	cout<<"The average KW_KSD Characteristic reduction factor:("<<L<<","<<KSLen<<") is "<<setprecision(3)<<average_KW_KSD_CH<<endl;

}

//计算当输入差分的韩明重量d一定的时候，平均输出差分的个数
void cal_average_OutputDiff(u32 L,u32 sam_N){
	srand((unsigned)time(NULL));
	u32 average_Diff_Num=0;
	double average_Diff_prop=0.0;
	double average_KW_KSD_CH=0.0;
	map<string,u32> counter;
	for(int D=1;D<=sam_N;D++){

		//随机选取160bit 状态的差分位置 NFSR从0~79，LFSR从80~159
		u32* pos=new u32[L]();
		for(int j=0;j<L;j++){
			pos[j]=rc4() % 160;
		}
		//初始化 输入差分为全0
		u8 diff_state[LEN];
		for(int j=0;j<LEN;j++){
			diff_state[j]=0;
		}
		for(int j=0;j<L;j++){
				u32 p=posIdx(pos[j]);
				u32 r=rotateIdx(pos[j]);
				diff_state[p]=diff_state[p]^(1<<r);
		}
		
		cout<<"\n-------------State Differential-"<<D<<":"<<ends;
		for(int j=0;j<20;j++){
			printf("%x ",diff_state[j]);
		}
		cout<<"-----------"<<endl;
		
		//随机选取M个状态，计算在差分下的另外M个状态，分别运行Grain 并输出长度为l的密钥流，统计其差分的分布特征
		//cout<<"\nOutput Differential:"<<endl;
		for(int i=0;i<T_NUM;i++){
			if(i % 20000==0)
				cout<<"proceed "<<setprecision(3)<<(double)i*100/T_NUM<<"%..."<<endl;
			//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
			u8 rnd_state_1[LEN];
			for(int j=0;j<LEN;j++){
				rnd_state_1[j]=rc4();
			}
			
			//根据差分位置，得到另一个状态rud_state_2
			u8 rnd_state_2[LEN];
			for(int j=0;j<LEN;j++){
				rnd_state_2[j]=rnd_state_1[j]^diff_state[j];
			}
			//分别代入Grain中
			ECRYPT_ctx* ctx_1=new ECRYPT_ctx;
			ctx_1->keysize=80;
			ctx_1->ivsize=64;
			u8 keyStream_1[KSLen];

			ECRYPT_ctx* ctx_2=new ECRYPT_ctx;
			ctx_2->keysize=80;
			ctx_2->ivsize=64;
			u8 keyStream_2[KSLen];
			//将状态代入grain中,获得对应的长度为KSLen的密钥流，并输出其差分
			grain_state_load(ctx_1,rnd_state_1);
			grain_state_load(ctx_2,rnd_state_2);
			/*cout<<"输出前正向输入状态1："<<endl;
			for(int j=10;j<20;j++){
				printf("%x ",rnd_state_1[j]);
			}
			cout<<endl;
			*/
			ECRYPT_keystream_bytes(ctx_1,keyStream_1,KSLen);
			ECRYPT_keystream_bytes(ctx_2,keyStream_2,KSLen);
			//ECRYPT_keystream_backward_bytes(ctx_1,keyStream_1,KSLen);
			//ECRYPT_keystream_backward_bytes(ctx_2,keyStream_2,KSLen);
			//计算输出差分
			u8 Diff_KS[KSLen];
			for(int j=0;j<KSLen;j++){
				Diff_KS[j]=keyStream_1[j]^keyStream_2[j];
			}
			//统计各个差分出现的频率
			string str=char2HexString(Diff_KS,KSLen);
			map<string,u32>::iterator it=counter.find(str);
			if(it!=counter.end()){//已存在这个差分
				it->second+=1;
			}else
				counter.insert(make_pair(str,1));
			//结构体ctx_1和ctx_2的内存释放
			if(ctx_1){
				delete [] ctx_1->LFSR,ctx_1->NFSR;
				//delete ctx_1->p_key;
			}
			ctx_1=NULL;
			if(ctx_2){
				delete [] ctx_2->LFSR,ctx_2->NFSR;
				//delete ctx_2->p_key;
			}
			ctx_1=NULL;
		}
		//统计输出差分，占所有差分的比例
		// cout<<"Diff prop:"<<setprecision(3)<<(double)counter.size()*100/pow(2.0,(double)KSLen*8)<<"%"<<endl;
		average_Diff_Num+=counter.size();
		//memory release
		counter.clear();
		delete [] pos;
	}
	average_Diff_prop=(double)average_Diff_Num/sam_N;
	cout<<"The average differential Num (d,l):("<<L<<","<<KSLen<<") is "<<setprecision(8)<<average_Diff_prop<<endl;

}


//针对某个特定差分，输出其前向backward(后向forward)输出差分分布,并计算BW-KSD characteristic

void inputOutputDiffForSpecificDiff(u32 L,u32 *pos){
	srand((unsigned)time(NULL));
	u32 average_Diff_Num=0;
	double average_Diff_prop=0.0;
	map<string,u32> counter;
	//初始化 输入差分为全0
	u8 diff_state[LEN];
	for(int j=0;j<LEN;j++){
		diff_state[j]=0;
	}
	for(int j=0;j<L;j++){
		u32 p=posIdx(pos[j]);
		u32 r=rotateIdx(pos[j]);
		diff_state[p]=diff_state[p]^(1<<r);
	}
	cout<<"\n-------------State Differential:"<<ends;
	for(int j=0;j<20;j++){
		printf("%x ",diff_state[j]);
	}
	cout<<"-----------"<<endl;
	//随机选取M个状态，计算在差分下的另外M个状态，分别运行Grain 并输出长度为l的密钥流，统计其差分的分布特征
	//cout<<"\nOutput Differential:"<<endl;
	//计算BW-KSD characteristic
	u8 And_logic[KSLen];   //用来确定前向差分中全1的位置
	u8 Or_logic[KSLen];		//用来确定前向差分中全0的位置
	//初始化 and 和 or logic
	for(int i=0;i<KSLen;i++){
		And_logic[i]=255;
		Or_logic[i]=0;
	}
	for(int i=0;i<T_NUM;i++){
		
		//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
		u8 rnd_state_1[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_1[j]=rc4();
		}
			
		//根据差分位置，得到另一个状态rud_state_2
		u8 rnd_state_2[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_2[j]=rnd_state_1[j]^diff_state[j];
		}
		//分别代入Grain中
		ECRYPT_ctx ctx_1;
		ctx_1.keysize=80;
		ctx_1.ivsize=64;
		u8 keyStream_1[KSLen];

		ECRYPT_ctx ctx_2;
		ctx_2.keysize=80;
		ctx_2.ivsize=64;
		u8 keyStream_2[KSLen];
		//将状态代入grain中,获得对应的长度为KSLen的密钥流，并输出其差分
		grain_state_load(&ctx_1,rnd_state_1);
		grain_state_load(&ctx_2,rnd_state_2);
		ECRYPT_keystream_bytes(&ctx_1,keyStream_1,KSLen);
		ECRYPT_keystream_bytes(&ctx_2,keyStream_2,KSLen);
		//ECRYPT_keystream_backward_bytes(&ctx_1,keyStream_1,KSLen);
		//ECRYPT_keystream_backward_bytes(&ctx_2,keyStream_2,KSLen);
		//计算输出差分
		u8 Diff_KS[KSLen];
		for(int j=0;j<KSLen;j++){
			Diff_KS[j]=keyStream_1[j]^keyStream_2[j];
		}
		//计算BW-KSD characteristic
		for(int j=0;j<KSLen;j++){
			And_logic[j]&=Diff_KS[j];
			Or_logic[j]|=Diff_KS[j];
		}
		//统计各个差分出现的频率
		string str=char2HexString(Diff_KS,KSLen);
		map<string,u32>::iterator it=counter.find(str);
		if(it!=counter.end()){//已存在这个差分
			it->second+=1;
		}else
			counter.insert(make_pair(str,1));
		////结构体ctx_1和ctx_2的内存释放
		//if(ctx_1){
		//	delete [] ctx_1->LFSR,ctx_1->NFSR;
		//	//delete ctx_1->p_key;
		//}
		//ctx_1=NULL;
		//if(ctx_2){
		//	delete [] ctx_2->LFSR,ctx_2->NFSR;
		//	//delete ctx_2->p_key;
		//}
		//ctx_1=NULL;
	}
	//输出当前输入差分，对应输出差分的分布
	map<string,u32>::iterator beg=counter.begin();
	map<string,u32>::iterator end=counter.end();
	for(;beg!=end;beg++){
		cout<<beg->first<<"  "<<setprecision(3)<<(float)beg->second*100/T_NUM<<"%"<<endl;
	}
	//计算当前输入差分对应的BW-KSD的characteristic  And逻辑确定全1的位置  Or逻辑确定全0的位置  剩下的就是不确定的位置
	string KSD_character="";
	for(int i=0;i<KSLen;i++){
		u8 t_and=And_logic[i];
		u8 t_or=Or_logic[i];
		for(int j=0;j<8;j++){
			if((t_and>>j)&0x01)
				KSD_character.append("1");
			else if(!( (t_or>>j)&0x01 ))
				KSD_character.append("0");
			else
				KSD_character.append("*");
		}
	}
	cout<<"前向输出差分的BW-KSD characteristic为:"<<KSD_character<<endl;
}


