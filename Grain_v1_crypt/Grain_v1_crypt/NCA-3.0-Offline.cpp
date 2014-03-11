/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of offline stage in NCA-3.0
	 
*/

#include "stdafx.h"
#include "head.h"

//穷举所有Hamming重量小于d的53比特的内部状态差分，然后在N大小的样本空间下，进行预计算，输出密钥流长度为l（最大支持64bit）。
/*
	
	d:输入状态差分的最大汉明重量
*/
void offLine_table_construct_v3(u32 d){
	//创建输出流
	//建立输出文件
	string part="Grain_(l,d)_(";
	string curr_DIR=DIR_REDUCE_V3+part+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")"+
		FILE_SUFFIX+WITH_PREFIX+"_KSD_"+int_2_string(MAX_KSD)+"_HM_"+int_2_string(MAX_KSD_HM)
		+"_N_"+int_2_string(STATE_NUM)+"\\";
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
	for(int i=1;i<=d;i++){
		//枚举所有输入差分的汉明重量为i的差分   
		u32 state_Len=STATE_REDUCE-SP;		//总的状态数 减去sampling resistance的大小
		cout<<"Grain reduce--开始处理输入差分汉明重量为:"<<i<<"的情况."<<endl;
		double time[4]={0};
		start_cal();
		combination_for_search_grain_reduce_v3(state_Len,i,curr_DIR);
		end_cal(time);
		cout<<"Grain reduce--输入差分汉明重量为:"<<i<<"的情况已经处理完毕."<<endl;
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
	}
}

//简单组合问题，打印从1~n个数中选取k个的所有组合,这个程序对于k和n比较小的时候速度快,非递归实现
//用于辅助输入差分的搜索
void combination_for_search_grain_reduce_v3(u32 n,u32 k,string curr_DIR){
	//定义一个计数器，用来检测试验的进度
	long long counter=0;
	//预先存储一个估计的总的计算量
	long long t_Sum[6]={53,1378,23426,292825,2869685,22957480};
	//初始化组合向量
	u32 *v=new u32[k+1]();
	for(int i=0;i<k;i++){
		v[i]=i+1;
	}
	v[k]=n+1;
	//用初始化的组合数，并对初始化组合进行操作
	genOutput_diff_imp_grain_reduce_v3(k,v,curr_DIR);
	//穷举C(n,k)的所有组合，为每个组合设定输入状态差分，并执行grain得到输出差分
	while(combin_for_search_imp_sub_grain_reduce_v3(k,v,curr_DIR)){
		if((++counter) % 20000 ==0){
			cout<<"proceed "<<setprecision(3)<<(double)counter*100/t_Sum[k-1]<<"%..."<<endl;
		}
	}
	delete [] v;
}

bool combin_for_search_imp_sub_grain_reduce_v3(u32 k,u32* v,string curr_DIR){
	for(int i=k-1;i>=0;i--){
		if(v[i]+1!=v[i+1]){
			v[i]++;
			//根据当前组合进行操作
			for(int j=i+1;j<k;j++)
				v[j]=v[j-1]+1;
			genOutput_diff_imp_grain_reduce_v3(k,v,curr_DIR);
			return true;
		}
	}
	return false;
}

//得到输出差分的分布并建表 改进版
void genOutput_diff_imp_grain_reduce_v3(u32 k,u32 *v,string curr_DIR){
	//初始化 输入差分为全0 并输出当前组合v的对应的输入状态差分
	/*
		可以优化成byte上的操作,不过效果不明显
		LFSR[0]~LFSR[31]----index:1~32
		NFSR[0]~NFSR[9]----index:33~42
		NFSR[21]~NFSR[31]----index:43~53
	*/
	u32 LFSR[32];
	u32 NFSR[32];
	for(int i=0;i<32;i++){
		LFSR[i]=0;
		NFSR[i]=0;
	}
	for(int i=0;i<k;i++){
		u32 idx=v[i];
		if(idx>=1 && idx <=32)
			LFSR[idx-1]=1;
		else if(idx>=33 && idx<=42)
			NFSR[idx-33]=1;
		else
			NFSR[idx-22]=1;
	}
	//map<string,u32> counter;
	u32 spcial_KSD_size=0;
	//u32 SIZE_DIFF=STATE_NUM*k;
	//unsigned long long *data=new unsigned long long[SIZE_DIFF];
	unsigned long long *data=new unsigned long long[STATE_NUM];
	//for(int i=0;i<SIZE_DIFF;i++){
	for(int i=0;i<STATE_NUM;i++){
		u32 LFSR_1[32];
		u32 NFSR_1[32];
		//随机选择一个状态
		for(int j=0;j<32;j++){
			NFSR_1[j]=0;
			LFSR_1[j]=0;

			LFSR_1[j]=rc4()&0x01;
			if(j<10 || j>20)
				NFSR_1[j]=rc4()&0x01;
		}
		//根据差分位置，得到另一个状态
		u32 LFSR_2[32];
		u32 NFSR_2[32];
		for(int j=0;j<32;j++){
			LFSR_2[j]=LFSR_1[j]^LFSR[j];
			NFSR_2[j]=NFSR_1[j]^NFSR[j];
		}
		//分别用Grain reduce输出长度为KSLen_Reduced(bytes)的密钥流（Sampling resistance）
		/*ECRYPT_ctx_reduce* ctx_reduce_1=new ECRYPT_ctx_reduce;
		ECRYPT_ctx_reduce* ctx_reduce_2=new ECRYPT_ctx_reduce;*/
		ECRYPT_ctx_reduce ctx_reduce_1;
		ECRYPT_ctx_reduce ctx_reduce_2;
		u8 keystream_1[KSLen_Reduced];
		u8 keystream_2[KSLen_Reduced];
		//首先确定剩下的NFSR的11个比特
		grain_reduce_sampling_resistance(&ctx_reduce_1,LFSR_1,NFSR_1);
		grain_reduce_sampling_resistance(&ctx_reduce_2,LFSR_2,NFSR_2);
		//然后生成从12个clock开始的密钥流
		grain_reduce_sampling_resistance_genKSBytes(&ctx_reduce_1,keystream_1,KSLen_Reduced);
		grain_reduce_sampling_resistance_genKSBytes(&ctx_reduce_2,keystream_2,KSLen_Reduced);
		//计算截断密钥流的差分
		
		u8 keystream_Diff[KSLen_Reduced];
		for(int j=0;j<KSLen_Reduced;j++){
			keystream_Diff[j]=keystream_1[j]^keystream_2[j];
		}
		//统计各个特殊差分(HM<=MAX_KSD_HM)出现的频率 MAX_KSD_HM=5
		if(Hamming_weight_of_state(keystream_Diff,KSLen_Reduced)<=MAX_KSD_HM){
			unsigned long long diff_long=char_2_long(keystream_Diff,KSLen_Reduced);
			data[spcial_KSD_size]=diff_long;
			spcial_KSD_size++;
		}
	}
	//将counter中对应的输出差分存储到一个txt文件中（以输出差分的16进制表示命名），将输入状态差分转化成16进制+输出该差分的比例，存储在txt的一行。
	u8 inputDiffbyte[STATE_BYTE];
	for(int i=0;i<STATE_BYTE;i++){
		inputDiffbyte[i]=0;
	}
	stateBit2Byte(inputDiffbyte,STATE_BYTE,LFSR,NFSR,32);
	string inputDiffStr=char2HexString(inputDiffbyte,STATE_BYTE);  //NFSR+LFSR   16进制

	//将data 排序
	//sort(data,data+SIZE_DIFF);
	qsort(data,spcial_KSD_size,sizeof(unsigned long long),comp);
	//将data中的元素统计，并建表（以输出差分的16进制命名）
	u32 counter;
	multimap<u32,unsigned long long> occurrance;
	for(int i=0;i<spcial_KSD_size;){
		counter=0;
		unsigned long long curr=data[i];
		int j=i;
		while(curr==data[j] && j<spcial_KSD_size){
			counter++;
			j++;
		}
		//counter记录了当前KSD出现的次数，j是下一个KSD第一个出现的下标。
		//只保留当前比重最大的MAX_KSD(100)个差分 建最大值堆  对于NCA-3.0这里除了考虑频率之外，最好把所有special的KSD都留下来，不过这个措施是否有效还不清楚
		multimap<u32,unsigned long long>::iterator it=occurrance.begin();
		if(it==occurrance.end()){//对应初始没有元素的情况
			occurrance.insert(make_pair(counter,curr));
		}
		else if(counter>it->first){
			occurrance.insert(make_pair(counter,curr));
			if(occurrance.size()>MAX_KSD)  //删除最小的，保持最大的MAX_KSD个
				occurrance.erase(occurrance.begin());
		}
		//已跳过当前重复区域，进入下一个KSD
		i=j;
	}
	//将MAX_KSD(100)个差分建表/更新表
	multimap<u32,unsigned long long>::iterator beg=occurrance.begin();
	multimap<u32,unsigned long long>::iterator end=occurrance.end();
	for(;beg!=end;beg++){
		//cout<<beg->second<<"出现了:"<<beg->first<<"次。"<<endl;
		string outDiff=long_to_hexString(beg->second,KSLen_Reduced);
		//cout<<outDiff<<endl;
		string fileName=curr_DIR+outDiff+".txt";
		ofstream outfile;
		outfile.open(fileName.c_str(),ofstream::app);
		outfile<<fixed<<showpoint;
		if(outfile){
			outfile<<inputDiffStr<<" "<<beg->first<<"/"<<STATE_NUM<<"\n";
		}
		outfile.close();
	}
	occurrance.clear();
	delete [] data;
}

u32 Hamming_weight_of_state(u8* state,u32 Len){
	u32 HM=0;
	for(int i=0;i<Len;i++){
		for(int j=0;j<8;j++){
			HM+=(state[i]>>j)&0x01;
		}
	}
	return HM;
}