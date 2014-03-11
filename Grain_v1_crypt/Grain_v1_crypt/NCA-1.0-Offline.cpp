/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of offline stage in NCA-1.0 
	
*/

#include "stdafx.h"
#include "head.h"

//穷举所有Hamming重量小于d的64比特的内部状态差分，然后在N大小的样本空间下，进行预计算，输出密钥流长度为l（最大支持64bit， unsigned long long）。
/*
	d:输入状态差分的最大汉明重量
*/

void offLine_table_construct_v1(u32 d){
	for(int i=1;i<=d;i++){
		//枚举所有输入差分的汉明重量为i的差分   
		u32 state_Len=STATE_REDUCE;		//总的状态数 减去sampling resistance的大小
		cout<<"Grain reduce--开始处理输入差分汉明重量为:"<<i<<"的情况."<<endl;
		double time[4]={0};
		start_cal();
		combination_for_search_grain_reduce_v1(state_Len,i,d);
		end_cal(time);
		cout<<"Grain reduce--输入差分汉明重量为:"<<i<<"的情况已经处理完毕."<<endl;
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
	}
}

//简单组合问题，打印从1~n个数中选取k个的所有组合,这个程序对于k和n比较小的时候速度快,非递归实现
//用于辅助输入差分的搜索
void combination_for_search_grain_reduce_v1(u32 n,u32 k,u32 d){
	//定义一个计数器，用来检测试验的进度
	long long counter=0;
	//预先存储一个估计的总的计算量
	long long t_Sum[6]={64,2016,41664,635376,7624512,74974368};
	//初始化组合向量
	u32 *v=new u32[k+1]();
	for(int i=0;i<k;i++){
		v[i]=i+1;
	}
	v[k]=n+1;
	//用初始化的组合数，并对初始化组合进行操作
	genOutput_diff_imp_grain_reduce_v1(k,v,d);
	//穷举C(n,k)的所有组合，为每个组合设定输入状态差分，并执行grain得到输出差分
	while(combin_for_search_imp_sub_grain_reduce_v1(k,v,d)){
		if((++counter) % 10000 ==0){
			cout<<"proceed "<<setprecision(3)<<(double)counter*100/t_Sum[k-1]<<"%..."<<endl;
		}
	}
	delete [] v;
}

bool combin_for_search_imp_sub_grain_reduce_v1(u32 k,u32* v,u32 d){
	for(int i=k-1;i>=0;i--){
		if(v[i]+1!=v[i+1]){
			v[i]++;
			//根据当前组合进行操作
			for(int j=i+1;j<k;j++)
				v[j]=v[j-1]+1;
			genOutput_diff_imp_grain_reduce_v1(k,v,d);
			return true;
		}
	}
	return false;
}

//得到输出差分的分布并建表 改进版
void genOutput_diff_imp_grain_reduce_v1(u32 k,u32 *v,u32 d){
	//初始化 输入差分为全0 并输出当前组合v的对应的输入状态差分
	u8 input_diff[STATE_BYTE];
	for(int i=0;i<STATE_BYTE;i++){
		input_diff[i]=0;
	}
	for(int m=0;m<k;m++){
		//cout<<v[m]<<" "<<ends;
		u32 p=posIdx(v[m]-1);
		u32 r=rotateIdx(v[m]-1);
		input_diff[p]=input_diff[p]^(1<<r);
	}
	
	
	//随机选择STATE_NUM*k个状态
	u32 SIZE_DIFF=STATE_NUM*k;
	unsigned long long *data=new unsigned long long[SIZE_DIFF];
	for(int i=0;i<SIZE_DIFF;i++){
		//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
		u8 rnd_state_1[STATE_BYTE];
		for(int j=0;j<STATE_BYTE;j++){
			rnd_state_1[j]=rc4();
		}
		//根据差分位置，得到另一个状态rud_state_2
		u8 rnd_state_2[STATE_BYTE];
		for(int j=0;j<STATE_BYTE;j++){
			rnd_state_2[j]=rnd_state_1[j]^input_diff[j];
		}
		//分别代入Grain中 输出l长的密钥流
		//分别用Grain reduce输出长度为KSLen_Reduced(bytes)的密钥流（Sampling resistance）
		/*ECRYPT_ctx_reduce* ctx_reduce_1=new ECRYPT_ctx_reduce;
		ECRYPT_ctx_reduce* ctx_reduce_2=new ECRYPT_ctx_reduce;*/
		ECRYPT_ctx_reduce ctx_reduce_1;
		ECRYPT_ctx_reduce ctx_reduce_2;
		ctx_reduce_1.keysize=32;
		ctx_reduce_1.ivsize=24;
		ctx_reduce_2.keysize=32;
		ctx_reduce_2.ivsize=24;
		u8 keystream_1[KSLen_Reduced];
		u8 keystream_2[KSLen_Reduced];

		//将状态代入grain中,获得对应的长度为KSLen的密钥流，并输出其差分
		grain_state_load_reduce(&ctx_reduce_1,rnd_state_1);
		grain_state_load_reduce(&ctx_reduce_2,rnd_state_2);
		ECRYPT_keystream_bytes_reduce(&ctx_reduce_1,keystream_1,KSLen_Reduced);
		ECRYPT_keystream_bytes_reduce(&ctx_reduce_2,keystream_2,KSLen_Reduced);
		
			
		u8 Diff_KS[KSLen_Reduced];
		for(int j=0;j<KSLen_Reduced;j++){
			Diff_KS[j]=keystream_1[j]^keystream_2[j];
		}
		unsigned long long diff_long=char_2_long(Diff_KS,KSLen_Reduced);
		data[i]=diff_long;
		//统计各个差分出现的频率
		//string str=char2HexString(Diff_KS,KSLen_Reduced);
		/*map<string,u32>::iterator it=counter.find(str);
		if(it!=counter.end()){//已存在这个差分
			it->second+=1;
		}else
			counter.insert(make_pair(str,1));
		*/
		//结构体ctx_1和ctx_2的内存释放
		/*if(ctx_reduce_1){
			delete [] ctx_reduce_1->LFSR;
			delete [] ctx_reduce_1->NFSR;
		}
		ctx_reduce_1=NULL;
		if(ctx_reduce_2){
			delete [] ctx_reduce_2->LFSR;
			delete [] ctx_reduce_2->NFSR;
		}
		ctx_reduce_2=NULL;*/
	}
	//将data 排序
	//sort(data,data+SIZE_DIFF);
	qsort(data,SIZE_DIFF,sizeof(unsigned long long),comp);
	//将data中的元素统计，并建表（以输出差分的16进制命名）
	u32 counter;
	multimap<u32,unsigned long long> occurrance;
	for(int i=0;i<SIZE_DIFF;){
		counter=0;
		unsigned long long curr=data[i];
		int j=i;
		while(curr==data[j] && j<SIZE_DIFF){
			counter++;
			j++;
		}
		//counter记录了当前KSD出现的次数，j是下一个KSD第一个出现的下标。
		//只保留当前比重最大的MAX_KSD(100)个差分 建最大值堆
		multimap<u32,unsigned long long>::iterator it=occurrance.begin();
		if(it==occurrance.end()){//对应初始没有元素的情况
			occurrance.insert(make_pair(counter,curr));
		}
		else if(counter>it->first){
			occurrance.insert(make_pair(counter,curr));
			if(occurrance.size()>MAX_KSD)  //删除最小的，保持最大的100个
				occurrance.erase(occurrance.begin());
		}
		//已跳过当前重复区域，进入下一个KSD
		i=j;
	}
	//将MAX_KSD(100)个差分建表/更新表
	//建立输出文件
	string part="Grain_(l,d)_(";
	string curr_DIR=DIR_REDUCE_V1+part+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")"+
		FILE_SUFFIX+"\\";
	multimap<u32,unsigned long long>::iterator beg=occurrance.begin();
	multimap<u32,unsigned long long>::iterator end=occurrance.end();
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
	for(;beg!=end;beg++){
		//cout<<beg->second<<"出现了:"<<beg->first<<"次。"<<endl;
		string outDiff=long_to_hexString(beg->second,KSLen_Reduced);
		//cout<<outDiff<<endl;
		string fileName=curr_DIR+outDiff+".txt";
		ofstream outfile;
		outfile.open(fileName.c_str(),ofstream::app);
		outfile<<fixed<<showpoint;
		if(outfile){
			outfile<<char2HexString(input_diff,STATE_BYTE)<<" "<<beg->first<<"/"<<SIZE_DIFF<<"\n";
		}
		outfile.close();
	}
	occurrance.clear();
	delete [] data;
	//将data中对应的输出差分存储到一个txt文件中（以输出差分的16进制表示命名），将input_diff转化成16进制+输出该差分的比例，存储在txt的一行。
	//最后统计每个txt的行数，求出平均的行数，也即每个table的大小（以输出差分的16进制命名）。

	//string inputDiffStr=char2HexString(input_diff,STATE_BYTE);
	

	/*
	//test the speed
	//if(counter.size()==SIZE_DIFF){
		//cout<<"输入差分："<<inputDiffStr<<endl;
		//cout<<"输出差分的个数等于Sampling的个数."<<counter.size()<<"/"<<SIZE_DIFF<<endl<<endl;
		//cout<<"输出差分的个数:"<<counter.size()<<"/"<<SIZE_DIFF<<endl<<endl;
	//}
	//首先遍历counter中的所有输出差分
	map<string,u32>::iterator beg=counter.begin();
	map<string,u32>::iterator end=counter.end();
	for(;beg!=end;beg++){
		string outDiff=beg->first;
		u32 occurs=beg->second;
		double occur_prop=(double)occurs/STATE_NUM;
		//cout<<"输入差分："<<inputDiffStr<<endl;
		//cout<<outDiff<<"  "<<occur_prop<<endl;
		//将输入差分和比例 写入到以outDiff命名的txt中。
		string fileName=outDiff+".txt";
		string part="Grain_(l,d)_(";
		fileName=DIR_REDUCE_V1+part+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")\\"+fileName;
		ofstream outfile;
		outfile.open(fileName.c_str(),ofstream::app);
		outfile<<fixed<<showpoint;
		if(outfile){
			outfile<<inputDiffStr<<" "<<setprecision(8)<<occur_prop<<"\n";
		}
		outfile.close();
	}
	//cout<<endl<<endl;
	//counter.clear();
	*/
}