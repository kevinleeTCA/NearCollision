#include "stdafx.h"
#include "head.h"
//kevin edit. this file is used for table construction

/*参数：
L:输入差分的最大汉明重量
*/
void searchAllNearColStates(u32 L){
	for(int i=4;i<=L;i++){
		
		/*//初始化 输入差分为全0
		u8 diff_state[LEN];
		for(int j=0;j<LEN;j++){
			diff_state[j]=0;
		}
		//枚举所有输入差分的汉明重量为i的差分  数组B[i]=1表示该位置出现，B[i]=0表示该位置不出现
		u32 N=LEN*8;		//LEN*8 bits length
		u32 B[LEN*8];
		combination_for_search(N,i,0,B,diff_state);
		*/
			
		u32 N=LEN*8;
		cout<<"开始处理输入差分汉明重量为:"<<i<<"的情况."<<endl;
		combination_for_search_imp(N,i);
		cout<<"输入差分汉明重量为:"<<i<<"的情况已经处理完毕.\n\n"<<endl;
		
		//cout<<"开始处理输入差分汉明重量为:"<<L<<"的情况."<<endl;
		//combination_for_search_imp(N,L);
		//cout<<"输入差分汉明重量为:"<<L<<"的情况已经处理完毕.\n\n"<<endl;
	}
}
//简单组合问题，打印从1~n个数中选取k个的所有组合,这个程序利用了回溯的思想
//用于辅助输入差分的搜索
void combination_for_search(u32 n,u32 k,u32 curr,u32 *B, u8 *diff_state){
	u32 counter=0;
	for(int i=0;i<curr;i++)
		counter+=B[i];
	if(counter==k){
		//如果当前满足，直接打印
		//打元素为k的这个组合
		for(int i=0;i<curr;i++){
			if(B[i])
				cout<<i+1<<" "<<ends;
		}
		cout<<"对应输入差分："<<ends;
		for(int j=0;j<20;j++){
				printf("%x ",diff_state[j]);
		}
		cout<<endl;
		genOutput_diff(diff_state);
		return;
	}
	if(counter>k || curr==n)
		//回溯
		return;
	B[curr]=0;
	combination_for_search(n,k,curr+1,B,diff_state);
	B[curr]=1;
	u32 p=posIdx(curr);
	u32 r=rotateIdx(curr);
	diff_state[p]=diff_state[p]^(1<<r);
	combination_for_search(n,k,curr+1,B,diff_state);
	diff_state[p]=diff_state[p]^(1<<r);
}
//简单组合问题，打印从1~n个数中选取k个的所有组合,这个程序对于k和n比较小的时候速度快,非递归实现
//用于辅助输入差分的搜索
void combination_for_search_imp(u32 n,u32 k){
	//定义一个计数器，用来检测试验的进度
	long long counter=0;
	//预先存储一个估计的总的计算量
	long long t_Sum[5]={160,12720,669920,26294360,820384032};
	//初始化组合向量
	u32 *v=new u32[k+1]();
	for(int i=0;i<k;i++){
		v[i]=i+1;
	}
	v[k]=n+1;
	//用初始化的组合数，并对初始化组合进行操作
	genOutput_diff_imp(k,v);
	//穷举C(n,k)的所有组合，为每个组合设定输入状态差分，并执行grain得到输出差分
	while(combin_for_search_imp_sub(k,v)){
		if((++counter) % 30000 ==0){
			cout<<"proceed "<<setprecision(3)<<(double)counter*100/t_Sum[k-1]<<"%..."<<endl;
		}
	}
}
bool combin_for_search_imp_sub(u32 k,u32* v){
	for(int i=k-1;i>=0;i--){
		if(v[i]+1!=v[i+1]){
			v[i]++;
			//根据当前组合进行操作
			for(int j=i+1;j<k;j++)
				v[j]=v[j-1]+1;
			genOutput_diff_imp(k,v);
			
			return true;
		}
	}
	return false;
}
//得到输出差分的分布并建表 改进版
void genOutput_diff_imp(u32 k,u32 *v){
	//初始化 输入差分为全0 并输出当前组合v的对应的输入状态差分
	u8 *input_diff=new u8[LEN]();
	for(int m=0;m<k;m++){
		//cout<<v[m]<<" "<<ends;
		u32 p=posIdx(v[m]-1);
		u32 r=rotateIdx(v[m]-1);
		input_diff[p]=input_diff[p]^(1<<r);
	}
	/*
	for(int i=0;i<k;i++){
			if(v[i])
				cout<<v[i]<<" "<<ends;
	}
	cout<<"对应输入差分："<<ends;
		for(int j=0;j<20;j++){
				printf("%x ",input_diff[j]);
	}
	cout<<endl;
	*/
	map<string,u32> counter;
	//随机选择T_NUM个状态
	for(int i=0;i<T_NUM;i++){
		//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
		u8 rnd_state_1[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_1[j]=rc4();
		}
		//根据差分位置，得到另一个状态rud_state_2
		u8 rnd_state_2[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_2[j]=rnd_state_1[j]^input_diff[j];
		}
		//分别代入Grain中 输出l长的密钥流
		//u32 KSLen=10;  //byte length
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
		ECRYPT_keystream_bytes(ctx_1,keyStream_1,KSLen);
		ECRYPT_keystream_bytes(ctx_2,keyStream_2,KSLen);
		
			
		u8 Diff_KS[KSLen];
		for(int i=0;i<KSLen;i++){
			Diff_KS[i]=keyStream_1[i]^keyStream_2[i];
		}
		/*
		for(int i=0;i<KSLen;i++){
				printf("%x ",Diff_KS[i]);
			}
		cout<<endl;
		*/
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
	//将counter中对应的输出差分存储到一个txt文件中（以输出差分的16进制表示命名），将input_diff转化成16进制+输出该差分的比例，存储在txt的一行。
	//最后统计每个txt的行数，求出平均的行数，也即每个table的大小（以输出差分的16进制命名）。
	string inputDiffStr=char2HexString(input_diff,LEN);
	//首先遍历counter中的所有输出差分
	map<string,u32>::iterator beg=counter.begin();
	map<string,u32>::iterator end=counter.end();
	for(;beg!=end;beg++){
		string outDiff=beg->first;
		u32 occurs=beg->second;
		double occur_prop=(double)occurs/T_NUM;
		//将输入差分和比例 写入到以outDiff命名的txt中。
		string fileName=outDiff+".txt";
		fileName=DIR+fileName;
		ofstream outfile;
		outfile.open(fileName.c_str(),ofstream::app);
		if(outfile){
			//cout<<"file \'"<<fileName<<"\' created."<<endl;
			outfile<<inputDiffStr<<" "<<occur_prop<<"\n";
			//cout<<"Successfully write:"<<inputDiffStr<<" "<<occur_prop<<" to file:" <<fileName<<endl;
		}
		outfile.close();
	}
	counter.clear();
	delete [] input_diff;
}
void genOutput_diff(u8 *input_diff){
	map<string,u32> counter;
	//随机选择T_NUM个状态
	for(int i=0;i<T_NUM;i++){
		//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
		u8 rnd_state_1[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_1[j]=rc4();
		}
		//根据差分位置，得到另一个状态rud_state_2
		u8 rnd_state_2[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_2[j]=rnd_state_1[j]^input_diff[j];
		}
		//分别代入Grain中 输出l长的密钥流
		//u32 KSLen=10;  //byte length
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
		ECRYPT_keystream_bytes(ctx_1,keyStream_1,KSLen);
		ECRYPT_keystream_bytes(ctx_2,keyStream_2,KSLen);
		
			
		u8 Diff_KS[KSLen];
		for(int i=0;i<KSLen;i++){
			Diff_KS[i]=keyStream_1[i]^keyStream_2[i];
		}
		/*
		for(int i=0;i<KSLen;i++){
				printf("%x ",Diff_KS[i]);
			}
		cout<<endl;
		*/
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
	//将counter中对应的输出差分存储到一个txt文件中（以输出差分的16进制表示命名），将input_diff转化成16进制+输出该差分的比例，存储在txt的一行。
	//最后统计每个txt的行数，求出平均的行数，也即每个table的大小（以输出差分的16进制命名）。
	string inputDiffStr=char2HexString(input_diff,LEN);
	//首先遍历counter中的所有输出差分
	map<string,u32>::iterator beg=counter.begin();
	map<string,u32>::iterator end=counter.end();
	for(;beg!=end;beg++){
		string outDiff=beg->first;
		u32 occurs=beg->second;
		double occur_prop=(double)occurs/T_NUM;
		//将输入差分和比例 写入到以outDiff命名的txt中。
		string fileName=outDiff+".txt";
		fileName=DIR+fileName;
		ofstream outfile;
		outfile.open(fileName.c_str(),ofstream::app);
		if(outfile){
			//cout<<"file \'"<<fileName<<"\' created."<<endl;
			outfile<<inputDiffStr<<" "<<occur_prop<<"\n"<<ends;
			//cout<<"Successfully write:"<<inputDiffStr<<" "<<occur_prop<<" to file:" <<fileName<<endl;
		}
		outfile.close();
	}
	counter.clear();
}

//统计以输出差分命名的每个table的行数，用于估计存储空间的大小
/*
void cal_ave_rows(string dirName){
	//首先读取该路径下对应的所有文件的名字 存储在一个vector中
	cout<<"start"<<endl;
	vector<string> fileNameList=get_filelist((char*)dirName.c_str());
	//依次遍历每个文件，并记录文件的行数
	
	vector<string>::iterator beg=fileNameList.begin();
	vector<string>::iterator end=fileNameList.end();
	for(;beg!=end;beg++){
		cout<<*beg<<endl;
	}
}

vector<string> & get_filelist(char *foldname){
	vector<string> flist;
	HANDLE file;
	WIN32_FIND_DATA fileData;
	char line[1024];
	wchar_t fn[1000];
	mbstowcs(fn,(const char*)foldname,999);
	file = FindFirstFile(fn, &fileData);
	FindNextFile(file, &fileData);
	while(FindNextFile(file, &fileData)){
		wcstombs(line,(const wchar_t*)fileData.cFileName,259);
		flist.push_back(line);
	}
	return flist;
}

*/