/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of offline stage in NCA-3.0
	 
*/

#include "stdafx.h"
#include "head.h"
//验证NCA-3.0假设 grain full version 
//需要调用预先写好的sampling resistance版本的grain
void verify_assumption(u32 d,u32 random_test_num){
	rc4_setup();
	string part="verify_ass";
	string curr_DIR=DIR_ASS+part+"_KSD_"+int_2_string(MAX_KSD)+"_HM_"
		+int_2_string(MAX_KSD_HM)+"_d_"+int_2_string(d)+"\\";
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
	cout<<"首先随即选取ISD，计算相应KSD并存储起来..."<<endl;
	for(int q=0;q<random_test_num;q++){

	}
}


//验证NCA-3.0假设，缩减版本
void verify_assumption_reduce(u32 d,u32 random_test_num){
	rc4_setup();
	//构建输出路径
	string part="verify_ass";
	string curr_DIR=DIR_REDUCE_V3_ASS+part+"_KSD_"+int_2_string(MAX_KSD)+"_HM_"
		+int_2_string(MAX_KSD_HM)+"_d_"+int_2_string(d)+"\\";
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
	cout<<"首先随即选取ISD，计算相应KSD并存储起来..."<<endl;
	for(int q=0;q<random_test_num;q++){
		if((q+1) % 1000 ==0){
			cout<<"proceed "<<setprecision(3)<<(double)q*100/random_test_num<<"%..."<<endl;
		}
		
		//随即选取d个查分位置并存储在v[i]当中
		u32 *v=new u32[d]();
		u32 state_Len=STATE_REDUCE-SP;
		for(int i=0;i<d;i++){
			v[i]=(rc4() % state_Len)+1;		//产生1~53之间的数
		}
		//根据位置生成状态查分
		u32 LFSR[32];
		u32 NFSR[32];
		for(int i=0;i<32;i++){
			LFSR[i]=0;
			NFSR[i]=0;
		}
		for(int i=0;i<d;i++){
			u32 idx=v[i];
			if(idx>=1 && idx <=32)
				LFSR[idx-1]=1;
			else if(idx>=33 && idx<=42)
				NFSR[idx-33]=1;
			else
				NFSR[idx-22]=1;
		}
		u32 spcial_KSD_size=0;
		unsigned long long *data=new unsigned long long[STATE_NUM];
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
		delete [] v;
	}
	//接下来统计KSD表中ISD出现的比例
	cout<<"接下来统计KSD表中ISD出现的比例..."<<endl;
	string fileSuffix="*.txt";
	string fileDir=curr_DIR+fileSuffix;
	set<string> ISD;
	ifstream infile;
	struct _finddata_t file;  
    long longf; 
	if((longf = _findfirst(fileDir.c_str(),&file))==-1L){
		cout<<"文件没有找到!\n"<<endl;
	}else{
		//循环查找所有后缀为.txt的文件
		string fileName=file.name;
		//解析出KSD
		string::size_type pos=fileName.find(".");
		string ksd=fileName.substr(0,pos);
		string tableName=curr_DIR+fileName;
		infile.open(tableName.c_str());
		if(infile){
			char val[2048];
			while(infile.getline(val,sizeof(val))){
				string str(val);
				//extract cube size
				string::size_type pos=str.find(" ");
				ISD.insert(str.substr(0,pos));
			}
		}else{
			cout<<"找不到"<<tableName<<"文件"<<endl;
		}
		infile.close();
		while(_findnext(longf,&file)==0){
			fileName=file.name;
			ksd=fileName.substr(0,pos);
			tableName=curr_DIR+fileName;
			infile.open(tableName.c_str());
			if(infile){
				char val[2048];
				while(infile.getline(val,sizeof(val))){
					string str(val);
					//extract cube size
					string::size_type pos=str.find(" ");
					ISD.insert(str.substr(0,pos));
				}
			}else{
				cout<<"找不到"<<tableName<<"文件"<<endl;
			}
			infile.close();
		}
	}
	cout<<"Special表中包含ISD的比例为:"<<ISD.size()<<"/"<<random_test_num<<endl;
	_findclose(longf);
}