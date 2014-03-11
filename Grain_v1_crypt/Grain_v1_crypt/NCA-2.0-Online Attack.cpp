/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of online stage in NCA-2.0 
*/

#include "stdafx.h"
#include "head.h"

/*
	在确定命中输入差分的时候，只需要匹配53bit的内部状态即可，由输出密钥流来决定的剩下的11bit的内部状态不用管。
	在线上阶段选取的密钥流对应的时刻，应该是再输出11bit之前的的那个时刻。内部状态差分也是那个时刻的。
*/

bool online_attack_v2(u32 d){
	bool result=false;
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
	//initial phase complete, start to collect sets A and B
	start_cal();
	double time[4]={0};
	unsigned long long set_size=ceil(pow((double)2,DATA_SET));
	cout<<"Data set size:2^{"<<DATA_SET<<"}"<<endl;
	Online_Data_Reduce *data_A=new Online_Data_Reduce[set_size];
	Online_Data_Reduce *data_B=new Online_Data_Reduce[set_size];
	//首先收集数据并排序数据量不能超过2^{30}，否则内存会不够用，就得考虑读写硬盘盒外排序
	//collect_sets_v2_no_prefix(ctx_reduce,data_A,data_B,1,set_size);
	collect_sets_v2_with_prefix(ctx_reduce,data_A,data_B,1,set_size);
	//接着寻找near collision
	//result=find_near_collision_v2_no_prefix(data_A,data_B,set_size);
	result=find_near_collision_v2_with_prefix_imp(d,data_A,data_B,set_size);
	end_cal(time);
	printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);
	////测试collect数据的正确性  前缀是否为全0，后缀是否能够匹配得上，当前状态是否能够匹配得上。
	
	//for(int i=0;i<set_size;i++){
	//	Online_Data_Reduce *val=&data_A[i];
	//	unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	//	for(int j=0;j<KSLen_Reduced;j++){
	//	//	printf("%x",val->KS[j]);
	//	}
	//	printf("%u",lval);
	//	printf("_");
	//	printf("%d",val->clock_t);
	//	printf("_");
	//	for(int j=0;j<STATE_BYTE;j++){
	//		printf("%x",val->state[j]);
	//	}
	//	printf("\n");
	//}
	//cout<<endl;
	////for(int i=0;i<set_size;i++){
	//for(int i=218;i<222;i++){
	//	Online_Data_Reduce *val=&data_B[i];
	//	unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	//	for(int j=0;j<KSLen_Reduced;j++){
	//	//	printf("%x",val->KS[j]);
	//	}
	//	printf("%u",lval);
	//	printf("_");
	//	printf("%d",val->clock_t);
	//	printf("_");
	//	for(int j=0;j<STATE_BYTE;j++){
	//		printf("%x",val->state[j]);
	//	}
	//	printf("\n");
	//}
	//cout<<"随机测试一个样本的输出前缀，看看是否全为11个0"<<endl;
	//unsigned long long test_clock=data_A[15].clock_t;
	//cout<<test_clock<<endl;
	//ECRYPT_ctx_reduce* ctx_reduce_test=new ECRYPT_ctx_reduce;
	//ECRYPT_keysetup_reduce(ctx_reduce_test,key_R,32,24);
	//ECRYPT_ivsetup_reduce(ctx_reduce_test,IV_R);
	//for(unsigned long long i=0;i<test_clock;i++){
	//	grain_keystream_reduce(ctx_reduce_test);
	//}
	////看看状态能否匹配得上
	//u8 test_state[STATE_BYTE];
	//grain_state_read_reduce(ctx_reduce_test,test_state);
	//for(int j=0;j<STATE_BYTE;j++){
	//	printf("%x",test_state[j]);
	//}
	//printf("\n");
	////grain_state_load_reduce(ctx_reduce_test,test_state);
	////看看输出前缀是不是全0
	//for(int i=0;i<SP;i++){
	//	printf("%d",grain_keystream_reduce(ctx_reduce_test));
	//}
	//cout<<endl;
	////测试with prefix才会用到
	//for(int i=1;i<=SP;i++){
	//	grain_keystream_backward_reduce(ctx_reduce_test);
	//}
	////看看后缀能不能匹配的上
	//u8 KS_test[KSLen_Reduced];
	//ECRYPT_keystream_bytes_reduce(ctx_reduce_test,KS_test,KSLen_Reduced);
	//printf("%u",char_2_long(KS_test,KSLen_Reduced));
	//
	//long long j=220;
	//cout<<"\nbeg:"<<find_begin(data_B,0,set_size-1,data_B[j])<<endl;
	//cout<<"end:"<<find_end(data_B,0,set_size-1,data_B[j])<<endl;
	//cout<<"220:";
	//cout<<char_2_long(data_B[220].KS,KSLen_Reduced)<<endl;
	//cout<<"219:";
	//cout<<char_2_long(data_B[219].KS,KSLen_Reduced)<<endl;
	delete [] key_R;
	delete [] IV_R;
	delete [] data_A;
	delete [] data_B;
	return result;
}
/*
	b:用于验证的密钥流的长度
	要注意结构体和指针的内存泄露
	为了模拟，我们除了记录输出截断密钥流和时刻外，还记录了输出该密钥流的内部状态
	记录从11个bit之后的密钥流截断
*/
void collect_sets_v2_no_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,u32 b,unsigned long long set_size){
	cout<<"Start to collect data set A, no prefix..."<<endl;
	unsigned long long clock_t=0;
	unsigned long long curr_idx_A=0;
	while(curr_idx_A<set_size){
		//找到第一个为0的起点
		while(grain_keystream_reduce(ctx_reduce)){
			clock_t++;
		}
		grain_keystream_backward_reduce(ctx_reduce);
			
		//保存当前状态和clock 开始判断接下来的11bit
		u8 stateByte[STATE_BYTE];
		grain_state_read_reduce(ctx_reduce,stateByte);
		unsigned long long curr_clock=clock_t;
		bool tag=true;
		for(int i=1;i<=SP;i++){
			//如果某一个状态bit为1;则退出
			if(grain_keystream_reduce(ctx_reduce)){
				tag=false;
				clock_t+=i;			//更新clock
				break;
			}
		}
		if(tag){
			//找到一个前缀为11bit全0候选截断密钥流；
			clock_t+=SP;
			Online_Data_Reduce val;
			u8 keyStream_R[KSLen_Reduced];
			ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //会进行KSLen_Reduced*8个Grain tick;
			for(int j=0;j<KSLen_Reduced;j++){
				val.KS[j]=keyStream_R[j];
			}
			for(int j=0;j<STATE_BYTE;j++){
				val.state[j]=stateByte[j];
			}
			val.clock_t=curr_clock;
			data_A[curr_idx_A++]=val;
			//显示当前收集的状态
			if((curr_idx_A) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_A*100/set_size<<"%..."<<endl;
			}
			clock_t+=KSLen_Reduced*8;
		}
	}
	cout<<"Set A Collect complete,start to sort data set..."<<endl;
	//对数据进行排序。
	//sort(data,data+set_size,comp_struct);
	qsort(data_A,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to collect data set B, no prefix..."<<endl;
	unsigned long long curr_idx_B=0;
	while(curr_idx_B<set_size){
		//找到第一个为0的起点
		while(grain_keystream_reduce(ctx_reduce))
			clock_t++;
		grain_keystream_backward_reduce(ctx_reduce);
		//保存当前状态和clock开始判断接下来的11bit
		u8 stateByte[STATE_BYTE];
		grain_state_read_reduce(ctx_reduce,stateByte);
		unsigned long long curr_clock=clock_t;
		bool tag=true;
		for(int i=1;i<=SP;i++){
			//如果某一个状态bit为1;则退出
			if(grain_keystream_reduce(ctx_reduce)){
				tag=false;
				clock_t+=i;			//更新clock
				break;
			}
		}
		if(tag){
			//找到一个前缀为11bit全0候选截断密钥流；
			clock_t+=SP;
			Online_Data_Reduce val;
			u8 keyStream_R[KSLen_Reduced];
			ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //会进行KSLen_Reduced*8个Grain tick;
			for(int j=0;j<KSLen_Reduced;j++){
				val.KS[j]=keyStream_R[j];
			}
			for(int j=0;j<STATE_BYTE;j++){
				val.state[j]=stateByte[j];
			}
			val.clock_t=curr_clock;
			data_B[curr_idx_B++]=val;
			//显示当前收集的状态
			if((curr_idx_B) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_B*100/set_size<<"%..."<<endl;
			}
			//更新clock
			clock_t+=KSLen_Reduced*8;
		}
	}
	cout<<"Set B Collect complete,start to sort data set..."<<endl;
	//对数据进行排序。
	//sort(data,data+set_size,comp_struct);
	qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to find collision in the precomputed table....using Strategy II"<<endl;
}

//Strategy II
bool find_near_collision_v2_no_prefix(Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size){
	//string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)"+FILE_SUFFIX+NO_PREFIX+"\\";
	string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)_no_prefix\\";
	for(int i=0;i<set_size;i++){
		if((i+1) % 1000 ==0){
			cout<<"Collision finding proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
		}
		//cout<<"i:"<<i<<endl;
		Online_Data_Reduce val_A=data_A[i];
		for(int j=0;j<set_size;j++){
			Online_Data_Reduce val_B=data_B[j];
			//记录当前输出差分 不带固定前缀的
			u8 curr_KS_Diff[KSLen_Reduced];
			for(int k=0;k<KSLen_Reduced;k++)
				curr_KS_Diff[k]=val_A.KS[k]^val_B.KS[k];
			//根据当前输出差分查表，并在表中寻找匹配的内部状态差分。
			string tableName=char2HexString(curr_KS_Diff,KSLen_Reduced);
			tableName=DIR_REDUCE_V2+subdir+tableName+".txt";
			ifstream infile;
			infile.open(tableName.c_str());
			if(infile){
				//记录当前输入差分
				u8 curr_state_Diff[STATE_BYTE];
				for(int k=0;k<STATE_BYTE;k++)
					curr_state_Diff[k]=val_A.state[k]^val_B.state[k];
				//因为保存的内部状态的差分中NFSR[10]~NFSR[20]是全0的，所以
				//我们需要预先将curr_state_Diff的这些位置置为0，然后再进行比较
				curr_state_Diff[1]&=0x03;
				curr_state_Diff[2]&=0xe0;
				char val[2048];
				while(infile.getline(val,sizeof(val))){
					string str(val);
					//extract cube size
					string::size_type pos=str.find(" ");
					string str_state_Diff=str.substr(0,pos);
					if(state_comp(curr_state_Diff,STATE_BYTE,str_state_Diff))
						return true;
				}
			}
			//else{
			//	//cout<<"文件:"<<tableName<<"没有找到."<<endl;
			//}
			//cout<<"file fail to load."<<endl;	
			infile.close();
		}
	}
	cout<<"Collision finding complete...fail to find match."<<endl;
	return false;
}


void collect_sets_v2_with_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,u32 b,unsigned long long set_size){
	cout<<"Start to collect data set A, with prefix..."<<endl;
	unsigned long long clock_t=0;
	unsigned long long curr_idx_A=0;
	while(curr_idx_A<set_size){
		//找到第一个为0的起点
		while(grain_keystream_reduce(ctx_reduce))
			clock_t++;
		grain_keystream_backward_reduce(ctx_reduce);
		//保存当前状态和clock开始判断接下来的11bit
		u8 stateByte[STATE_BYTE];
		grain_state_read_reduce(ctx_reduce,stateByte);
		unsigned long long curr_clock=clock_t;
		bool tag=true;
		for(int i=1;i<=SP;i++){
			//如果某一个状态bit为1;则退出
			if(grain_keystream_reduce(ctx_reduce)){
				tag=false;
				clock_t+=i;			//更新clock
				break;
			}
		}
		if(tag){
			//找到一个前缀为11bit全0候选截断密钥流；
			//退回到即将输出11个bit全0的那个状态
			for(int i=1;i<=SP;i++){
				grain_keystream_backward_reduce(ctx_reduce);
			}
			//clock_t+=SP;
			Online_Data_Reduce val;
			u8 keyStream_R[KSLen_Reduced];
			ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //会进行KSLen_Reduced*8个Grain tick;
			for(int j=0;j<KSLen_Reduced;j++){
				val.KS[j]=keyStream_R[j];
			}
			for(int j=0;j<STATE_BYTE;j++){
				val.state[j]=stateByte[j];
			}
			val.clock_t=curr_clock;
			data_A[curr_idx_A++]=val;
			//更新clock
			clock_t+=KSLen_Reduced*8;
			//显示当前收集的状态
			if((curr_idx_A) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_A*100/set_size<<"%..."<<endl;
			}	
		}
	}
	cout<<"Set A Collect complete,start to sort data set..."<<endl;
	//对数据进行排序。
	//sort(data,data+set_size,comp_struct);
	qsort(data_A,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to collect data set B, with prefix..."<<endl;
	unsigned long long curr_idx_B=0;
	while(curr_idx_B<set_size){
		//找到第一个为0的起点
		while(grain_keystream_reduce(ctx_reduce))
			clock_t++;
		grain_keystream_backward_reduce(ctx_reduce);
		//保存当前状态和clock开始判断接下来的11bit
		u8 stateByte[STATE_BYTE];
		grain_state_read_reduce(ctx_reduce,stateByte);
		unsigned long long curr_clock=clock_t;
		bool tag=true;
		for(int i=1;i<=SP;i++){
			//如果某一个状态bit为1;则退出
			if(grain_keystream_reduce(ctx_reduce)){
				tag=false;
				clock_t+=i;			//更新clock
				break;
			}
		}
		if(tag){
			//找到一个前缀为11bit全0候选截断密钥流；
			//退回到即将输出11个bit全0的那个状态
			for(int i=1;i<=SP;i++){
				grain_keystream_backward_reduce(ctx_reduce);
			}
			//clock_t+=SP;
			Online_Data_Reduce val;
			u8 keyStream_R[KSLen_Reduced];
			ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //会进行KSLen_Reduced*8个Grain tick;
			for(int j=0;j<KSLen_Reduced;j++){
				val.KS[j]=keyStream_R[j];
			}
			for(int j=0;j<STATE_BYTE;j++){
				val.state[j]=stateByte[j];
			}
			val.clock_t=curr_clock;
			data_B[curr_idx_B++]=val;
			//更新clock
			clock_t+=KSLen_Reduced*8;
			//显示当前收集的状态
			if((curr_idx_B) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_B*100/set_size<<"%..."<<endl;
			}
		}
	}
	cout<<"Set B Collect complete,start to sort data set..."<<endl;
	//对数据进行排序。
	//sort(data,data+set_size,comp_struct);
	qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to find collision in the precomputed table....using Strategy II"<<endl;
}
//stategy II 和find_near_collision_v2_no_prefix一模一样
//适合于data_A和data_B中重复元素很多的情况
bool find_near_collision_v2_with_prefix(u32 d,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,unsigned long long set_size){
	//string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)"+FILE_SUFFIX+WITH_PREFIX+"\\";
	//建立输入文件路径
	string part="Grain_(l,d)_(";
	string curr_DIR=DIR_REDUCE_V3+part+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")"+
		FILE_SUFFIX+WITH_PREFIX+"_KSD_"+int_2_string(MAX_KSD)+"_HM_"+int_2_string(MAX_KSD_HM)
		+"_N_"+int_2_string(STATE_NUM)+"\\";
	for(int i=0;i<set_size;i=find_end(data_A,i,set_size-1,data_A[i])+1){
		if((i+1) % 5000 ==0){
			cout<<"Collision finding proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
		}
		//cout<<"i:"<<i<<endl;
		for(int j=0;j<set_size;j=find_end(data_B,j,set_size-1,data_B[j])+1){
			//记录当前输出差分 
			//cout<<"  j:"<<j<<endl;
			//cout<<"  find(j):"<<find_end(data_B,0,set_size-1,data_B[j])<<endl;
			u8 curr_KS_Diff[KSLen_Reduced];
			for(int k=0;k<KSLen_Reduced;k++)
				curr_KS_Diff[k]=((data_A[i]).KS[k])^((data_B[j]).KS[k]);
			//根据当前输出差分查表，并在表中寻找匹配的内部状态差分。
			string tableName=char2HexString(curr_KS_Diff,KSLen_Reduced);
			tableName=curr_DIR+tableName+".txt";
			ifstream infile;
			infile.open(tableName.c_str());
			if(infile){
				//小组内部的元素进行异或
				long long beg_A,end_A;
				beg_A=i;
				end_A=find_end(data_A,i,set_size-1,data_A[i]);

				long long beg_B,end_B;
				beg_B=j;
				end_B=find_end(data_B,j,set_size-1,data_B[j]);
				for(;beg_A<=end_A;beg_A++){
					for(;beg_B<=end_B;beg_B++){
						//接下来在KSD中保存的ISD中寻找匹配的内部状态
						//记录当前输入差分
						u8 curr_state_Diff[STATE_BYTE];
						for(int k=0;k<STATE_BYTE;k++)
							curr_state_Diff[k]=((data_A[beg_A]).state[k])^((data_B[beg_B]).state[k]);
						//因为保存的内部状态的差分中NFSR[10]~NFSR[20]是全0的，所以
						//我们需要预先将curr_state_Diff的这些位置置为0，然后再进行比较
						curr_state_Diff[1]&=0x03;
						curr_state_Diff[2]&=0xe0;
						//接下来寻找匹配的内部状态差分
						char val[2048];
						while(infile.getline(val,sizeof(val))){
							string str(val);
							//extract cube size
							string::size_type pos=str.find(" ");
							string str_state_Diff=str.substr(0,pos);
							if(state_comp(curr_state_Diff,STATE_BYTE,str_state_Diff))
								return true;
						}
					}
				}
			}else{
			}
			infile.close();
		}
	}
	cout<<"Collision finding complete...fail to find match."<<endl;
	return false;
}
//改进版的find near collision with prefix  适合于data_A和data_B中重复元素不多的情况
bool find_near_collision_v2_with_prefix_imp(u32 d,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,unsigned long long set_size){
	//string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)"+FILE_SUFFIX+WITH_PREFIX+"\\";
	//建立输入文件路径
	string part="Grain_(l,d)_(";
	string curr_DIR=DIR_REDUCE_V2+part+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")"+
		FILE_SUFFIX+WITH_PREFIX+"_KSD_"+int_2_string(MAX_KSD)+"_N_"+int_2_string(STATE_NUM)+"\\";
	for(int i=0;i<set_size;i++){
		if((i+1) % 10000 ==0){
			cout<<"Collision finding proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
		}
		//cout<<"i:"<<i<<endl;
		for(int j=0;j<set_size;j++){
			//记录当前输出差分 
			u8 curr_KS_Diff[KSLen_Reduced];
			for(int k=0;k<KSLen_Reduced;k++)
				curr_KS_Diff[k]=((data_A[i]).KS[k])^((data_B[j]).KS[k]);
			//根据当前输出差分查表，并在表中寻找匹配的内部状态差分。
			string tableName=char2HexString(curr_KS_Diff,KSLen_Reduced);
			tableName=curr_DIR+tableName+".txt";
			ifstream infile;
			infile.open(tableName.c_str());
			if(infile){
				//接下来在KSD中保存的ISD中寻找匹配的内部状态
				//记录当前输入差分
				u8 curr_state_Diff[STATE_BYTE];
				for(int k=0;k<STATE_BYTE;k++)
					curr_state_Diff[k]=((data_A[i]).state[k])^((data_B[j]).state[k]);
				//因为保存的内部状态的差分中NFSR[10]~NFSR[20]是全0的，所以
				//我们需要预先将curr_state_Diff的这些位置置为0，然后再进行比较
				curr_state_Diff[1]&=0x03;
				curr_state_Diff[2]&=0xe0;
				//接下来寻找匹配的内部状态差分
				char val[2048];
				while(infile.getline(val,sizeof(val))){
					string str(val);
					//extract cube size
					string::size_type pos=str.find(" ");
					string str_state_Diff=str.substr(0,pos);
					if(state_comp(curr_state_Diff,STATE_BYTE,str_state_Diff))
						return true;
				}
			}
			infile.close();
		}
	}
	cout<<"Collision finding complete...fail to find match."<<endl;
	return false;
}