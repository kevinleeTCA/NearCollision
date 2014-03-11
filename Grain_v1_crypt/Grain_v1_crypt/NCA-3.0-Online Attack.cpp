/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of online stage in NCA-3.0 
*/

#include "stdafx.h"
#include "head.h"

bool online_attack_v3(u32 d){
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
	//首先收集数据并排序数据量不能超过2^{30}，否则内存会不够用，就得考虑读写硬盘和外排序
	//collect_sets_v3_no_prefix(ctx_reduce,data_A,data_B,1,set_size);
	collect_sets_v3_with_prefix(ctx_reduce,data_A,data_B,1,set_size);
	//result=find_near_collision_v3_no_prefix(data_A,data_B,set_size);
	result=find_near_collision_v3_with_prefix(d,data_A,data_B,set_size);
	//接着寻找near collision
	end_cal(time);
	printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);
	

	//测试数据量中KS字段重复率有多高
	//string fileName_A="DataAnalysis_A.txt";
	//string dir=DIR_REDUCE_V3+fileName_A;
	//ofstream outfile;
	//outfile.open(dir.c_str(),ofstream::app);
	////outfile<<fixed<<showpoint;
	//if(outfile){
	//	for(int i=0;i<set_size-1;i++){
	//		Online_Data_Reduce *val=&data_A[i];
	//		unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	//		outfile<<lval<<endl;
	//	}
	//}
	//outfile.close();
	//string fileName_B="DataAnalysis_B.txt";
	//dir=DIR_REDUCE_V3+fileName_B;
	//outfile.open(dir.c_str(),ofstream::app);
	////outfile<<fixed<<showpoint;
	//if(outfile){
	//	for(int i=0;i<set_size-1;i++){
	//		Online_Data_Reduce *val=&data_B[i];
	//		unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	//		outfile<<lval<<endl;
	//	}
	//}
	//outfile.close();


	//for(int i=0;i<set_size;i++){
	//	Online_Data_Reduce *val=&data_A[i];
	//	//unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	//	for(int j=0;j<KSLen_Reduced;j++){
	//		printf("%02x",val->KS[j]);
	//	}
	//	//printf("%u",lval);
	//	printf("_");
	//	printf("%d",val->clock_t);
	//	printf("_");
	//	for(int j=0;j<STATE_BYTE;j++){
	//		printf("%x",val->state[j]);
	//	}
	//	printf("\n");
	//}
	//cout<<endl;


	//for(int i=0;i<set_size;i++){
	//	Online_Data_Reduce *val=&data_B[i];
	//	//unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	//	for(int j=0;j<KSLen_Reduced;j++){
	//		printf("%02x",val->KS[j]);
	//	}
	//	//printf("%u",lval);
	//	printf("_");
	//	printf("%d",val->clock_t);
	//	printf("_");
	//	for(int j=0;j<STATE_BYTE;j++){
	//		printf("%x",val->state[j]);
	//	}
	//	printf("\n");
	//}
	//cout<<"随机测试一个样本的输出前缀，看看是否全为11个0"<<endl;
	//unsigned long long test_clock=data_B[set_size-1].clock_t;
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
	//for(int j=0;j<KSLen_Reduced;j++){
	//		printf("%02x",KS_test[j]);
	//}

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
	这个版本和v2的一模一样
*/
void collect_sets_v3_no_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
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
	cout<<"Start to find collision in the precomputed table....using Strategy I"<<endl;
}
/*
	Strategy I
*/
bool find_near_collision_v3_no_prefix(Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size){
	//找到所有重量小于MAX_KSD_HM的KSD，并以16进制命名在NCA-3.0指定的路径中找到KSD table
	//for()
	string fileSuffix="*.txt";
	string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)_no_prefix\\";
	string fileDir=DIR_REDUCE_V3+subdir+fileSuffix;
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
		//cout<<"Proceed KSD:"<<ksd<<endl;
		//用Strategy1来寻找碰撞
		if(find_collision_sub_routine(ksd,DIR_REDUCE_V3+subdir+fileName,data_A,data_B,set_size)){
			_findclose(longf);
			return true;
		}
		while(_findnext(longf,&file)==0){
			fileName=file.name;
			//解析出KSD
			//string::size_type pos=fileName.find(".");这句话不需要是因为所有的fileName格式都一样
			ksd=fileName.substr(0,pos);
			//cout<<"Proceed KSD:"<<ksd<<endl;
			if(find_collision_sub_routine(ksd,DIR_REDUCE_V3+subdir+fileName,data_A,data_B,set_size)){
				_findclose(longf);
				return true;
			}
		}
	}
	_findclose(longf);
	return false;
}

//针对with prefix优化后的版本，适合于data_A和data_B中重复元素很多的情况
bool find_collision_sub_routine(string KSD,string tableName, Online_Data_Reduce *data_A
	,Online_Data_Reduce *data_B,unsigned long long set_size){
	//首先将fileName下的所有数据load进内存  可以将ISD换成unsigned long long类型的数组，load完后排序来提高速度
	set<string> ISD;
	ifstream infile;
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
		return false;
	}
	//将KSD转换成u8和A数据集合中的元素异或 然后在B数据集合中寻找碰撞
	u8 KS_byte[KSLen_Reduced];
	string2byte(KS_byte,KSLen_Reduced,KSD);	//这一步可能比较费时
	for(int i=0;i<set_size;){
		//构造一个临时的Online_Data_Reduce,state和clock_t复制val_A的。 用于比较
		//cout<<"  i:"<<i<<endl;
		Online_Data_Reduce temp;
		//和A的数据进行异或
		for(int j=0;j<KSLen_Reduced;j++)
			temp.KS[j]=KS_byte[j]^((data_A[i]).KS[j]);
		//在B中寻找碰撞（有序数组的二分查找,B中可能会出现重复的KS，要对每个KS都check） 并在ISD中匹配内部状态差分
		//找到最小的下标beg,使得data_B[beg].KS=temp.KS，找到最大的下标end，使得data_B[end]=temp.KS
		long long beg,end;
		beg=find_begin(data_B,0,set_size-1,temp);
		if(beg!=-1){
			end=find_end(data_B,beg,set_size-1,temp);
			//在B中找到了碰撞
			//然后对当前所有具有相同KS属性的data_A[i]和data_B中从 beg到end的的状态的state字段进行异或保存在curr_state_Diff中
			long long beg_A,end_A;
			beg_A=i;
			end_A=find_end(data_A,i,set_size-1,data_A[i]);
			for(;beg_A<=end_A;beg_A++){
				for(;beg<=end;beg++){
					//首先计算状态差分
					u8 curr_state_Diff[STATE_BYTE];
					for(int j=0;j<STATE_BYTE;j++)
						curr_state_Diff[j]=((data_A[beg_A]).state[j])^((data_B[beg]).state[j]);
					//我们需要预先将curr_state_Diff的这些位置置为0，然后再进行比较
					curr_state_Diff[1]&=0x03;
					curr_state_Diff[2]&=0xe0;
					if(ISD.find(char2HexString(curr_state_Diff,STATE_BYTE))!=ISD.end()){
						//cout<<"beg A:"<<beg_A<<endl;
						//cout<<"beg B:"<<beg<<endl;
						return true;
					}
				}
			}
			i=end_A+1;
		}else{
			//与data_A[i]的KS异或后没有在B中找到匹配
			long long end_A=find_end(data_A,i,set_size-1,data_A[i]);
			//下标i移动到下一个组的第一个状态，因为A是有序的所以+1一定是下一组的第一个状态 或者超过数组边界
			i=end_A+1;
		}
	}
	return false;
}

//下表逐步增加的版本，针对with prefix优化后的版本  适合于data_A和data_B中重复元素不多的情况
bool find_collision_sub_routine_imp(string KSD,string tableName, Online_Data_Reduce *data_A
	,Online_Data_Reduce *data_B,unsigned long long set_size){
	//首先将fileName下的所有数据load进内存  可以将ISD换成unsigned long long类型的数组，load完后排序来提高速度
	set<string> ISD;
	ifstream infile;
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
		return false;
	}
	infile.close();
	//将KSD转换成u8和A数据集合中的元素异或 然后在B数据集合中寻找碰撞
	u8 KS_byte[KSLen_Reduced];
	string2byte(KS_byte,KSLen_Reduced,KSD);	//这一步可能比较费时
	for(int i=0;i<set_size;i++){
		//构造一个临时的Online_Data_Reduce,state和clock_t复制val_A的。 用于比较
		Online_Data_Reduce temp;
		//和A的数据进行异或
		for(int j=0;j<KSLen_Reduced;j++)
			temp.KS[j]=KS_byte[j]^((data_A[i]).KS[j]);
		//在B中寻找碰撞（有序数组的二分查找,B中可能会出现重复的KS，要对每个KS都check） 并在ISD中匹配内部状态差分
		//找到最小的下标beg,使得data_B[beg].KS=temp.KS，找到最大的下标end，使得data_B[end]=temp.KS
		long long beg,end;
		beg=find_begin(data_B,0,set_size-1,temp);
		if(beg!=-1){
			end=find_end(data_B,beg,set_size-1,temp);
			//在B中找到了碰撞
			for(;beg<=end;beg++){
				//首先计算状态差分
				u8 curr_state_Diff[STATE_BYTE];
				for(int j=0;j<STATE_BYTE;j++)
					curr_state_Diff[j]=((data_A[i]).state[j])^((data_B[beg]).state[j]);
				//我们需要预先将curr_state_Diff的这些位置置为0，然后再进行比较
				curr_state_Diff[1]&=0x03;
				curr_state_Diff[2]&=0xe0;
				if(ISD.find(char2HexString(curr_state_Diff,STATE_BYTE))!=ISD.end()){
					return true;
				}
			}
		}
	}
	return false;
}
//找到最小的下标beg,使得data_B[beg].KS=temp.KS，
long long find_begin(Online_Data_Reduce *data_B,long long i,long long j,Online_Data_Reduce val){
	if(i>j)
		return -1;
	while(i<j-1){
		long long mid=i+(j-i)/2;
		if(comp_struct(&val,&data_B[mid])<=0)
			j=mid;
		else
			i=mid;
	}
	if(comp_struct(&val,&data_B[i])==0)
		return i;
	else if(comp_struct(&val,&data_B[j])==0)
		return j;
	else 
		return -1;
	//if(i>=j){	
	//	if(comp_struct(&val,&data_B[j])==0){
	//		return j;
	//	}else{
	//		return -1;
	//	}
	//}
	//long long mid=i+(j-i)/2;  //注意不能写成mid=(i+j)/2，容易产生加法溢出
	//if(comp_struct(&val,&data_B[mid])==0)		//如果相等，继续在左边找，
	//	return find_begin(data_B,i,mid,val);
	//else if(comp_struct(&val,&data_B[mid])<0)
	//	return find_begin(data_B,i,mid-1,val);
	//else
	//	return find_begin(data_B,mid+1,j,val);
}
//找到最大的下标end，使得data_B[end]=temp.KS
long long find_end(Online_Data_Reduce *data_B,long long i,long long j,Online_Data_Reduce val){
	if(i>j)
		return -1;
	while(i<j-1){
		long long mid=i+(j-i)/2;
		if(comp_struct(&val,&data_B[mid])>=0)
			i=mid;
		else
			j=mid;
	}
	if(comp_struct(&val,&data_B[j])==0)
		return j;
	else if(comp_struct(&val,&data_B[i])==0)
		return i;
	else 
		return -1;
	//if(i>=j || i==j-1){
	//	if(comp_struct(&val,&data_B[j])==0)
	//		return j;
	//	else if(comp_struct(&val,&data_B[i])==0)
	//		return i;
	//	else 
	//		return -1;
	//}
	//long long mid=i+(j-i)/2;
	//if(comp_struct(&val,&data_B[mid])==0)		//如果相等，继续在右边找，
	//	return find_begin(data_B,mid,j,val);
	//else if(comp_struct(&val,&data_B[mid])<0)
	//	return find_begin(data_B,i,mid-1,val);
	//else
	//	return find_begin(data_B,mid+1,j,val);
}

void collect_sets_v3_with_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
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
			/*if((curr_idx_A) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_A*100/set_size<<"%..."<<endl;
			}	*/
		}
	}
	cout<<"Set A Collect complete,start to sort data set..."<<endl;
	//对数据进行排序。
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
			/*if((curr_idx_B) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_B*100/set_size<<"%..."<<endl;
			}*/
		}
	}
	cout<<"Set B Collect complete,start to sort data set..."<<endl;
	//对数据进行排序。
	qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to find collision in the precomputed table....using Strategy I"<<endl;
}

/*
	Strategy I 和no_prefix的版本一样
*/
bool find_near_collision_v3_with_prefix(u32 d,Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size){
	/*string fileSuffix="*.txt";
	string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)\\";
	string fileDir=DIR_REDUCE_V3+subdir+fileSuffix;*/
	//建立输入文件路径
	string part="Grain_(l,d)_(";
	string curr_DIR=DIR_REDUCE_V3+part+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")"+
		FILE_SUFFIX+WITH_PREFIX+"_KSD_"+int_2_string(MAX_KSD)+"_HM_"+int_2_string(MAX_KSD_HM)
		+"_N_"+int_2_string(STATE_NUM)+"\\";
	string fileSuffix="*.txt";
	string fileDir=curr_DIR+fileSuffix;
	unsigned long long proceed=0;
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
		//cout<<"Proceed KSD:"<<ksd<<endl;
		//用Strategy1来寻找碰撞
		//cout<<"filename:"<<fileName<<endl;
		if(find_collision_sub_routine(ksd,curr_DIR+fileName,data_A,data_B,set_size)){
			_findclose(longf);
			return true;
		}
		while(_findnext(longf,&file)==0){
			if((++proceed) % 100 ==0){
				cout<<"proceed "<<setprecision(3)<<proceed<<endl;
			}
			fileName=file.name;
			//cout<<"filename:"<<fileName<<endl;
			//解析出KSD
			//string::size_type pos=fileName.find(".");这句话不需要是因为所有的fileName格式都一样
			ksd=fileName.substr(0,pos);
			if(find_collision_sub_routine(ksd,curr_DIR+fileName,data_A,data_B,set_size)){
				_findclose(longf);
				return true;
			}
		}
	}
	_findclose(longf);
	return false;
}

