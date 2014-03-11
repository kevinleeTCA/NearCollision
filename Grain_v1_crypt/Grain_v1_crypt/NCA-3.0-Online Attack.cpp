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
	//�����ռ����ݲ��������������ܳ���2^{30}�������ڴ�᲻���ã��͵ÿ��Ƕ�дӲ�̺�������
	//collect_sets_v3_no_prefix(ctx_reduce,data_A,data_B,1,set_size);
	collect_sets_v3_with_prefix(ctx_reduce,data_A,data_B,1,set_size);
	//result=find_near_collision_v3_no_prefix(data_A,data_B,set_size);
	result=find_near_collision_v3_with_prefix(d,data_A,data_B,set_size);
	//����Ѱ��near collision
	end_cal(time);
	printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);
	

	//������������KS�ֶ��ظ����ж��
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
	//cout<<"�������һ�����������ǰ׺�������Ƿ�ȫΪ11��0"<<endl;
	//unsigned long long test_clock=data_B[set_size-1].clock_t;
	//cout<<test_clock<<endl;
	//ECRYPT_ctx_reduce* ctx_reduce_test=new ECRYPT_ctx_reduce;
	//ECRYPT_keysetup_reduce(ctx_reduce_test,key_R,32,24);
	//ECRYPT_ivsetup_reduce(ctx_reduce_test,IV_R);
	//for(unsigned long long i=0;i<test_clock;i++){
	//	grain_keystream_reduce(ctx_reduce_test);
	//}
	////����״̬�ܷ�ƥ�����
	//u8 test_state[STATE_BYTE];
	//grain_state_read_reduce(ctx_reduce_test,test_state);
	//for(int j=0;j<STATE_BYTE;j++){
	//	printf("%x",test_state[j]);
	//}
	//printf("\n");
	////�������ǰ׺�ǲ���ȫ0
	//for(int i=0;i<SP;i++){
	//	printf("%d",grain_keystream_reduce(ctx_reduce_test));
	//}
	//cout<<endl;
	////����with prefix�Ż��õ�
	//for(int i=1;i<=SP;i++){
	//	grain_keystream_backward_reduce(ctx_reduce_test);
	//}
	////������׺�ܲ���ƥ�����
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
	b:������֤����Կ���ĳ���
	Ҫע��ṹ���ָ����ڴ�й¶
	Ϊ��ģ�⣬���ǳ��˼�¼����ض���Կ����ʱ���⣬����¼���������Կ�����ڲ�״̬
	��¼��11��bit֮�����Կ���ض�
	����汾��v2��һģһ��
*/
void collect_sets_v3_no_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,u32 b,unsigned long long set_size){
	cout<<"Start to collect data set A, no prefix..."<<endl;
	unsigned long long clock_t=0;
	unsigned long long curr_idx_A=0;
	while(curr_idx_A<set_size){
		//�ҵ���һ��Ϊ0�����
		while(grain_keystream_reduce(ctx_reduce)){
			clock_t++;
		}
		grain_keystream_backward_reduce(ctx_reduce);
			
		//���浱ǰ״̬��clock ��ʼ�жϽ�������11bit
		u8 stateByte[STATE_BYTE];
		grain_state_read_reduce(ctx_reduce,stateByte);
		unsigned long long curr_clock=clock_t;
		bool tag=true;
		for(int i=1;i<=SP;i++){
			//���ĳһ��״̬bitΪ1;���˳�
			if(grain_keystream_reduce(ctx_reduce)){
				tag=false;
				clock_t+=i;			//����clock
				break;
			}
		}
		if(tag){
			//�ҵ�һ��ǰ׺Ϊ11bitȫ0��ѡ�ض���Կ����
			clock_t+=SP;
			Online_Data_Reduce val;
			u8 keyStream_R[KSLen_Reduced];
			ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //�����KSLen_Reduced*8��Grain tick;
			for(int j=0;j<KSLen_Reduced;j++){
				val.KS[j]=keyStream_R[j];
			}
			for(int j=0;j<STATE_BYTE;j++){
				val.state[j]=stateByte[j];
			}
			val.clock_t=curr_clock;
			data_A[curr_idx_A++]=val;
			//��ʾ��ǰ�ռ���״̬
			if((curr_idx_A) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_A*100/set_size<<"%..."<<endl;
			}
			clock_t+=KSLen_Reduced*8;
		}
	}
	cout<<"Set A Collect complete,start to sort data set..."<<endl;
	//�����ݽ�������
	//sort(data,data+set_size,comp_struct);
	qsort(data_A,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to collect data set B, no prefix..."<<endl;
	unsigned long long curr_idx_B=0;
	while(curr_idx_B<set_size){
		//�ҵ���һ��Ϊ0�����
		while(grain_keystream_reduce(ctx_reduce))
			clock_t++;
		grain_keystream_backward_reduce(ctx_reduce);
		//���浱ǰ״̬��clock��ʼ�жϽ�������11bit
		u8 stateByte[STATE_BYTE];
		grain_state_read_reduce(ctx_reduce,stateByte);
		unsigned long long curr_clock=clock_t;
		bool tag=true;
		for(int i=1;i<=SP;i++){
			//���ĳһ��״̬bitΪ1;���˳�
			if(grain_keystream_reduce(ctx_reduce)){
				tag=false;
				clock_t+=i;			//����clock
				break;
			}
		}
		if(tag){
			//�ҵ�һ��ǰ׺Ϊ11bitȫ0��ѡ�ض���Կ����
			clock_t+=SP;
			Online_Data_Reduce val;
			u8 keyStream_R[KSLen_Reduced];
			ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //�����KSLen_Reduced*8��Grain tick;
			for(int j=0;j<KSLen_Reduced;j++){
				val.KS[j]=keyStream_R[j];
			}
			for(int j=0;j<STATE_BYTE;j++){
				val.state[j]=stateByte[j];
			}
			val.clock_t=curr_clock;
			data_B[curr_idx_B++]=val;
			//��ʾ��ǰ�ռ���״̬
			if((curr_idx_B) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_B*100/set_size<<"%..."<<endl;
			}
			//����clock
			clock_t+=KSLen_Reduced*8;
		}
	}
	cout<<"Set B Collect complete,start to sort data set..."<<endl;
	//�����ݽ�������
	//sort(data,data+set_size,comp_struct);
	qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to find collision in the precomputed table....using Strategy I"<<endl;
}
/*
	Strategy I
*/
bool find_near_collision_v3_no_prefix(Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size){
	//�ҵ���������С��MAX_KSD_HM��KSD������16����������NCA-3.0ָ����·�����ҵ�KSD table
	//for()
	string fileSuffix="*.txt";
	string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)_no_prefix\\";
	string fileDir=DIR_REDUCE_V3+subdir+fileSuffix;
	struct _finddata_t file;  
    long longf; 
	if((longf = _findfirst(fileDir.c_str(),&file))==-1L){
		cout<<"�ļ�û���ҵ�!\n"<<endl;
	}else{
		//ѭ���������к�׺Ϊ.txt���ļ�
		string fileName=file.name;
		//������KSD
		string::size_type pos=fileName.find(".");
		string ksd=fileName.substr(0,pos);
		//cout<<"Proceed KSD:"<<ksd<<endl;
		//��Strategy1��Ѱ����ײ
		if(find_collision_sub_routine(ksd,DIR_REDUCE_V3+subdir+fileName,data_A,data_B,set_size)){
			_findclose(longf);
			return true;
		}
		while(_findnext(longf,&file)==0){
			fileName=file.name;
			//������KSD
			//string::size_type pos=fileName.find(".");��仰����Ҫ����Ϊ���е�fileName��ʽ��һ��
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

//���with prefix�Ż���İ汾���ʺ���data_A��data_B���ظ�Ԫ�غܶ�����
bool find_collision_sub_routine(string KSD,string tableName, Online_Data_Reduce *data_A
	,Online_Data_Reduce *data_B,unsigned long long set_size){
	//���Ƚ�fileName�µ���������load���ڴ�  ���Խ�ISD����unsigned long long���͵����飬load�������������ٶ�
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
		cout<<"�Ҳ���"<<tableName<<"�ļ�"<<endl;
		return false;
	}
	//��KSDת����u8��A���ݼ����е�Ԫ����� Ȼ����B���ݼ�����Ѱ����ײ
	u8 KS_byte[KSLen_Reduced];
	string2byte(KS_byte,KSLen_Reduced,KSD);	//��һ�����ܱȽϷ�ʱ
	for(int i=0;i<set_size;){
		//����һ����ʱ��Online_Data_Reduce,state��clock_t����val_A�ġ� ���ڱȽ�
		//cout<<"  i:"<<i<<endl;
		Online_Data_Reduce temp;
		//��A�����ݽ������
		for(int j=0;j<KSLen_Reduced;j++)
			temp.KS[j]=KS_byte[j]^((data_A[i]).KS[j]);
		//��B��Ѱ����ײ����������Ķ��ֲ���,B�п��ܻ�����ظ���KS��Ҫ��ÿ��KS��check�� ����ISD��ƥ���ڲ�״̬���
		//�ҵ���С���±�beg,ʹ��data_B[beg].KS=temp.KS���ҵ������±�end��ʹ��data_B[end]=temp.KS
		long long beg,end;
		beg=find_begin(data_B,0,set_size-1,temp);
		if(beg!=-1){
			end=find_end(data_B,beg,set_size-1,temp);
			//��B���ҵ�����ײ
			//Ȼ��Ե�ǰ���о�����ͬKS���Ե�data_A[i]��data_B�д� beg��end�ĵ�״̬��state�ֶν�����򱣴���curr_state_Diff��
			long long beg_A,end_A;
			beg_A=i;
			end_A=find_end(data_A,i,set_size-1,data_A[i]);
			for(;beg_A<=end_A;beg_A++){
				for(;beg<=end;beg++){
					//���ȼ���״̬���
					u8 curr_state_Diff[STATE_BYTE];
					for(int j=0;j<STATE_BYTE;j++)
						curr_state_Diff[j]=((data_A[beg_A]).state[j])^((data_B[beg]).state[j]);
					//������ҪԤ�Ƚ�curr_state_Diff����Щλ����Ϊ0��Ȼ���ٽ��бȽ�
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
			//��data_A[i]��KS����û����B���ҵ�ƥ��
			long long end_A=find_end(data_A,i,set_size-1,data_A[i]);
			//�±�i�ƶ�����һ����ĵ�һ��״̬����ΪA�����������+1һ������һ��ĵ�һ��״̬ ���߳�������߽�
			i=end_A+1;
		}
	}
	return false;
}

//�±������ӵİ汾�����with prefix�Ż���İ汾  �ʺ���data_A��data_B���ظ�Ԫ�ز�������
bool find_collision_sub_routine_imp(string KSD,string tableName, Online_Data_Reduce *data_A
	,Online_Data_Reduce *data_B,unsigned long long set_size){
	//���Ƚ�fileName�µ���������load���ڴ�  ���Խ�ISD����unsigned long long���͵����飬load�������������ٶ�
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
		cout<<"�Ҳ���"<<tableName<<"�ļ�"<<endl;
		return false;
	}
	infile.close();
	//��KSDת����u8��A���ݼ����е�Ԫ����� Ȼ����B���ݼ�����Ѱ����ײ
	u8 KS_byte[KSLen_Reduced];
	string2byte(KS_byte,KSLen_Reduced,KSD);	//��һ�����ܱȽϷ�ʱ
	for(int i=0;i<set_size;i++){
		//����һ����ʱ��Online_Data_Reduce,state��clock_t����val_A�ġ� ���ڱȽ�
		Online_Data_Reduce temp;
		//��A�����ݽ������
		for(int j=0;j<KSLen_Reduced;j++)
			temp.KS[j]=KS_byte[j]^((data_A[i]).KS[j]);
		//��B��Ѱ����ײ����������Ķ��ֲ���,B�п��ܻ�����ظ���KS��Ҫ��ÿ��KS��check�� ����ISD��ƥ���ڲ�״̬���
		//�ҵ���С���±�beg,ʹ��data_B[beg].KS=temp.KS���ҵ������±�end��ʹ��data_B[end]=temp.KS
		long long beg,end;
		beg=find_begin(data_B,0,set_size-1,temp);
		if(beg!=-1){
			end=find_end(data_B,beg,set_size-1,temp);
			//��B���ҵ�����ײ
			for(;beg<=end;beg++){
				//���ȼ���״̬���
				u8 curr_state_Diff[STATE_BYTE];
				for(int j=0;j<STATE_BYTE;j++)
					curr_state_Diff[j]=((data_A[i]).state[j])^((data_B[beg]).state[j]);
				//������ҪԤ�Ƚ�curr_state_Diff����Щλ����Ϊ0��Ȼ���ٽ��бȽ�
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
//�ҵ���С���±�beg,ʹ��data_B[beg].KS=temp.KS��
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
	//long long mid=i+(j-i)/2;  //ע�ⲻ��д��mid=(i+j)/2�����ײ����ӷ����
	//if(comp_struct(&val,&data_B[mid])==0)		//�����ȣ�����������ң�
	//	return find_begin(data_B,i,mid,val);
	//else if(comp_struct(&val,&data_B[mid])<0)
	//	return find_begin(data_B,i,mid-1,val);
	//else
	//	return find_begin(data_B,mid+1,j,val);
}
//�ҵ������±�end��ʹ��data_B[end]=temp.KS
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
	//if(comp_struct(&val,&data_B[mid])==0)		//�����ȣ��������ұ��ң�
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
		//�ҵ���һ��Ϊ0�����
		while(grain_keystream_reduce(ctx_reduce))
			clock_t++;
		grain_keystream_backward_reduce(ctx_reduce);
		//���浱ǰ״̬��clock��ʼ�жϽ�������11bit
		u8 stateByte[STATE_BYTE];
		grain_state_read_reduce(ctx_reduce,stateByte);
		unsigned long long curr_clock=clock_t;
		bool tag=true;
		for(int i=1;i<=SP;i++){
			//���ĳһ��״̬bitΪ1;���˳�
			if(grain_keystream_reduce(ctx_reduce)){
				tag=false;
				clock_t+=i;			//����clock
				break;
			}
		}
		if(tag){
			//�ҵ�һ��ǰ׺Ϊ11bitȫ0��ѡ�ض���Կ����
			//�˻ص��������11��bitȫ0���Ǹ�״̬
			for(int i=1;i<=SP;i++){
				grain_keystream_backward_reduce(ctx_reduce);
			}
			//clock_t+=SP;
			Online_Data_Reduce val;
			u8 keyStream_R[KSLen_Reduced];
			ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //�����KSLen_Reduced*8��Grain tick;
			for(int j=0;j<KSLen_Reduced;j++){
				val.KS[j]=keyStream_R[j];
			}
			for(int j=0;j<STATE_BYTE;j++){
				val.state[j]=stateByte[j];
			}
			val.clock_t=curr_clock;
			data_A[curr_idx_A++]=val;
			//����clock
			clock_t+=KSLen_Reduced*8;
			//��ʾ��ǰ�ռ���״̬
			/*if((curr_idx_A) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_A*100/set_size<<"%..."<<endl;
			}	*/
		}
	}
	cout<<"Set A Collect complete,start to sort data set..."<<endl;
	//�����ݽ�������
	qsort(data_A,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to collect data set B, with prefix..."<<endl;
	unsigned long long curr_idx_B=0;
	while(curr_idx_B<set_size){
		//�ҵ���һ��Ϊ0�����
		while(grain_keystream_reduce(ctx_reduce))
			clock_t++;
		grain_keystream_backward_reduce(ctx_reduce);
		//���浱ǰ״̬��clock��ʼ�жϽ�������11bit
		u8 stateByte[STATE_BYTE];
		grain_state_read_reduce(ctx_reduce,stateByte);
		unsigned long long curr_clock=clock_t;
		bool tag=true;
		for(int i=1;i<=SP;i++){
			//���ĳһ��״̬bitΪ1;���˳�
			if(grain_keystream_reduce(ctx_reduce)){
				tag=false;
				clock_t+=i;			//����clock
				break;
			}
		}
		if(tag){
			//�ҵ�һ��ǰ׺Ϊ11bitȫ0��ѡ�ض���Կ����
			//�˻ص��������11��bitȫ0���Ǹ�״̬
			for(int i=1;i<=SP;i++){
				grain_keystream_backward_reduce(ctx_reduce);
			}
			//clock_t+=SP;
			Online_Data_Reduce val;
			u8 keyStream_R[KSLen_Reduced];
			ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //�����KSLen_Reduced*8��Grain tick;
			for(int j=0;j<KSLen_Reduced;j++){
				val.KS[j]=keyStream_R[j];
			}
			for(int j=0;j<STATE_BYTE;j++){
				val.state[j]=stateByte[j];
			}
			val.clock_t=curr_clock;
			data_B[curr_idx_B++]=val;
			//����clock
			clock_t+=KSLen_Reduced*8;
			//��ʾ��ǰ�ռ���״̬
			/*if((curr_idx_B) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_B*100/set_size<<"%..."<<endl;
			}*/
		}
	}
	cout<<"Set B Collect complete,start to sort data set..."<<endl;
	//�����ݽ�������
	qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to find collision in the precomputed table....using Strategy I"<<endl;
}

/*
	Strategy I ��no_prefix�İ汾һ��
*/
bool find_near_collision_v3_with_prefix(u32 d,Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size){
	/*string fileSuffix="*.txt";
	string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)\\";
	string fileDir=DIR_REDUCE_V3+subdir+fileSuffix;*/
	//���������ļ�·��
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
		cout<<"�ļ�û���ҵ�!\n"<<endl;
	}else{
		//ѭ���������к�׺Ϊ.txt���ļ�
		string fileName=file.name;
		//������KSD
		string::size_type pos=fileName.find(".");
		string ksd=fileName.substr(0,pos);
		//cout<<"Proceed KSD:"<<ksd<<endl;
		//��Strategy1��Ѱ����ײ
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
			//������KSD
			//string::size_type pos=fileName.find(".");��仰����Ҫ����Ϊ���е�fileName��ʽ��һ��
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

