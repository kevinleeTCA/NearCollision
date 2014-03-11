/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of online stage in NCA-2.0 
*/

#include "stdafx.h"
#include "head.h"

/*
	��ȷ�����������ֵ�ʱ��ֻ��Ҫƥ��53bit���ڲ�״̬���ɣ��������Կ����������ʣ�µ�11bit���ڲ�״̬���ùܡ�
	�����Ͻ׶�ѡȡ����Կ����Ӧ��ʱ�̣�Ӧ���������11bit֮ǰ�ĵ��Ǹ�ʱ�̡��ڲ�״̬���Ҳ���Ǹ�ʱ�̵ġ�
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
	//�����ռ����ݲ��������������ܳ���2^{30}�������ڴ�᲻���ã��͵ÿ��Ƕ�дӲ�̺�������
	//collect_sets_v2_no_prefix(ctx_reduce,data_A,data_B,1,set_size);
	collect_sets_v2_with_prefix(ctx_reduce,data_A,data_B,1,set_size);
	//����Ѱ��near collision
	//result=find_near_collision_v2_no_prefix(data_A,data_B,set_size);
	result=find_near_collision_v2_with_prefix_imp(d,data_A,data_B,set_size);
	end_cal(time);
	printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);
	////����collect���ݵ���ȷ��  ǰ׺�Ƿ�Ϊȫ0����׺�Ƿ��ܹ�ƥ����ϣ���ǰ״̬�Ƿ��ܹ�ƥ����ϡ�
	
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
	//cout<<"�������һ�����������ǰ׺�������Ƿ�ȫΪ11��0"<<endl;
	//unsigned long long test_clock=data_A[15].clock_t;
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
	////grain_state_load_reduce(ctx_reduce_test,test_state);
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
	b:������֤����Կ���ĳ���
	Ҫע��ṹ���ָ����ڴ�й¶
	Ϊ��ģ�⣬���ǳ��˼�¼����ض���Կ����ʱ���⣬����¼���������Կ�����ڲ�״̬
	��¼��11��bit֮�����Կ���ض�
*/
void collect_sets_v2_no_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
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
			//��¼��ǰ������ �����̶�ǰ׺��
			u8 curr_KS_Diff[KSLen_Reduced];
			for(int k=0;k<KSLen_Reduced;k++)
				curr_KS_Diff[k]=val_A.KS[k]^val_B.KS[k];
			//���ݵ�ǰ�����ֲ�����ڱ���Ѱ��ƥ����ڲ�״̬��֡�
			string tableName=char2HexString(curr_KS_Diff,KSLen_Reduced);
			tableName=DIR_REDUCE_V2+subdir+tableName+".txt";
			ifstream infile;
			infile.open(tableName.c_str());
			if(infile){
				//��¼��ǰ������
				u8 curr_state_Diff[STATE_BYTE];
				for(int k=0;k<STATE_BYTE;k++)
					curr_state_Diff[k]=val_A.state[k]^val_B.state[k];
				//��Ϊ������ڲ�״̬�Ĳ����NFSR[10]~NFSR[20]��ȫ0�ģ�����
				//������ҪԤ�Ƚ�curr_state_Diff����Щλ����Ϊ0��Ȼ���ٽ��бȽ�
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
			//	//cout<<"�ļ�:"<<tableName<<"û���ҵ�."<<endl;
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
			if((curr_idx_A) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_A*100/set_size<<"%..."<<endl;
			}	
		}
	}
	cout<<"Set A Collect complete,start to sort data set..."<<endl;
	//�����ݽ�������
	//sort(data,data+set_size,comp_struct);
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
			if((curr_idx_B) % 20000 ==0){
				cout<<"proceed "<<setprecision(3)<<(double)curr_idx_B*100/set_size<<"%..."<<endl;
			}
		}
	}
	cout<<"Set B Collect complete,start to sort data set..."<<endl;
	//�����ݽ�������
	//sort(data,data+set_size,comp_struct);
	qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to find collision in the precomputed table....using Strategy II"<<endl;
}
//stategy II ��find_near_collision_v2_no_prefixһģһ��
//�ʺ���data_A��data_B���ظ�Ԫ�غܶ�����
bool find_near_collision_v2_with_prefix(u32 d,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,unsigned long long set_size){
	//string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)"+FILE_SUFFIX+WITH_PREFIX+"\\";
	//���������ļ�·��
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
			//��¼��ǰ������ 
			//cout<<"  j:"<<j<<endl;
			//cout<<"  find(j):"<<find_end(data_B,0,set_size-1,data_B[j])<<endl;
			u8 curr_KS_Diff[KSLen_Reduced];
			for(int k=0;k<KSLen_Reduced;k++)
				curr_KS_Diff[k]=((data_A[i]).KS[k])^((data_B[j]).KS[k]);
			//���ݵ�ǰ�����ֲ�����ڱ���Ѱ��ƥ����ڲ�״̬��֡�
			string tableName=char2HexString(curr_KS_Diff,KSLen_Reduced);
			tableName=curr_DIR+tableName+".txt";
			ifstream infile;
			infile.open(tableName.c_str());
			if(infile){
				//С���ڲ���Ԫ�ؽ������
				long long beg_A,end_A;
				beg_A=i;
				end_A=find_end(data_A,i,set_size-1,data_A[i]);

				long long beg_B,end_B;
				beg_B=j;
				end_B=find_end(data_B,j,set_size-1,data_B[j]);
				for(;beg_A<=end_A;beg_A++){
					for(;beg_B<=end_B;beg_B++){
						//��������KSD�б����ISD��Ѱ��ƥ����ڲ�״̬
						//��¼��ǰ������
						u8 curr_state_Diff[STATE_BYTE];
						for(int k=0;k<STATE_BYTE;k++)
							curr_state_Diff[k]=((data_A[beg_A]).state[k])^((data_B[beg_B]).state[k]);
						//��Ϊ������ڲ�״̬�Ĳ����NFSR[10]~NFSR[20]��ȫ0�ģ�����
						//������ҪԤ�Ƚ�curr_state_Diff����Щλ����Ϊ0��Ȼ���ٽ��бȽ�
						curr_state_Diff[1]&=0x03;
						curr_state_Diff[2]&=0xe0;
						//������Ѱ��ƥ����ڲ�״̬���
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
//�Ľ����find near collision with prefix  �ʺ���data_A��data_B���ظ�Ԫ�ز�������
bool find_near_collision_v2_with_prefix_imp(u32 d,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,unsigned long long set_size){
	//string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)"+FILE_SUFFIX+WITH_PREFIX+"\\";
	//���������ļ�·��
	string part="Grain_(l,d)_(";
	string curr_DIR=DIR_REDUCE_V2+part+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")"+
		FILE_SUFFIX+WITH_PREFIX+"_KSD_"+int_2_string(MAX_KSD)+"_N_"+int_2_string(STATE_NUM)+"\\";
	for(int i=0;i<set_size;i++){
		if((i+1) % 10000 ==0){
			cout<<"Collision finding proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
		}
		//cout<<"i:"<<i<<endl;
		for(int j=0;j<set_size;j++){
			//��¼��ǰ������ 
			u8 curr_KS_Diff[KSLen_Reduced];
			for(int k=0;k<KSLen_Reduced;k++)
				curr_KS_Diff[k]=((data_A[i]).KS[k])^((data_B[j]).KS[k]);
			//���ݵ�ǰ�����ֲ�����ڱ���Ѱ��ƥ����ڲ�״̬��֡�
			string tableName=char2HexString(curr_KS_Diff,KSLen_Reduced);
			tableName=curr_DIR+tableName+".txt";
			ifstream infile;
			infile.open(tableName.c_str());
			if(infile){
				//��������KSD�б����ISD��Ѱ��ƥ����ڲ�״̬
				//��¼��ǰ������
				u8 curr_state_Diff[STATE_BYTE];
				for(int k=0;k<STATE_BYTE;k++)
					curr_state_Diff[k]=((data_A[i]).state[k])^((data_B[j]).state[k]);
				//��Ϊ������ڲ�״̬�Ĳ����NFSR[10]~NFSR[20]��ȫ0�ģ�����
				//������ҪԤ�Ƚ�curr_state_Diff����Щλ����Ϊ0��Ȼ���ٽ��бȽ�
				curr_state_Diff[1]&=0x03;
				curr_state_Diff[2]&=0xe0;
				//������Ѱ��ƥ����ڲ�״̬���
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