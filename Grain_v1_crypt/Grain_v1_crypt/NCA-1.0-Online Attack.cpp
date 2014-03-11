/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of online stage in NCA-1.0 
*/

#include "stdafx.h"
#include "head.h"


bool online_attack(){
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
	bool res=collect_sets(ctx_reduce,1,12);
	end_cal(time);
	printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);
	//����ʱ�̺ͱ�����ڲ�״̬���Լ��������Կ���Ƿ�Ե���

	delete [] key_R;
	delete [] IV_R;
	//delete ctx_reduce;

	return res;
}
/*
	b:������֤����Կ���ĳ���
	size:���ɼ��ϵĴ�С��Ϊ2��ָ����
	����汾û�б��漯����b���ȵ���֤����
	Ҫע��ṹ���ָ����ڴ�й¶
	Ϊ��ģ�⣬���ǳ��˼�¼����ض���Կ����ʱ���⣬����¼���������Կ�����ڲ�״̬
*/
bool collect_sets(ECRYPT_ctx_reduce* ctx_reduce,u32 b,double size){
	//���㼯�ϵĴ�С
	unsigned long long set_size=ceil(pow((double)2,size));
	//��ʼ��Grain tick
	unsigned long long clock_t=0;
	//��������  ks_t_state
	//vector<string> data;
	Online_Data_Reduce *data_A=new Online_Data_Reduce[set_size];
	Online_Data_Reduce *data_B=new Online_Data_Reduce[set_size];
	//�ռ�����A������
	cout<<"Data set size:2^{"<<size<<"}"<<endl;
	cout<<"Start to collect data set A..."<<endl;
	for(unsigned long long i=0;i<set_size;i++){
		//Online_Data_Reduce* val=new Online_Data_Reduce;
		Online_Data_Reduce val;
		u8 keyStream_R[KSLen_Reduced];
		u8 stateByte[STATE_BYTE];
		//ÿ��20000�Σ�����Ѵ��������
		if((i+1) % 20000 ==0){
			cout<<"proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
		}
		grain_state_read_reduce(ctx_reduce,stateByte);
		for(int j=0;j<STATE_BYTE;j++){
			val.state[j]=stateByte[j];
		}
		ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //�����KSLen_Reduced*8��Grain tick;
		for(int j=0;j<KSLen_Reduced;j++){
			val.KS[j]=keyStream_R[j];
		}
		val.clock_t=clock_t;
		data_A[i]=val;
		clock_t+=KSLen_Reduced*8;
		//delete val;
	}
	cout<<"Set A Collect complete,start to sort data set..."<<endl;
	//�����ݽ�������
	//sort(data,data+set_size,comp_struct);
	qsort(data_A,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to collect data set B..."<<endl;
	for(unsigned long long i=0;i<set_size;i++){
		//Online_Data_Reduce* val=new Online_Data_Reduce;
		Online_Data_Reduce val;
		u8 keyStream_R[KSLen_Reduced];
		u8 stateByte[STATE_BYTE];
		//ÿ��20000�Σ�����Ѵ��������
		if((i+1) % 20000 ==0){
			cout<<"Data collect proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
		}
		grain_state_read_reduce(ctx_reduce,stateByte);
		for(int j=0;j<STATE_BYTE;j++){
			val.state[j]=stateByte[j];
		}
		ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);  //�����KSLen_Reduced*8��Grain tick;
		for(int j=0;j<KSLen_Reduced;j++){
			val.KS[j]=keyStream_R[j];
		}
		val.clock_t=clock_t;
		data_B[i]=val;
		clock_t+=KSLen_Reduced*8;
		//delete val;
	}
	cout<<"Set B Collect complete,start to sort data set..."<<endl;
	//�����ݽ�������
	//sort(data,data+set_size,comp_struct);
	qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	cout<<"Start to find collision in the precomputed table....using Strategy II"<<endl;
	//Ȼ��Ѱ��ƥ��
	bool res=find_near_collision(data_A,data_B,set_size);
	/*//�������
	for(int i=0;i<set_size;i++){
		Online_Data_Reduce *val=&data[i];
		unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
		for(int j=0;j<KSLen_Reduced;j++){
		//	printf("%x",val->KS[j]);
		}
		printf("%u",lval);
		printf("_");
		printf("%d",val->clock_t);
		printf("_");
		for(int j=0;j<STATE_BYTE;j++){
			printf("%x",val->state[j]);
		}
		printf("\n");
	}*/
	
	//������������

	delete [] data_A;
	delete [] data_B;
	return res;
}
//Strategy II
bool find_near_collision(Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size){
	string subdir="Grain_(l,d)_("+int_2_string(KSLen_Reduced)+",4)"+
		FILE_SUFFIX+"\\";
	for(int i=0;i<set_size;i++){
		if((i+1) % 1000 ==0){
			cout<<"Collision finding proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
		}
		Online_Data_Reduce val_A=data_A[i];
		for(int j=0;j<set_size;j++){
			Online_Data_Reduce val_B=data_B[j];
			//��¼��ǰ������
			u8 curr_state_Diff[STATE_BYTE];
			for(int k=0;k<STATE_BYTE;k++)
				curr_state_Diff[k]=val_A.state[k]^val_B.state[k];
			//��¼��ǰ������
			u8 curr_KS_Diff[KSLen_Reduced];
			for(int k=0;k<KSLen_Reduced;k++)
				curr_KS_Diff[k]=val_A.KS[k]^val_B.KS[k];
			//���ݵ�ǰ�����ֲ�����ڱ���Ѱ��ƥ����ڲ�״̬��֡�
			string tableName=char2HexString(curr_KS_Diff,KSLen_Reduced);
			tableName=DIR_REDUCE_V1+subdir+tableName+".txt";
			ifstream infile;
			infile.open(tableName.c_str());
			if(infile){
				char val[2048];
				while(infile.getline(val,sizeof(val))){
					string str(val);
					//extract cube size
					string::size_type pos=str.find(" ");
					string str_state_Diff=str.substr(0,pos);
					if(state_comp(curr_state_Diff,STATE_BYTE,str_state_Diff))
						return true;
				}
			}else{
				cout<<"�ļ�:"<<tableName<<"û���ҵ�."<<endl;
			}
			//cout<<"file fail to load."<<endl;	
			infile.close();
		}
	}
	cout<<"Collision finding complete...fail to find match."<<endl;
	return false;
}
