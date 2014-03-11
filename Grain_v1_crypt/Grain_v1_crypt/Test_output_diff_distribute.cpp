
#include "stdafx.h"
#include "head.h"
//kevin edit, ��������ڴ�й¶������
/*������
L:�����ֵ����������
KSLen:�����Կ���Ľضϳ���(byte)
sam_N:���ѡ��������ΪL�������ֵĸ���
test_Num:ÿһ����ֶ�Ӧ�Ĳ�������������
*/
//ͳ��ǰ����Կ����ֵ�BW-KSD Characteristic
void inputOutputDiff(u32 L,u32 sam_N){
	srand((unsigned)time(NULL));
	rc4_setup();
	u32 average_Diff_Num=0;
	double average_Diff_prop=0.0;
	double average_KW_KSD_CH=0.0;
	map<string,u32> counter;
	for(int D=1;D<=sam_N;D++){

		//���ѡȡ160bit ״̬�Ĳ��λ�� NFSR��0~79��LFSR��80~159
		u32* pos=new u32[L]();
		for(int j=0;j<L;j++){
			//pos[j]=rc4() % 160;
			pos[j]=(rc4() % 80)+80;			//ֻ��LFSR��������
		}
		//��ʼ�� ������Ϊȫ0
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
		
		//���ѡȡM��״̬�������ڲ���µ�����M��״̬���ֱ�����Grain ���������Ϊl����Կ����ͳ�����ֵķֲ�����
		//cout<<"\nOutput Differential:"<<endl;
		//����BW-KSD characteristic
		u8 And_logic[KSLen];   //����ȷ��ǰ������ȫ1��λ��
		u8 Or_logic[KSLen];		//����ȷ��ǰ������ȫ0��λ��
		//��ʼ�� and �� or logic
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
			
			//���ݲ��λ�ã��õ���һ��״̬rud_state_2
			u8 rnd_state_2[LEN];
			for(int j=0;j<LEN;j++){
				rnd_state_2[j]=rnd_state_1[j]^diff_state[j];
			}
			//�ֱ����Grain��
			ECRYPT_ctx ctx_1;
			ctx_1.keysize=80;
			ctx_1.ivsize=64;
			u8 keyStream_1[KSLen];

			ECRYPT_ctx ctx_2;
			ctx_2.keysize=80;
			ctx_2.ivsize=64;
			u8 keyStream_2[KSLen];
			//��״̬����grain��,��ö�Ӧ�ĳ���ΪKSLen����Կ�������������
			grain_state_load(&ctx_1,rnd_state_1);
			grain_state_load(&ctx_2,rnd_state_2);
			/*cout<<"���ǰ��������״̬1��"<<endl;
			for(int j=10;j<20;j++){
				printf("%x ",rnd_state_1[j]);
			}
			cout<<endl;
			*/
			ECRYPT_keystream_bytes(&ctx_1,keyStream_1,KSLen);
			ECRYPT_keystream_bytes(&ctx_2,keyStream_2,KSLen);
			//ECRYPT_keystream_backward_bytes(&ctx_1,keyStream_1,KSLen);
			//ECRYPT_keystream_backward_bytes(&ctx_2,keyStream_2,KSLen);
			//����������
			u8 Diff_KS[KSLen];
			for(int j=0;j<KSLen;j++){
				Diff_KS[j]=keyStream_1[j]^keyStream_2[j];
			}
			//����BW-KSD characteristic
			for(int j=0;j<KSLen;j++){
				And_logic[j]&=Diff_KS[j];
				Or_logic[j]|=Diff_KS[j];
			}
			//ͳ�Ƹ�����ֳ��ֵ�Ƶ��
			//string str=char2HexString(Diff_KS,KSLen);
			//map<string,u32>::iterator it=counter.find(str);
			//if(it!=counter.end()){//�Ѵ���������
			//	it->second+=1;
			//}else
			//	counter.insert(make_pair(str,1));
			////�ṹ��ctx_1��ctx_2���ڴ��ͷ�
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
		//�����ǰ�����֣���Ӧ�����ֵķֲ�
	/*	map<string,u32>::iterator beg=counter.begin();
		map<string,u32>::iterator end=counter.end();
		for(;beg!=end;beg++){
			cout<<beg->first<<"  "<<setprecision(3)<<(float)beg->second*100/T_NUM<<"%"<<endl;
		}*/
		//���㵱ǰ�����ֶ�Ӧ��BW-KSD��characteristic  And�߼�ȷ��ȫ1��λ��  Or�߼�ȷ��ȫ0��λ��  ʣ�µľ��ǲ�ȷ����λ��
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
			cout<<"ǰ�������ֵ�BW-KSD characteristicΪ:"<<KSD_character<<endl;
			cout<<" �̶�λ�õĸ�����"<<KW_KSD_CH<<endl<<endl;
		}
		
		//ͳ�������֣�ռ���в�ֵı���
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

//���㵱�����ֵĺ�������dһ����ʱ��ƽ�������ֵĸ���
void cal_average_OutputDiff(u32 L,u32 sam_N){
	srand((unsigned)time(NULL));
	u32 average_Diff_Num=0;
	double average_Diff_prop=0.0;
	double average_KW_KSD_CH=0.0;
	map<string,u32> counter;
	for(int D=1;D<=sam_N;D++){

		//���ѡȡ160bit ״̬�Ĳ��λ�� NFSR��0~79��LFSR��80~159
		u32* pos=new u32[L]();
		for(int j=0;j<L;j++){
			pos[j]=rc4() % 160;
		}
		//��ʼ�� ������Ϊȫ0
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
		
		//���ѡȡM��״̬�������ڲ���µ�����M��״̬���ֱ�����Grain ���������Ϊl����Կ����ͳ�����ֵķֲ�����
		//cout<<"\nOutput Differential:"<<endl;
		for(int i=0;i<T_NUM;i++){
			if(i % 20000==0)
				cout<<"proceed "<<setprecision(3)<<(double)i*100/T_NUM<<"%..."<<endl;
			//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
			u8 rnd_state_1[LEN];
			for(int j=0;j<LEN;j++){
				rnd_state_1[j]=rc4();
			}
			
			//���ݲ��λ�ã��õ���һ��״̬rud_state_2
			u8 rnd_state_2[LEN];
			for(int j=0;j<LEN;j++){
				rnd_state_2[j]=rnd_state_1[j]^diff_state[j];
			}
			//�ֱ����Grain��
			ECRYPT_ctx* ctx_1=new ECRYPT_ctx;
			ctx_1->keysize=80;
			ctx_1->ivsize=64;
			u8 keyStream_1[KSLen];

			ECRYPT_ctx* ctx_2=new ECRYPT_ctx;
			ctx_2->keysize=80;
			ctx_2->ivsize=64;
			u8 keyStream_2[KSLen];
			//��״̬����grain��,��ö�Ӧ�ĳ���ΪKSLen����Կ�������������
			grain_state_load(ctx_1,rnd_state_1);
			grain_state_load(ctx_2,rnd_state_2);
			/*cout<<"���ǰ��������״̬1��"<<endl;
			for(int j=10;j<20;j++){
				printf("%x ",rnd_state_1[j]);
			}
			cout<<endl;
			*/
			ECRYPT_keystream_bytes(ctx_1,keyStream_1,KSLen);
			ECRYPT_keystream_bytes(ctx_2,keyStream_2,KSLen);
			//ECRYPT_keystream_backward_bytes(ctx_1,keyStream_1,KSLen);
			//ECRYPT_keystream_backward_bytes(ctx_2,keyStream_2,KSLen);
			//����������
			u8 Diff_KS[KSLen];
			for(int j=0;j<KSLen;j++){
				Diff_KS[j]=keyStream_1[j]^keyStream_2[j];
			}
			//ͳ�Ƹ�����ֳ��ֵ�Ƶ��
			string str=char2HexString(Diff_KS,KSLen);
			map<string,u32>::iterator it=counter.find(str);
			if(it!=counter.end()){//�Ѵ���������
				it->second+=1;
			}else
				counter.insert(make_pair(str,1));
			//�ṹ��ctx_1��ctx_2���ڴ��ͷ�
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
		//ͳ�������֣�ռ���в�ֵı���
		// cout<<"Diff prop:"<<setprecision(3)<<(double)counter.size()*100/pow(2.0,(double)KSLen*8)<<"%"<<endl;
		average_Diff_Num+=counter.size();
		//memory release
		counter.clear();
		delete [] pos;
	}
	average_Diff_prop=(double)average_Diff_Num/sam_N;
	cout<<"The average differential Num (d,l):("<<L<<","<<KSLen<<") is "<<setprecision(8)<<average_Diff_prop<<endl;

}


//���ĳ���ض���֣������ǰ��backward(����forward)�����ֲַ�,������BW-KSD characteristic

void inputOutputDiffForSpecificDiff(u32 L,u32 *pos){
	srand((unsigned)time(NULL));
	u32 average_Diff_Num=0;
	double average_Diff_prop=0.0;
	map<string,u32> counter;
	//��ʼ�� ������Ϊȫ0
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
	//���ѡȡM��״̬�������ڲ���µ�����M��״̬���ֱ�����Grain ���������Ϊl����Կ����ͳ�����ֵķֲ�����
	//cout<<"\nOutput Differential:"<<endl;
	//����BW-KSD characteristic
	u8 And_logic[KSLen];   //����ȷ��ǰ������ȫ1��λ��
	u8 Or_logic[KSLen];		//����ȷ��ǰ������ȫ0��λ��
	//��ʼ�� and �� or logic
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
			
		//���ݲ��λ�ã��õ���һ��״̬rud_state_2
		u8 rnd_state_2[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_2[j]=rnd_state_1[j]^diff_state[j];
		}
		//�ֱ����Grain��
		ECRYPT_ctx ctx_1;
		ctx_1.keysize=80;
		ctx_1.ivsize=64;
		u8 keyStream_1[KSLen];

		ECRYPT_ctx ctx_2;
		ctx_2.keysize=80;
		ctx_2.ivsize=64;
		u8 keyStream_2[KSLen];
		//��״̬����grain��,��ö�Ӧ�ĳ���ΪKSLen����Կ�������������
		grain_state_load(&ctx_1,rnd_state_1);
		grain_state_load(&ctx_2,rnd_state_2);
		ECRYPT_keystream_bytes(&ctx_1,keyStream_1,KSLen);
		ECRYPT_keystream_bytes(&ctx_2,keyStream_2,KSLen);
		//ECRYPT_keystream_backward_bytes(&ctx_1,keyStream_1,KSLen);
		//ECRYPT_keystream_backward_bytes(&ctx_2,keyStream_2,KSLen);
		//����������
		u8 Diff_KS[KSLen];
		for(int j=0;j<KSLen;j++){
			Diff_KS[j]=keyStream_1[j]^keyStream_2[j];
		}
		//����BW-KSD characteristic
		for(int j=0;j<KSLen;j++){
			And_logic[j]&=Diff_KS[j];
			Or_logic[j]|=Diff_KS[j];
		}
		//ͳ�Ƹ�����ֳ��ֵ�Ƶ��
		string str=char2HexString(Diff_KS,KSLen);
		map<string,u32>::iterator it=counter.find(str);
		if(it!=counter.end()){//�Ѵ���������
			it->second+=1;
		}else
			counter.insert(make_pair(str,1));
		////�ṹ��ctx_1��ctx_2���ڴ��ͷ�
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
	//�����ǰ�����֣���Ӧ�����ֵķֲ�
	map<string,u32>::iterator beg=counter.begin();
	map<string,u32>::iterator end=counter.end();
	for(;beg!=end;beg++){
		cout<<beg->first<<"  "<<setprecision(3)<<(float)beg->second*100/T_NUM<<"%"<<endl;
	}
	//���㵱ǰ�����ֶ�Ӧ��BW-KSD��characteristic  And�߼�ȷ��ȫ1��λ��  Or�߼�ȷ��ȫ0��λ��  ʣ�µľ��ǲ�ȷ����λ��
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
	cout<<"ǰ�������ֵ�BW-KSD characteristicΪ:"<<KSD_character<<endl;
}


