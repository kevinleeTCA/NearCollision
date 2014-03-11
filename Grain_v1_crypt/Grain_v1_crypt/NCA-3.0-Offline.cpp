/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of offline stage in NCA-3.0
	 
*/

#include "stdafx.h"
#include "head.h"

//�������Hamming����С��d��53���ص��ڲ�״̬��֣�Ȼ����N��С�������ռ��£�����Ԥ���㣬�����Կ������Ϊl�����֧��64bit����
/*
	
	d:����״̬��ֵ����������
*/
void offLine_table_construct_v3(u32 d){
	//���������
	//��������ļ�
	string part="Grain_(l,d)_(";
	string curr_DIR=DIR_REDUCE_V3+part+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")"+
		FILE_SUFFIX+WITH_PREFIX+"_KSD_"+int_2_string(MAX_KSD)+"_HM_"+int_2_string(MAX_KSD_HM)
		+"_N_"+int_2_string(STATE_NUM)+"\\";
	//����Ŀ¼��������������Զ�����Ŀ¼
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
		//ö�����������ֵĺ�������Ϊi�Ĳ��   
		u32 state_Len=STATE_REDUCE-SP;		//�ܵ�״̬�� ��ȥsampling resistance�Ĵ�С
		cout<<"Grain reduce--��ʼ���������ֺ�������Ϊ:"<<i<<"�����."<<endl;
		double time[4]={0};
		start_cal();
		combination_for_search_grain_reduce_v3(state_Len,i,curr_DIR);
		end_cal(time);
		cout<<"Grain reduce--�����ֺ�������Ϊ:"<<i<<"������Ѿ��������."<<endl;
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
	}
}

//��������⣬��ӡ��1~n������ѡȡk�����������,����������k��n�Ƚ�С��ʱ���ٶȿ�,�ǵݹ�ʵ��
//���ڸ��������ֵ�����
void combination_for_search_grain_reduce_v3(u32 n,u32 k,string curr_DIR){
	//����һ���������������������Ľ���
	long long counter=0;
	//Ԥ�ȴ洢һ�����Ƶ��ܵļ�����
	long long t_Sum[6]={53,1378,23426,292825,2869685,22957480};
	//��ʼ���������
	u32 *v=new u32[k+1]();
	for(int i=0;i<k;i++){
		v[i]=i+1;
	}
	v[k]=n+1;
	//�ó�ʼ��������������Գ�ʼ����Ͻ��в���
	genOutput_diff_imp_grain_reduce_v3(k,v,curr_DIR);
	//���C(n,k)��������ϣ�Ϊÿ������趨����״̬��֣���ִ��grain�õ�������
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
			//���ݵ�ǰ��Ͻ��в���
			for(int j=i+1;j<k;j++)
				v[j]=v[j-1]+1;
			genOutput_diff_imp_grain_reduce_v3(k,v,curr_DIR);
			return true;
		}
	}
	return false;
}

//�õ������ֵķֲ������� �Ľ���
void genOutput_diff_imp_grain_reduce_v3(u32 k,u32 *v,string curr_DIR){
	//��ʼ�� ������Ϊȫ0 �������ǰ���v�Ķ�Ӧ������״̬���
	/*
		�����Ż���byte�ϵĲ���,����Ч��������
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
		//���ѡ��һ��״̬
		for(int j=0;j<32;j++){
			NFSR_1[j]=0;
			LFSR_1[j]=0;

			LFSR_1[j]=rc4()&0x01;
			if(j<10 || j>20)
				NFSR_1[j]=rc4()&0x01;
		}
		//���ݲ��λ�ã��õ���һ��״̬
		u32 LFSR_2[32];
		u32 NFSR_2[32];
		for(int j=0;j<32;j++){
			LFSR_2[j]=LFSR_1[j]^LFSR[j];
			NFSR_2[j]=NFSR_1[j]^NFSR[j];
		}
		//�ֱ���Grain reduce�������ΪKSLen_Reduced(bytes)����Կ����Sampling resistance��
		/*ECRYPT_ctx_reduce* ctx_reduce_1=new ECRYPT_ctx_reduce;
		ECRYPT_ctx_reduce* ctx_reduce_2=new ECRYPT_ctx_reduce;*/
		ECRYPT_ctx_reduce ctx_reduce_1;
		ECRYPT_ctx_reduce ctx_reduce_2;
		u8 keystream_1[KSLen_Reduced];
		u8 keystream_2[KSLen_Reduced];
		//����ȷ��ʣ�µ�NFSR��11������
		grain_reduce_sampling_resistance(&ctx_reduce_1,LFSR_1,NFSR_1);
		grain_reduce_sampling_resistance(&ctx_reduce_2,LFSR_2,NFSR_2);
		//Ȼ�����ɴ�12��clock��ʼ����Կ��
		grain_reduce_sampling_resistance_genKSBytes(&ctx_reduce_1,keystream_1,KSLen_Reduced);
		grain_reduce_sampling_resistance_genKSBytes(&ctx_reduce_2,keystream_2,KSLen_Reduced);
		//����ض���Կ���Ĳ��
		
		u8 keystream_Diff[KSLen_Reduced];
		for(int j=0;j<KSLen_Reduced;j++){
			keystream_Diff[j]=keystream_1[j]^keystream_2[j];
		}
		//ͳ�Ƹ���������(HM<=MAX_KSD_HM)���ֵ�Ƶ�� MAX_KSD_HM=5
		if(Hamming_weight_of_state(keystream_Diff,KSLen_Reduced)<=MAX_KSD_HM){
			unsigned long long diff_long=char_2_long(keystream_Diff,KSLen_Reduced);
			data[spcial_KSD_size]=diff_long;
			spcial_KSD_size++;
		}
	}
	//��counter�ж�Ӧ�������ִ洢��һ��txt�ļ��У��������ֵ�16���Ʊ�ʾ��������������״̬���ת����16����+����ò�ֵı������洢��txt��һ�С�
	u8 inputDiffbyte[STATE_BYTE];
	for(int i=0;i<STATE_BYTE;i++){
		inputDiffbyte[i]=0;
	}
	stateBit2Byte(inputDiffbyte,STATE_BYTE,LFSR,NFSR,32);
	string inputDiffStr=char2HexString(inputDiffbyte,STATE_BYTE);  //NFSR+LFSR   16����

	//��data ����
	//sort(data,data+SIZE_DIFF);
	qsort(data,spcial_KSD_size,sizeof(unsigned long long),comp);
	//��data�е�Ԫ��ͳ�ƣ��������������ֵ�16����������
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
		//counter��¼�˵�ǰKSD���ֵĴ�����j����һ��KSD��һ�����ֵ��±ꡣ
		//ֻ������ǰ��������MAX_KSD(100)����� �����ֵ��  ����NCA-3.0������˿���Ƶ��֮�⣬��ð�����special��KSD�������������������ʩ�Ƿ���Ч�������
		multimap<u32,unsigned long long>::iterator it=occurrance.begin();
		if(it==occurrance.end()){//��Ӧ��ʼû��Ԫ�ص����
			occurrance.insert(make_pair(counter,curr));
		}
		else if(counter>it->first){
			occurrance.insert(make_pair(counter,curr));
			if(occurrance.size()>MAX_KSD)  //ɾ����С�ģ���������MAX_KSD��
				occurrance.erase(occurrance.begin());
		}
		//��������ǰ�ظ����򣬽�����һ��KSD
		i=j;
	}
	//��MAX_KSD(100)����ֽ���/���±�
	multimap<u32,unsigned long long>::iterator beg=occurrance.begin();
	multimap<u32,unsigned long long>::iterator end=occurrance.end();
	for(;beg!=end;beg++){
		//cout<<beg->second<<"������:"<<beg->first<<"�Ρ�"<<endl;
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