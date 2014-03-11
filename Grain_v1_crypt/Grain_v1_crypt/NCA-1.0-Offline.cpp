/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of offline stage in NCA-1.0 
	
*/

#include "stdafx.h"
#include "head.h"

//�������Hamming����С��d��64���ص��ڲ�״̬��֣�Ȼ����N��С�������ռ��£�����Ԥ���㣬�����Կ������Ϊl�����֧��64bit�� unsigned long long����
/*
	d:����״̬��ֵ����������
*/

void offLine_table_construct_v1(u32 d){
	for(int i=1;i<=d;i++){
		//ö�����������ֵĺ�������Ϊi�Ĳ��   
		u32 state_Len=STATE_REDUCE;		//�ܵ�״̬�� ��ȥsampling resistance�Ĵ�С
		cout<<"Grain reduce--��ʼ���������ֺ�������Ϊ:"<<i<<"�����."<<endl;
		double time[4]={0};
		start_cal();
		combination_for_search_grain_reduce_v1(state_Len,i,d);
		end_cal(time);
		cout<<"Grain reduce--�����ֺ�������Ϊ:"<<i<<"������Ѿ��������."<<endl;
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
	}
}

//��������⣬��ӡ��1~n������ѡȡk�����������,����������k��n�Ƚ�С��ʱ���ٶȿ�,�ǵݹ�ʵ��
//���ڸ��������ֵ�����
void combination_for_search_grain_reduce_v1(u32 n,u32 k,u32 d){
	//����һ���������������������Ľ���
	long long counter=0;
	//Ԥ�ȴ洢һ�����Ƶ��ܵļ�����
	long long t_Sum[6]={64,2016,41664,635376,7624512,74974368};
	//��ʼ���������
	u32 *v=new u32[k+1]();
	for(int i=0;i<k;i++){
		v[i]=i+1;
	}
	v[k]=n+1;
	//�ó�ʼ��������������Գ�ʼ����Ͻ��в���
	genOutput_diff_imp_grain_reduce_v1(k,v,d);
	//���C(n,k)��������ϣ�Ϊÿ������趨����״̬��֣���ִ��grain�õ�������
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
			//���ݵ�ǰ��Ͻ��в���
			for(int j=i+1;j<k;j++)
				v[j]=v[j-1]+1;
			genOutput_diff_imp_grain_reduce_v1(k,v,d);
			return true;
		}
	}
	return false;
}

//�õ������ֵķֲ������� �Ľ���
void genOutput_diff_imp_grain_reduce_v1(u32 k,u32 *v,u32 d){
	//��ʼ�� ������Ϊȫ0 �������ǰ���v�Ķ�Ӧ������״̬���
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
	
	
	//���ѡ��STATE_NUM*k��״̬
	u32 SIZE_DIFF=STATE_NUM*k;
	unsigned long long *data=new unsigned long long[SIZE_DIFF];
	for(int i=0;i<SIZE_DIFF;i++){
		//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
		u8 rnd_state_1[STATE_BYTE];
		for(int j=0;j<STATE_BYTE;j++){
			rnd_state_1[j]=rc4();
		}
		//���ݲ��λ�ã��õ���һ��״̬rud_state_2
		u8 rnd_state_2[STATE_BYTE];
		for(int j=0;j<STATE_BYTE;j++){
			rnd_state_2[j]=rnd_state_1[j]^input_diff[j];
		}
		//�ֱ����Grain�� ���l������Կ��
		//�ֱ���Grain reduce�������ΪKSLen_Reduced(bytes)����Կ����Sampling resistance��
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

		//��״̬����grain��,��ö�Ӧ�ĳ���ΪKSLen����Կ�������������
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
		//ͳ�Ƹ�����ֳ��ֵ�Ƶ��
		//string str=char2HexString(Diff_KS,KSLen_Reduced);
		/*map<string,u32>::iterator it=counter.find(str);
		if(it!=counter.end()){//�Ѵ���������
			it->second+=1;
		}else
			counter.insert(make_pair(str,1));
		*/
		//�ṹ��ctx_1��ctx_2���ڴ��ͷ�
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
	//��data ����
	//sort(data,data+SIZE_DIFF);
	qsort(data,SIZE_DIFF,sizeof(unsigned long long),comp);
	//��data�е�Ԫ��ͳ�ƣ��������������ֵ�16����������
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
		//counter��¼�˵�ǰKSD���ֵĴ�����j����һ��KSD��һ�����ֵ��±ꡣ
		//ֻ������ǰ��������MAX_KSD(100)����� �����ֵ��
		multimap<u32,unsigned long long>::iterator it=occurrance.begin();
		if(it==occurrance.end()){//��Ӧ��ʼû��Ԫ�ص����
			occurrance.insert(make_pair(counter,curr));
		}
		else if(counter>it->first){
			occurrance.insert(make_pair(counter,curr));
			if(occurrance.size()>MAX_KSD)  //ɾ����С�ģ���������100��
				occurrance.erase(occurrance.begin());
		}
		//��������ǰ�ظ����򣬽�����һ��KSD
		i=j;
	}
	//��MAX_KSD(100)����ֽ���/���±�
	//��������ļ�
	string part="Grain_(l,d)_(";
	string curr_DIR=DIR_REDUCE_V1+part+int_2_string(KSLen_Reduced)+","+int_2_string(d)+")"+
		FILE_SUFFIX+"\\";
	multimap<u32,unsigned long long>::iterator beg=occurrance.begin();
	multimap<u32,unsigned long long>::iterator end=occurrance.end();
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
	for(;beg!=end;beg++){
		//cout<<beg->second<<"������:"<<beg->first<<"�Ρ�"<<endl;
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
	//��data�ж�Ӧ�������ִ洢��һ��txt�ļ��У��������ֵ�16���Ʊ�ʾ����������input_diffת����16����+����ò�ֵı������洢��txt��һ�С�
	//���ͳ��ÿ��txt�����������ƽ����������Ҳ��ÿ��table�Ĵ�С���������ֵ�16������������

	//string inputDiffStr=char2HexString(input_diff,STATE_BYTE);
	

	/*
	//test the speed
	//if(counter.size()==SIZE_DIFF){
		//cout<<"�����֣�"<<inputDiffStr<<endl;
		//cout<<"�����ֵĸ�������Sampling�ĸ���."<<counter.size()<<"/"<<SIZE_DIFF<<endl<<endl;
		//cout<<"�����ֵĸ���:"<<counter.size()<<"/"<<SIZE_DIFF<<endl<<endl;
	//}
	//���ȱ���counter�е�����������
	map<string,u32>::iterator beg=counter.begin();
	map<string,u32>::iterator end=counter.end();
	for(;beg!=end;beg++){
		string outDiff=beg->first;
		u32 occurs=beg->second;
		double occur_prop=(double)occurs/STATE_NUM;
		//cout<<"�����֣�"<<inputDiffStr<<endl;
		//cout<<outDiff<<"  "<<occur_prop<<endl;
		//�������ֺͱ��� д�뵽��outDiff������txt�С�
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