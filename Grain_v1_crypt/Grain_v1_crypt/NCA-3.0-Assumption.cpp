/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of offline stage in NCA-3.0
	 
*/

#include "stdafx.h"
#include "head.h"
//��֤NCA-3.0���� grain full version 
//��Ҫ����Ԥ��д�õ�sampling resistance�汾��grain
void verify_assumption(u32 d,u32 random_test_num){
	rc4_setup();
	string part="verify_ass";
	string curr_DIR=DIR_ASS+part+"_KSD_"+int_2_string(MAX_KSD)+"_HM_"
		+int_2_string(MAX_KSD_HM)+"_d_"+int_2_string(d)+"\\";
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
	cout<<"�����漴ѡȡISD��������ӦKSD���洢����..."<<endl;
	for(int q=0;q<random_test_num;q++){

	}
}


//��֤NCA-3.0���裬�����汾
void verify_assumption_reduce(u32 d,u32 random_test_num){
	rc4_setup();
	//�������·��
	string part="verify_ass";
	string curr_DIR=DIR_REDUCE_V3_ASS+part+"_KSD_"+int_2_string(MAX_KSD)+"_HM_"
		+int_2_string(MAX_KSD_HM)+"_d_"+int_2_string(d)+"\\";
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
	cout<<"�����漴ѡȡISD��������ӦKSD���洢����..."<<endl;
	for(int q=0;q<random_test_num;q++){
		if((q+1) % 1000 ==0){
			cout<<"proceed "<<setprecision(3)<<(double)q*100/random_test_num<<"%..."<<endl;
		}
		
		//�漴ѡȡd�����λ�ò��洢��v[i]����
		u32 *v=new u32[d]();
		u32 state_Len=STATE_REDUCE-SP;
		for(int i=0;i<d;i++){
			v[i]=(rc4() % state_Len)+1;		//����1~53֮�����
		}
		//����λ������״̬���
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
		delete [] v;
	}
	//������ͳ��KSD����ISD���ֵı���
	cout<<"������ͳ��KSD����ISD���ֵı���..."<<endl;
	string fileSuffix="*.txt";
	string fileDir=curr_DIR+fileSuffix;
	set<string> ISD;
	ifstream infile;
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
			cout<<"�Ҳ���"<<tableName<<"�ļ�"<<endl;
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
				cout<<"�Ҳ���"<<tableName<<"�ļ�"<<endl;
			}
			infile.close();
		}
	}
	cout<<"Special���а���ISD�ı���Ϊ:"<<ISD.size()<<"/"<<random_test_num<<endl;
	_findclose(longf);
}