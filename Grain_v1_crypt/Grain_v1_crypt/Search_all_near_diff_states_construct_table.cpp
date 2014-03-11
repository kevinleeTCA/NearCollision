#include "stdafx.h"
#include "head.h"
//kevin edit. this file is used for table construction

/*������
L:�����ֵ����������
*/
void searchAllNearColStates(u32 L){
	for(int i=4;i<=L;i++){
		
		/*//��ʼ�� ������Ϊȫ0
		u8 diff_state[LEN];
		for(int j=0;j<LEN;j++){
			diff_state[j]=0;
		}
		//ö�����������ֵĺ�������Ϊi�Ĳ��  ����B[i]=1��ʾ��λ�ó��֣�B[i]=0��ʾ��λ�ò�����
		u32 N=LEN*8;		//LEN*8 bits length
		u32 B[LEN*8];
		combination_for_search(N,i,0,B,diff_state);
		*/
			
		u32 N=LEN*8;
		cout<<"��ʼ���������ֺ�������Ϊ:"<<i<<"�����."<<endl;
		combination_for_search_imp(N,i);
		cout<<"�����ֺ�������Ϊ:"<<i<<"������Ѿ��������.\n\n"<<endl;
		
		//cout<<"��ʼ���������ֺ�������Ϊ:"<<L<<"�����."<<endl;
		//combination_for_search_imp(N,L);
		//cout<<"�����ֺ�������Ϊ:"<<L<<"������Ѿ��������.\n\n"<<endl;
	}
}
//��������⣬��ӡ��1~n������ѡȡk�����������,������������˻��ݵ�˼��
//���ڸ��������ֵ�����
void combination_for_search(u32 n,u32 k,u32 curr,u32 *B, u8 *diff_state){
	u32 counter=0;
	for(int i=0;i<curr;i++)
		counter+=B[i];
	if(counter==k){
		//�����ǰ���㣬ֱ�Ӵ�ӡ
		//��Ԫ��Ϊk��������
		for(int i=0;i<curr;i++){
			if(B[i])
				cout<<i+1<<" "<<ends;
		}
		cout<<"��Ӧ�����֣�"<<ends;
		for(int j=0;j<20;j++){
				printf("%x ",diff_state[j]);
		}
		cout<<endl;
		genOutput_diff(diff_state);
		return;
	}
	if(counter>k || curr==n)
		//����
		return;
	B[curr]=0;
	combination_for_search(n,k,curr+1,B,diff_state);
	B[curr]=1;
	u32 p=posIdx(curr);
	u32 r=rotateIdx(curr);
	diff_state[p]=diff_state[p]^(1<<r);
	combination_for_search(n,k,curr+1,B,diff_state);
	diff_state[p]=diff_state[p]^(1<<r);
}
//��������⣬��ӡ��1~n������ѡȡk�����������,����������k��n�Ƚ�С��ʱ���ٶȿ�,�ǵݹ�ʵ��
//���ڸ��������ֵ�����
void combination_for_search_imp(u32 n,u32 k){
	//����һ���������������������Ľ���
	long long counter=0;
	//Ԥ�ȴ洢һ�����Ƶ��ܵļ�����
	long long t_Sum[5]={160,12720,669920,26294360,820384032};
	//��ʼ���������
	u32 *v=new u32[k+1]();
	for(int i=0;i<k;i++){
		v[i]=i+1;
	}
	v[k]=n+1;
	//�ó�ʼ��������������Գ�ʼ����Ͻ��в���
	genOutput_diff_imp(k,v);
	//���C(n,k)��������ϣ�Ϊÿ������趨����״̬��֣���ִ��grain�õ�������
	while(combin_for_search_imp_sub(k,v)){
		if((++counter) % 30000 ==0){
			cout<<"proceed "<<setprecision(3)<<(double)counter*100/t_Sum[k-1]<<"%..."<<endl;
		}
	}
}
bool combin_for_search_imp_sub(u32 k,u32* v){
	for(int i=k-1;i>=0;i--){
		if(v[i]+1!=v[i+1]){
			v[i]++;
			//���ݵ�ǰ��Ͻ��в���
			for(int j=i+1;j<k;j++)
				v[j]=v[j-1]+1;
			genOutput_diff_imp(k,v);
			
			return true;
		}
	}
	return false;
}
//�õ������ֵķֲ������� �Ľ���
void genOutput_diff_imp(u32 k,u32 *v){
	//��ʼ�� ������Ϊȫ0 �������ǰ���v�Ķ�Ӧ������״̬���
	u8 *input_diff=new u8[LEN]();
	for(int m=0;m<k;m++){
		//cout<<v[m]<<" "<<ends;
		u32 p=posIdx(v[m]-1);
		u32 r=rotateIdx(v[m]-1);
		input_diff[p]=input_diff[p]^(1<<r);
	}
	/*
	for(int i=0;i<k;i++){
			if(v[i])
				cout<<v[i]<<" "<<ends;
	}
	cout<<"��Ӧ�����֣�"<<ends;
		for(int j=0;j<20;j++){
				printf("%x ",input_diff[j]);
	}
	cout<<endl;
	*/
	map<string,u32> counter;
	//���ѡ��T_NUM��״̬
	for(int i=0;i<T_NUM;i++){
		//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
		u8 rnd_state_1[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_1[j]=rc4();
		}
		//���ݲ��λ�ã��õ���һ��״̬rud_state_2
		u8 rnd_state_2[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_2[j]=rnd_state_1[j]^input_diff[j];
		}
		//�ֱ����Grain�� ���l������Կ��
		//u32 KSLen=10;  //byte length
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
		ECRYPT_keystream_bytes(ctx_1,keyStream_1,KSLen);
		ECRYPT_keystream_bytes(ctx_2,keyStream_2,KSLen);
		
			
		u8 Diff_KS[KSLen];
		for(int i=0;i<KSLen;i++){
			Diff_KS[i]=keyStream_1[i]^keyStream_2[i];
		}
		/*
		for(int i=0;i<KSLen;i++){
				printf("%x ",Diff_KS[i]);
			}
		cout<<endl;
		*/
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
	//��counter�ж�Ӧ�������ִ洢��һ��txt�ļ��У��������ֵ�16���Ʊ�ʾ����������input_diffת����16����+����ò�ֵı������洢��txt��һ�С�
	//���ͳ��ÿ��txt�����������ƽ����������Ҳ��ÿ��table�Ĵ�С���������ֵ�16������������
	string inputDiffStr=char2HexString(input_diff,LEN);
	//���ȱ���counter�е�����������
	map<string,u32>::iterator beg=counter.begin();
	map<string,u32>::iterator end=counter.end();
	for(;beg!=end;beg++){
		string outDiff=beg->first;
		u32 occurs=beg->second;
		double occur_prop=(double)occurs/T_NUM;
		//�������ֺͱ��� д�뵽��outDiff������txt�С�
		string fileName=outDiff+".txt";
		fileName=DIR+fileName;
		ofstream outfile;
		outfile.open(fileName.c_str(),ofstream::app);
		if(outfile){
			//cout<<"file \'"<<fileName<<"\' created."<<endl;
			outfile<<inputDiffStr<<" "<<occur_prop<<"\n";
			//cout<<"Successfully write:"<<inputDiffStr<<" "<<occur_prop<<" to file:" <<fileName<<endl;
		}
		outfile.close();
	}
	counter.clear();
	delete [] input_diff;
}
void genOutput_diff(u8 *input_diff){
	map<string,u32> counter;
	//���ѡ��T_NUM��״̬
	for(int i=0;i<T_NUM;i++){
		//cout<<"\n------Sample:"<<i+1<<"------"<<endl;
		u8 rnd_state_1[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_1[j]=rc4();
		}
		//���ݲ��λ�ã��õ���һ��״̬rud_state_2
		u8 rnd_state_2[LEN];
		for(int j=0;j<LEN;j++){
			rnd_state_2[j]=rnd_state_1[j]^input_diff[j];
		}
		//�ֱ����Grain�� ���l������Կ��
		//u32 KSLen=10;  //byte length
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
		ECRYPT_keystream_bytes(ctx_1,keyStream_1,KSLen);
		ECRYPT_keystream_bytes(ctx_2,keyStream_2,KSLen);
		
			
		u8 Diff_KS[KSLen];
		for(int i=0;i<KSLen;i++){
			Diff_KS[i]=keyStream_1[i]^keyStream_2[i];
		}
		/*
		for(int i=0;i<KSLen;i++){
				printf("%x ",Diff_KS[i]);
			}
		cout<<endl;
		*/
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
	//��counter�ж�Ӧ�������ִ洢��һ��txt�ļ��У��������ֵ�16���Ʊ�ʾ����������input_diffת����16����+����ò�ֵı������洢��txt��һ�С�
	//���ͳ��ÿ��txt�����������ƽ����������Ҳ��ÿ��table�Ĵ�С���������ֵ�16������������
	string inputDiffStr=char2HexString(input_diff,LEN);
	//���ȱ���counter�е�����������
	map<string,u32>::iterator beg=counter.begin();
	map<string,u32>::iterator end=counter.end();
	for(;beg!=end;beg++){
		string outDiff=beg->first;
		u32 occurs=beg->second;
		double occur_prop=(double)occurs/T_NUM;
		//�������ֺͱ��� д�뵽��outDiff������txt�С�
		string fileName=outDiff+".txt";
		fileName=DIR+fileName;
		ofstream outfile;
		outfile.open(fileName.c_str(),ofstream::app);
		if(outfile){
			//cout<<"file \'"<<fileName<<"\' created."<<endl;
			outfile<<inputDiffStr<<" "<<occur_prop<<"\n"<<ends;
			//cout<<"Successfully write:"<<inputDiffStr<<" "<<occur_prop<<" to file:" <<fileName<<endl;
		}
		outfile.close();
	}
	counter.clear();
}

//ͳ����������������ÿ��table�����������ڹ��ƴ洢�ռ�Ĵ�С
/*
void cal_ave_rows(string dirName){
	//���ȶ�ȡ��·���¶�Ӧ�������ļ������� �洢��һ��vector��
	cout<<"start"<<endl;
	vector<string> fileNameList=get_filelist((char*)dirName.c_str());
	//���α���ÿ���ļ�������¼�ļ�������
	
	vector<string>::iterator beg=fileNameList.begin();
	vector<string>::iterator end=fileNameList.end();
	for(;beg!=end;beg++){
		cout<<*beg<<endl;
	}
}

vector<string> & get_filelist(char *foldname){
	vector<string> flist;
	HANDLE file;
	WIN32_FIND_DATA fileData;
	char line[1024];
	wchar_t fn[1000];
	mbstowcs(fn,(const char*)foldname,999);
	file = FindFirstFile(fn, &fileData);
	FindNextFile(file, &fileData);
	while(FindNextFile(file, &fileData)){
		wcstombs(line,(const wchar_t*)fileData.cFileName,259);
		flist.push_back(line);
	}
	return flist;
}

*/