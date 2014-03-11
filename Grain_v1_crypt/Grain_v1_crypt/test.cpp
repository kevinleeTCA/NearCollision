

#include "stdafx.h"
#include "head.h"
//d������Hamming ������len �Ǵ��ĳ���
void enumerate_HW(int d,int len){
	//ö������HM����С�ڵ���d�����
	for(int i=1;i<=d;i++){
		combination_for_search_HM(len,i);
	}
}

void combination_for_search_HM(int len,int curr_HM){
	//��ʼ���������
	u32 *v=new u32[curr_HM+1]();
	for(int i=0;i<curr_HM;i++){
		v[i]=i+1;
	}
	v[curr_HM]=len+1;
	//do something for the first ���
	for(int i=0;i<curr_HM;i++){
		cout<<v[i]<<" ";
	}
	cout<<endl;

	while(combination_for_search_HM_sub(curr_HM,v)){
		//do something here for the current ���
		for(int i=0;i<curr_HM;i++){
			cout<<v[i]<<" ";
		}
		cout<<endl;
	}

	delete [] v;
}

bool combination_for_search_HM_sub(int curr_HM,u32* v){
	for(int i=curr_HM-1;i>=0;i--){
		if(v[i]+1!=v[i+1]){
			v[i]++;
			//���ݵ�ǰ��Ͻ��в���
			for(int j=i+1;j<curr_HM;j++)
				v[j]=v[j-1]+1;
			return true;
		}
	}
	return false;
}