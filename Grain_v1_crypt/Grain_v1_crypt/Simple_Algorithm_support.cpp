

#include "stdafx.h"
#include "head.h"
//��������⣬��ӡ��1~n������ѡȡk�����������,������������˻��ݵ�˼��
//Ȼ��õ���ЩԪ�ظ���Ϊk���Ӽ�����û�и��õķ�����
void combination(int n,int k,int curr,int *B){
	int counter=0;
	for(int i=0;i<curr;i++)
		counter+=B[i];
	if(counter==k){
		//�����ǰ���㣬ֱ�Ӵ�ӡ
		//��Ԫ��Ϊk��������
		for(int i=0;i<curr;i++)
			if(B[i])
				cout<<i+1<<" "<<ends;
		cout<<endl;
		return;
	}
	if(counter>k || curr==n)
		//����
		return;
	B[curr]=0;
	combination(n,k,curr+1,B);
	B[curr]=1;
	combination(n,k,curr+1,B);
}

//size of v: k+1  v[0]=1,v[1]=2,...,v[k-1]=k,v[k]=n+1
void simple_comb(u32 n, u32 k, u32 *v){
	for(int i=0;i<k;i++){
		v[i]=i+1;
	}
	v[k]=n+1;
	while(simple_comb_sub(k,v)){
	}
}
bool simple_comb_sub(u32 k,u32 *v){
	for(int i=k-1;i>=0;i--){
		if(v[i]+1!=v[i+1]){
			v[i]++;
			//print v
			for(int m=0;m<k;m++)
				cout<<v[m]<<","<<ends;
			cout<<endl;
			for(int j=i+1;j<k;j++)
				v[j]=v[j-1]+1;
			return true;
		}
	}
	return false;
}