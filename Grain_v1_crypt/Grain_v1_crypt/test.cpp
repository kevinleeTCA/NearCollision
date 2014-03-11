

#include "stdafx.h"
#include "head.h"
//d是最大的Hamming 重量，len 是串的长度
void enumerate_HW(int d,int len){
	//枚举所有HM重量小于等于d的组合
	for(int i=1;i<=d;i++){
		combination_for_search_HM(len,i);
	}
}

void combination_for_search_HM(int len,int curr_HM){
	//初始化组合向量
	u32 *v=new u32[curr_HM+1]();
	for(int i=0;i<curr_HM;i++){
		v[i]=i+1;
	}
	v[curr_HM]=len+1;
	//do something for the first 组合
	for(int i=0;i<curr_HM;i++){
		cout<<v[i]<<" ";
	}
	cout<<endl;

	while(combination_for_search_HM_sub(curr_HM,v)){
		//do something here for the current 组合
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
			//根据当前组合进行操作
			for(int j=i+1;j<curr_HM;j++)
				v[j]=v[j-1]+1;
			return true;
		}
	}
	return false;
}