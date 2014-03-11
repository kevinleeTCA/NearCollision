

#include "stdafx.h"
#include "head.h"
//简单组合问题，打印从1~n个数中选取k个的所有组合,这个程序利用了回溯的思想
//然后得到那些元素个数为k的子集，有没有更好的方法？
void combination(int n,int k,int curr,int *B){
	int counter=0;
	for(int i=0;i<curr;i++)
		counter+=B[i];
	if(counter==k){
		//如果当前满足，直接打印
		//打元素为k的这个组合
		for(int i=0;i<curr;i++)
			if(B[i])
				cout<<i+1<<" "<<ends;
		cout<<endl;
		return;
	}
	if(counter>k || curr==n)
		//回溯
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