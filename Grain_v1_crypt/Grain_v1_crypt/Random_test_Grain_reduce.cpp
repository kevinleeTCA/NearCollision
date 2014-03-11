/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of test case of NCA
*/

#include "stdafx.h"
#include "head.h"


//测试调用一次genOutput_diff_imp_grain_reduce_v1函数需要多长时间 NCA-1.0
//以及每次枚举随机状态的个数和输出差分个数之间的差距
void test_time_genOutput_v1(){
	u32 d=4;
	u32 k=1;
	for(;k<=d;k++){
		u32 *v=new u32[k+1]();
		//进行10次实验
		double time[4]={0};
		start_cal();
		for(int j=0;j<10;j++){
			for(int i=0;i<k;i++){
				v[i]=(rc4() % STATE_REDUCE) +1;
			}
			v[k]=STATE_REDUCE+1;
			genOutput_diff_imp_grain_reduce_v1(k,v,d);
		}
		end_cal(time);
		printf("输入差分的汉明重量:%d, 每一个差分枚举的状态个数为：%d.\n",k,STATE_NUM*k);
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
		delete [] v;
	}
}

//测试genOutput_diff_imp_grain_reduce函数需要多长时间 NCA-2.0
void test_time_genOutput_v2(){
	u32 d=4;
	u32 k=1;
	//针对不同重量的输入差分
	for(;k<=d;k++){
		u32 *v=new u32[k+1]();
		//进行10次实验
		double time[4]={0};
		u32 state_Len=STATE_REDUCE-SP;		//总的状态数 减去sampling resistance的大小
		start_cal();
		for(int j=0;j<10;j++){
			for(int i=0;i<k;i++){
				v[i]=(rc4() % state_Len) +1;
			}
			v[k]=state_Len+1;
			genOutput_diff_imp_grain_reduce(k,v,"");
		}
		end_cal(time);
		printf("输入差分的汉明重量:%d, 每一个差分枚举的状态个数为：%d.\n",k,STATE_NUM*k);
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
		delete [] v;
	}
}

//测试genOutput_diff_imp_grain_reduce函数需要多长时间 NCA-3.0
void test_time_genOutput_v3(){
	u32 d=4;
	u32 k=1;
	//针对不同重量的输入差分
	for(;k<=d;k++){
		u32 *v=new u32[k+1]();
		//进行10次实验
		double time[4]={0};
		u32 state_Len=STATE_REDUCE-SP;		//总的状态数 减去sampling resistance的大小
		start_cal();
		for(int j=0;j<10;j++){
			for(int i=0;i<k;i++){
				v[i]=(rc4() % state_Len) +1;
			}
			v[k]=state_Len+1;
			genOutput_diff_imp_grain_reduce_v3(k,v,"");
		}
		end_cal(time);
		printf("输入差分的汉明重量:%d, 每一个差分枚举的状态个数为：%d.\n",k,STATE_NUM*k);
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
		delete [] v;
	}
}