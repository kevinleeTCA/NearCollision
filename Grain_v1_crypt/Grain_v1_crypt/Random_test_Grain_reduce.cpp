/*
	Created by Kevin Lee 2012/12/18
	This is an implemention of test case of NCA
*/

#include "stdafx.h"
#include "head.h"


//���Ե���һ��genOutput_diff_imp_grain_reduce_v1������Ҫ�೤ʱ�� NCA-1.0
//�Լ�ÿ��ö�����״̬�ĸ����������ָ���֮��Ĳ��
void test_time_genOutput_v1(){
	u32 d=4;
	u32 k=1;
	for(;k<=d;k++){
		u32 *v=new u32[k+1]();
		//����10��ʵ��
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
		printf("�����ֵĺ�������:%d, ÿһ�����ö�ٵ�״̬����Ϊ��%d.\n",k,STATE_NUM*k);
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
		delete [] v;
	}
}

//����genOutput_diff_imp_grain_reduce������Ҫ�೤ʱ�� NCA-2.0
void test_time_genOutput_v2(){
	u32 d=4;
	u32 k=1;
	//��Բ�ͬ������������
	for(;k<=d;k++){
		u32 *v=new u32[k+1]();
		//����10��ʵ��
		double time[4]={0};
		u32 state_Len=STATE_REDUCE-SP;		//�ܵ�״̬�� ��ȥsampling resistance�Ĵ�С
		start_cal();
		for(int j=0;j<10;j++){
			for(int i=0;i<k;i++){
				v[i]=(rc4() % state_Len) +1;
			}
			v[k]=state_Len+1;
			genOutput_diff_imp_grain_reduce(k,v,"");
		}
		end_cal(time);
		printf("�����ֵĺ�������:%d, ÿһ�����ö�ٵ�״̬����Ϊ��%d.\n",k,STATE_NUM*k);
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
		delete [] v;
	}
}

//����genOutput_diff_imp_grain_reduce������Ҫ�೤ʱ�� NCA-3.0
void test_time_genOutput_v3(){
	u32 d=4;
	u32 k=1;
	//��Բ�ͬ������������
	for(;k<=d;k++){
		u32 *v=new u32[k+1]();
		//����10��ʵ��
		double time[4]={0};
		u32 state_Len=STATE_REDUCE-SP;		//�ܵ�״̬�� ��ȥsampling resistance�Ĵ�С
		start_cal();
		for(int j=0;j<10;j++){
			for(int i=0;i<k;i++){
				v[i]=(rc4() % state_Len) +1;
			}
			v[k]=state_Len+1;
			genOutput_diff_imp_grain_reduce_v3(k,v,"");
		}
		end_cal(time);
		printf("�����ֵĺ�������:%d, ÿһ�����ö�ٵ�״̬����Ϊ��%d.\n",k,STATE_NUM*k);
		printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);	
		delete [] v;
	}
}