// Grain_v1_crypt.cpp : 定义控制台应用程序的入口点。
/*
	Created by Kevin Lee 2012/6/18
	This is an implemention of Grain v1
*/

#include "stdafx.h"
#include "head.h"

//define NFSR and LFSR state. KEY and IV vector
//bitset<80> NFSR;
//bitset<80> LFSR;
//bitset<80> KEY;
//bitset<64> IV;


int _tmain(int argc, _TCHAR* argv[]){
	//enumerate_HW(3,32);
	inputOutputDiff(2,20);
	//compare_find_match("D:\\小琦\\Grain_Reduce\\NCA_2.0_TEST\\Analyze_data_(l,d)_(4,4)_with_prefix\\"
	//	,"D:\\小琦\\Grain_Reduce\\NCA_2.0\\Grain_(l,d)_(4,4)_imp_rand_with_prefix_KSD_2000_N_8192\\");
	//rc4_setup();
	//offLine_table_construct(4);
	//分析线上阶段收集的数据
	//double time[4]={0};		//测试调用一次需要多久
	//for(int i=0;i<10;i++){
	//	cout<<"**************case:"<<i<<"**************"<<endl;
	//	start_cal();
	//	analyze_collected_data(4);
	//	end_cal(time);
	//	printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);
	//	cout<<"****************************************"<<endl;
	//}

	
	//analyze_collected_data(5);
	//verify_assumption_reduce(4,10000);
	//测试出来char_2_long存在漏洞，不知道这个是否会影响到offline阶段
	//rc4_setup();
	//offLine_table_construct_v3(5);
	//online_attack_v3(4);
	//rc4_setup();
	//online_attack_v3(4);
	//offLine_table_construct_v3(4);
	//offLine_table_construct(4);
	//NCA-2.0 测试find_near_collision_v2_with_prefix_imp函数的正确性。版本1
	//rc4_setup();
	//string KSD="00907332";
	//string state="0000000002000000";
	//unsigned long long set_size=ceil(pow((double)2,DATA_SET));
	//cout<<"Data set size:2^{"<<DATA_SET<<"}"<<endl;
	//Online_Data_Reduce *data_A=new Online_Data_Reduce[set_size];
	//Online_Data_Reduce *data_B=new Online_Data_Reduce[set_size];
	//	//建立data_A
	//for(int i=0;i<set_size;i++){
	//	if((i+1) % 20000 ==0){
	//			cout<<"Data A proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
	//	}
	//	Online_Data_Reduce val_A;
	//	for(int j=0;j<KSLen_Reduced;j++){
	//		val_A.KS[j]=rc4();
	//	}
	//	for(int j=0;j<STATE_BYTE;j++){
	//		val_A.state[j]=rc4();
	//	}
	//	val_A.clock_t=rc4();
	//	data_A[i]=val_A;
	//}
	//	//建立data_B
	//for(int i=0;i<set_size;i++){
	//	if((i+1) % 20000 ==0){
	//			cout<<"Data B proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
	//	}
	//	Online_Data_Reduce val_B;
	//	for(int j=0;j<KSLen_Reduced;j++){
	//		val_B.KS[j]=rc4();
	//	}
	//	for(int j=0;j<STATE_BYTE;j++){
	//		val_B.state[j]=rc4();
	//	}
	//	val_B.clock_t=rc4();
	//	data_B[i]=val_B;
	//}
	////预先匹配好data_B中的一个元素
	//u8 KS_byte[KSLen_Reduced];
	//u8 state_byte[STATE_BYTE];
	//string2byte(KS_byte,KSLen_Reduced,KSD);	//这一步可能比较费时
	//string2byte(state_byte,STATE_BYTE,state);
	//	//先匹配KS
	////int A_idx=1;
	////int B_idx=1;
	////for(int j=0;j<KSLen_Reduced;j++)
	////	data_B[B_idx].KS[j]=data_A[A_idx].KS[j]^KS_byte[j];
	////	//再匹配state
	////for(int j=0;j<STATE_BYTE;j++)
	////	data_B[B_idx].state[j]=data_A[A_idx].state[j]^state_byte[j];
	///*cout<<"A["<<A_idx<<"] KS:";
	//for(int j=0;j<KSLen_Reduced;j++){
	//	printf("%02x",data_A[A_idx].KS[j]);
	//}
	//cout<<endl;
	//cout<<"B["<<B_idx<<"] KS:";
	//for(int j=0;j<KSLen_Reduced;j++){
	//	printf("%02x",data_B[B_idx].KS[j]);
	//}
	//cout<<endl;*/
	///*cout<<"A["<<A_idx<<"] state:";
	//for(int j=0;j<STATE_BYTE;j++){
	//	printf("%02x",data_A[A_idx].state[j]);
	//}
	//cout<<endl;
	//cout<<"B["<<B_idx<<"] state:";
	//for(int j=0;j<STATE_BYTE;j++){
	//	printf("%02x",data_B[B_idx].state[j]);
	//}
	//cout<<endl;*/
	////先对data_A和data_B进行排序
	//qsort(data_A,set_size,sizeof(Online_Data_Reduce),comp_struct);
	//qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	//
	////输出data_A和data_B中所有的元素
	////for(int i=set_size-3;i<set_size;i++){
	////	Online_Data_Reduce *val=&data_A[i];
	////	unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	////	for(int j=0;j<KSLen_Reduced;j++){
	////	//	printf("%x",val->KS[j]);
	////	}
	////	printf("%u",lval);
	////	printf("_");
	////	printf("%d",val->clock_t);
	////	printf("_");
	////	for(int j=0;j<STATE_BYTE;j++){
	////		printf("%x",val->state[j]);
	////	}
	////	printf("\n");
	////}
	////cout<<endl;
	////for(int i=set_size-3;i<set_size;i++){
	////	Online_Data_Reduce *val=&data_B[i];
	////	unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	////	for(int j=0;j<KSLen_Reduced;j++){
	////	//	printf("%x",val->KS[j]);
	////	}
	////	printf("%u",lval);
	////	printf("_");
	////	printf("%d",val->clock_t);
	////	printf("_");
	////	for(int j=0;j<STATE_BYTE;j++){
	////		printf("%x",val->state[j]);
	////	}
	////	printf("\n");
	////}
	////开始测试
	//start_cal();
	//double time[4]={0};		//测试调用一次需要多久
	//if(find_near_collision_v2_with_prefix_imp(4,data_A,data_B,set_size)){
	//	cout<<"success"<<endl;
	//}else
	//	cout<<"fail"<<endl;
	//end_cal(time);
	//printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);
	//delete [] data_A;
	//delete [] data_B;


	//NCA-2.0 测试find_near_collision_v2_with_prefix_imp函数的正确性。版本2

	//NCA-3.0 测试find_collision_sub_routine和find_collision_sub_routine_imp这个函数的正确性 版本2
	//rc4_setup();
	//string KSD="00000b";
	//string state="0000000008000000";
	//string tableName="D:\\小琦\\Grain_Reduce\\NCA_3.0\\Grain_(l,d)_(3,4)_imp_rand_with_prefix_KSD_50_HM_3_N_4096\\00000b.txt";
	//unsigned long long set_size=ceil(pow((double)2,DATA_SET));
	//cout<<"Data set size:2^{"<<DATA_SET<<"}"<<endl;
	//Online_Data_Reduce *data_A=new Online_Data_Reduce[set_size];
	//Online_Data_Reduce *data_B=new Online_Data_Reduce[set_size];
	//ECRYPT_ctx_reduce* ctx_reduce=new ECRYPT_ctx_reduce;
	//u8* key_R=new u8[4]();
	//u8* IV_R=new u8[3]();
	//for(int i=0;i<4;i++){
	//	key_R[i]= rc4();
	//}
	//for(int i=0;i<3;i++){
	//	IV_R[i]= rc4();
	//}
	//ECRYPT_keysetup_reduce(ctx_reduce,key_R,32,24);
	//ECRYPT_ivsetup_reduce(ctx_reduce,IV_R);
	//collect_sets_v3_with_prefix(ctx_reduce,data_A,data_B,1,set_size);

	////预先匹配好data_B中的一个元素
	//u8 KS_byte[KSLen_Reduced];
	//u8 state_byte[STATE_BYTE];
	//string2byte(KS_byte,KSLen_Reduced,KSD);	//这一步可能比较费时
	//string2byte(state_byte,STATE_BYTE,state);
	//	//先匹配KS
	//int A_idx=1;
	//int B_idx=1;
	//for(int j=0;j<KSLen_Reduced;j++)
	//	data_B[B_idx].KS[j]=data_A[A_idx].KS[j]^KS_byte[j];
	//	//再匹配state
	//for(int j=0;j<STATE_BYTE;j++)
	//	data_B[B_idx].state[j]=data_A[A_idx].state[j]^state_byte[j];
	//qsort(data_A,set_size,sizeof(Online_Data_Reduce),comp_struct);
	//qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	//////输出data_A和data_B中所有的元素
	//for(int i=0;i<set_size;i++){
	//	Online_Data_Reduce *val=&data_A[i];
	//	unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	//	for(int j=0;j<KSLen_Reduced;j++){
	//		printf("%02x",val->KS[j]);
	//	}
	//	//printf("%u",lval);
	//	printf("_");
	//	printf("%d",val->clock_t);
	//	printf("_");
	//	for(int j=0;j<STATE_BYTE;j++){
	//		printf("%x",val->state[j]);
	//	}
	//	printf("\n");
	//}
	//cout<<endl;
	//for(int i=0;i<set_size;i++){
	//	Online_Data_Reduce *val=&data_B[i];
	//	unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	//	for(int j=0;j<KSLen_Reduced;j++){
	//		printf("%02x",val->KS[j]);
	//	}
	//	//printf("%u",lval);
	//	printf("_");
	//	printf("%d",val->clock_t);
	//	printf("_");
	//	for(int j=0;j<STATE_BYTE;j++){
	//		printf("%x",val->state[j]);
	//	}
	//	printf("\n");
	//}
	//
	////测试调用一次需要多久
	//start_cal();
	//double time[4]={0};		
	//if(find_collision_sub_routine_imp(KSD,tableName,data_A,data_B,set_size)){
	//	cout<<"success"<<endl;
	//}else
	//	cout<<"fail"<<endl;
	//end_cal(time);
	//printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);
	//delete [] data_A;
	//delete [] data_B;

	//NCA-3.0 测试find_collision_sub_routine这个函数的正确性   版本1
	//rc4_setup();
	//string KSD="00000b";
	//string state="0000000008000000";
	//string tableName="D:\\小琦\\Grain_Reduce\\NCA_3.0\\Grain_(l,d)_(3,4)_imp_rand_with_prefix_KSD_50_HM_3_N_4096\\00000b.txt";
	//unsigned long long set_size=ceil(pow((double)2,DATA_SET));
	//cout<<"Data set size:2^{"<<DATA_SET<<"}"<<endl;
	//Online_Data_Reduce *data_A=new Online_Data_Reduce[set_size];
	//Online_Data_Reduce *data_B=new Online_Data_Reduce[set_size];
	//	//建立data_A
	//for(int i=0;i<set_size;i++){
	//	if((i+1) % 20000 ==0){
	//			cout<<"Data A proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
	//	}
	//	Online_Data_Reduce val_A;
	//	for(int j=0;j<KSLen_Reduced;j++){
	//		val_A.KS[j]=rc4();
	//	}
	//	for(int j=0;j<STATE_BYTE;j++){
	//		val_A.state[j]=rc4();
	//	}
	//	val_A.clock_t=rc4();
	//	data_A[i]=val_A;
	//}
	//	//建立data_B
	//for(int i=0;i<set_size;i++){
	//	if((i+1) % 20000 ==0){
	//			cout<<"Data B proceed "<<setprecision(3)<<(double)i*100/set_size<<"%..."<<endl;
	//	}
	//	Online_Data_Reduce val_B;
	//	for(int j=0;j<KSLen_Reduced;j++){
	//		val_B.KS[j]=rc4();
	//	}
	//	for(int j=0;j<STATE_BYTE;j++){
	//		val_B.state[j]=rc4();
	//	}
	//	val_B.clock_t=rc4();
	//	data_B[i]=val_B;
	//}
	////预先匹配好data_B中的一个元素
	//u8 KS_byte[KSLen_Reduced];
	//u8 state_byte[STATE_BYTE];
	//string2byte(KS_byte,KSLen_Reduced,KSD);	//这一步可能比较费时
	//string2byte(state_byte,STATE_BYTE,state);
	//	//先匹配KS
	//int A_idx=rc4();
	//int B_idx=rc4();
	//for(int j=0;j<KSLen_Reduced;j++)
	//	data_B[B_idx].KS[j]=data_A[A_idx].KS[j]^KS_byte[j];
	//	//再匹配state
	//for(int j=0;j<STATE_BYTE;j++)
	//	data_B[B_idx].state[j]=data_A[A_idx].state[j]^state_byte[j];
	///*cout<<"A["<<A_idx<<"] KS:";
	//for(int j=0;j<KSLen_Reduced;j++){
	//	printf("%02x",data_A[A_idx].KS[j]);
	//}
	//cout<<endl;
	//cout<<"B["<<B_idx<<"] KS:";
	//for(int j=0;j<KSLen_Reduced;j++){
	//	printf("%02x",data_B[B_idx].KS[j]);
	//}
	//cout<<endl;*/
	///*cout<<"A["<<A_idx<<"] state:";
	//for(int j=0;j<STATE_BYTE;j++){
	//	printf("%02x",data_A[A_idx].state[j]);
	//}
	//cout<<endl;
	//cout<<"B["<<B_idx<<"] state:";
	//for(int j=0;j<STATE_BYTE;j++){
	//	printf("%02x",data_B[B_idx].state[j]);
	//}
	//cout<<endl;*/
	////先对data_A和data_B进行排序
	//qsort(data_A,set_size,sizeof(Online_Data_Reduce),comp_struct);
	//qsort(data_B,set_size,sizeof(Online_Data_Reduce),comp_struct);
	//
	////输出data_A和data_B中所有的元素
	////for(int i=set_size-3;i<set_size;i++){
	////	Online_Data_Reduce *val=&data_A[i];
	////	unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	////	for(int j=0;j<KSLen_Reduced;j++){
	////	//	printf("%x",val->KS[j]);
	////	}
	////	printf("%u",lval);
	////	printf("_");
	////	printf("%d",val->clock_t);
	////	printf("_");
	////	for(int j=0;j<STATE_BYTE;j++){
	////		printf("%x",val->state[j]);
	////	}
	////	printf("\n");
	////}
	////cout<<endl;
	////for(int i=set_size-3;i<set_size;i++){
	////	Online_Data_Reduce *val=&data_B[i];
	////	unsigned long long lval=char_2_long(val->KS,KSLen_Reduced);
	////	for(int j=0;j<KSLen_Reduced;j++){
	////	//	printf("%x",val->KS[j]);
	////	}
	////	printf("%u",lval);
	////	printf("_");
	////	printf("%d",val->clock_t);
	////	printf("_");
	////	for(int j=0;j<STATE_BYTE;j++){
	////		printf("%x",val->state[j]);
	////	}
	////	printf("\n");
	////}
	////开始测试
	//start_cal();
	//double time[4]={0};		//测试调用一次需要多久
	//if(find_collision_sub_routine(KSD,tableName,data_A,data_B,set_size)){
	//	cout<<"success"<<endl;
	//}else
	//	cout<<"fail"<<endl;
	//end_cal(time);
	//printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);
	//delete [] data_A;
	//delete [] data_B;

	//rc4_setup();
	//offLine_table_construct_v3(5);
	//测试char2HexString
	/*u8 test[4];
	test[0]=0;
	test[1]=255;
	test[2]=254;
	test[3]=10;
	cout<<char2HexString(test,4)<<endl;*/
	//online_attack_v3(4);
	//offLine_table_construct(5);
	//NCA-2.0 online阶段测试
	//rc4_setup();
	////offLine_table_construct(4);
	//int succ=0;
	//for(int i=0;i<100;i++){
	//	cout<<"**************case:"<<i<<"**************"<<endl;
	//	if(online_attack_v2(4)){
	//		succ++;
	//		cout<<"Attack i:"<<i<<" succeed.";
	//	}else{
	//		cout<<"Attack i:"<<i<<" failed.";
	//	}
	//	cout<<endl;
	//	cout<<"****************************************"<<endl;
	//}
	//cout<<"NCA-2.0 with prefix version success probabiliy:"<<succ<<"/100"<<endl;


	//NCA-3.0 online阶段测试
	//rc4_setup();
	//int succ=0;
	//for(int i=0;i<100;i++){
	//	cout<<"**************case:"<<i<<"**************"<<endl;
	//	if(online_attack_v3(5)){
	//		succ++;
	//		cout<<"Attack i:"<<i<<" succeed.";
	//	}else{
	//		cout<<"Attack i:"<<i<<" failed.";
	//	}
	//	cout<<endl;
	//	cout<<"****************************************"<<endl;
	//}
	//cout<<"NCA-3.0 with prefix version success probabiliy:"<<succ<<"/100"<<endl;


	/*start_cal();
	double time[4];
	int a=1<<19;
	int b=1<<19;
	for(int i=0;i<a;i++){
		if((i+1) % 50000 ==0){
			cout<<"Collision finding proceed "<<setprecision(3)<<(double)i*100/a<<"%..."<<endl;
		}
		for(int j=0;j<b;j++){

		}
	}
	end_cal(time);
	printf("Time: %d hours, %d minutes, %f seconds.\n\n", (int)time[0],(int)time[1],time[2]);*/
	//线上攻击阶
	/*int succ=0;
	for(int i=0;i<100;i++){
		cout<<"**************case:"<<i<<"**************"<<endl;
		if(online_attack_v2()){
			succ++;
			cout<<"Attack i:"<<i<<" succeed.";
		}else{
			cout<<"Attack i:"<<i<<" failed.";
		}
		cout<<endl;
		cout<<"****************************************"<<endl;
	}
	cout<<"NCA-2.0 no prefix version success probabiliy:"<<"/100"<<endl;*/
	//offLine_table_construct_v1(4);
	//offLine_table_construct_v3(4);
	//for(int i=0;i<20;i++){
	//	printf("%d\n",rc4());
	//}

	/*u32 counter=0;
	u32 Sampling=200;
	for(int i=0;i<Sampling;i++){
		cout<<"------------------------------------------------------"<<endl;
		if(online_attack_v3()){
			counter++;
			cout<<"第"<<i+1<<"次攻击成功.Great!!!"<<endl;
		}else
			cout<<"第"<<i+1<<"次攻击失败."<<endl;
	}
	cout<<"NCA-3.0在Grain reduce版本上的成功率为:"<<counter<<"/"<<Sampling<<endl;*/
	//u32 counter=0;
	//u32 Sampling=200;
	//for(int i=0;i<Sampling;i++){
	//	cout<<"------------------------------------------------------"<<endl;
	//	if(online_attack_v2()){
	//		counter++;
	//		cout<<"第"<<i+1<<"次攻击成功.Great!!!"<<endl;
	//	}else
	//		cout<<"第"<<i+1<<"次攻击失败."<<endl;
	//}
	//cout<<"NCA-2.0在Grain reduce版本上的成功率为:"<<counter<<"/"<<Sampling<<endl;

	//online_attack();
	//online_attack_v3();
	////测试string2byte函数
	//u8 bArray[2];
	//string str="10a0";
	//string2byte(bArray,2,str);
	//for(int i=0;i<2;i++)
	//	printf("%x",bArray[i]);

	////测试，load一个给定目录下的所有txt文件
	//struct _finddata_t file;  
 //   long longf; 
	////system("mode con: CP SELECT=936");
	//if((longf = _findfirst("D:\\小琦\\Grain_Reduce\\NCA_3.0\\Grain_(l,d)_(2,2)\\*.txt",&file))==-1L){
	//	cout<<"文件没有找到!\n"<<endl;
	//}else{
	//	printf("%s\n",file.name);
	//	//cout<<file.name<<endl;
	//	while(_findnext(longf,&file)==0)
	//		printf("%s\n",file.name);
	//}
	//_findclose(longf); 
	
	//online_attack_v);
	//测试state read和state load函数的一致性
	/*u8 state[STATE_BYTE];
	for(int i=0;i<STATE_BYTE;i++){
		state[i]=rand() %256;
		printf("%x",state[i]);
	}
	printf("\n");
	ECRYPT_ctx_reduce* ctx=new ECRYPT_ctx_reduce;
	grain_state_load_reduce(ctx,state);
	grain_state_read_reduce(ctx,state);
	//cout<<sizeof(unsigned long)<<endl;
	for(int i=0;i<STATE_BYTE;i++){
		printf("%x",state[i]);
	}*/

	//online_attack();
	//online_attack();
	//offLine_table_construct_v3(4);
	//offLine_table_construct_v1(4);
	//offLine_table_construct(4);
	//test_time_genOutput_v3();
	//测试state_comp函数
	/*string str("0a0b000000000001 8/10000");
	string::size_type pos=str.find(" ");
	string tar=str.substr(0,pos);
	u8 state[STATE_BYTE];
	for(int i=0;i<STATE_BYTE;i++)
		state[i]=0;
	state[0]=10;
	state[1]=11;
	state[7]=1;
	//printf("%x",state[0]);
	cout<<state_comp(state,STATE_BYTE,tar)<<endl;
	*/
	//cout<<str.substr(0,pos)<<"size:"<<str.substr(0,pos).length()<<endl;
	
	//测试char_2_long函数 以及long_to_hexString函数
	/*
	u8 statrByte[4];
	for(int i=0;i<4;i++){
		statrByte[i]=0;
	}
	statrByte[0]=255;
	statrByte[1]=254;
	statrByte[3]=253;
	unsigned long long val=char_2_long(statrByte,4);
	cout<<val<<endl;
	cout<<long_to_hexString(val,4)<<endl;
	*/
	
	//测试
	/*unsigned long long data[15]={1,1,2,2,2,3,8,10,10,10,14,14,14,14,14};
	u32 counter;
	multimap<u32,unsigned long long> occurrance;
	for(int i=0;i<15;){
		counter=0;
		unsigned long long curr=data[i];
		int j=i;
		while(curr==data[j] && j<15){
			counter++;
			j++;
		}
		//counter记录了当前KSD出现的次数，j是下一个KSD第一个出现的下标。
		//只保留当前比重最大的MAX_KSD(100)个差分 建最大值堆
		cout<<curr<<"出现了："<<counter<<"次"<<endl;
		occurrance.insert(make_pair(counter,curr));
		if(occurrance.size()>3)  //删除最小的，保持最大的100个
			occurrance.erase(occurrance.begin());
		//已跳过当前重复区域，进入下一个KSD
		i=j;
	}
	multimap<u32,unsigned long long>::iterator beg=occurrance.begin();
	multimap<u32,unsigned long long>::iterator end=occurrance.end();
	for(;beg!=end;beg++){
		cout<<beg->second<<"出现了:"<<beg->first<<"次。"<<endl;
	}
	*/
	/*
	//测试grain_state_load_reduce函数
	u8 statrByte[STATE_BYTE];
	for(int i=0;i<STATE_BYTE;i++){
		statrByte[i]=rand() %256;
	}
	for(int i=0;i<STATE_BYTE;i++){
		printf("%x ",statrByte[i]);
	}
	cout<<endl;
	ECRYPT_ctx_reduce* ctx_reduce=new ECRYPT_ctx_reduce;
	grain_state_load_reduce(ctx_reduce,statrByte);
	for(int i=0;i<STATE_BYTE;i++){
		statrByte[i]=0;
	}
	grain_state_read_reduce(ctx_reduce,statrByte);
	for(int i=0;i<STATE_BYTE;i++){
		printf("%x ",statrByte[i]);
	}
	cout<<endl;
	*/
	/*//测试genOutput_diff_imp_grain_reduce函数的内存泄露
	u32 k=3;
	u32 *v=new u32[k]();
	v[0]=1;
	v[1]=3;
	v[2]=5;
	genOutput_diff_imp_grain_reduce(k,v,2);
	*/
	/*
	//测试stateBit2Byte函数的正确性
	u32* LFSR=new u32[32]();
	u32* NFSR=new u32[32]();
	NFSR[0]=1;
	NFSR[1]=1;
	LFSR[0]=1;
	LFSR[1]=1;
	LFSR[2]=1;
	LFSR[3]=1;
	LFSR[30]=1;
	LFSR[31]=1;
	u8 statrByte[STATE_BYTE];
	for(int i=0;i<STATE_BYTE;i++){
		statrByte[i]=0;
	}
	stateBit2Byte(statrByte,STATE_BYTE,LFSR,NFSR,32);
	for(int i=0;i<STATE_BYTE;i++){
		printf("%x ",statrByte[i]);
	}
	cout<<endl;
	//delete [] statrByte;
	*/
	
	/*
	//测试sampling resistance，事先给定53个内部状态bit 密钥流应该输出11个0
	ECRYPT_ctx_reduce* ctx_reduce=new ECRYPT_ctx_reduce;
	ECRYPT_ctx_reduce* ctx_reduce_1=new ECRYPT_ctx_reduce;
	u32* LFSR=new u32[32]();
	u32* NFSR=new u32[32]();
	u32* LFSR_1=new u32[32]();
	u32* NFSR_1=new u32[32]();
	for(int i=0;i<32;i++){
		LFSR[i]=(i+1)%2;
		if(i<10 || i>20)
		NFSR[i]=i % 2;

		LFSR_1[i]=(i+1)%2;
		if(i<10 || i>20)
		NFSR_1[i]=i % 2;
	}
	grain_reduce_sampling_resistance(ctx_reduce,LFSR,NFSR);
	u8* keyStream_R=new u8[KSLen_Reduced]();
	ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);
	//带固定pattern的输出
	for(int i=0;i<KSLen_Reduced;i++){
		for(int j=0;j<8;j++)
			printf("%d",(keyStream_R[i]>>j)&0x01);
		printf(" ");
	}
	printf("\n");

	u8* keyStream_R_1=new u8[KSLen_Reduced]();
	grain_reduce_sampling_resistance(ctx_reduce_1,LFSR_1,NFSR_1);
	grain_reduce_sampling_resistance_genKSBytes(ctx_reduce_1,keyStream_R_1,KSLen_Reduced);
	//不带固定pattern的输出
	for(int i=0;i<KSLen_Reduced;i++){
		for(int j=0;j<8;j++)
			printf("%d",(keyStream_R_1[i]>>j)&0x01);
		printf(" ");
	}
	printf("\n");
	*/


	/*
	//测试Grain reduce版本的正确性
	ECRYPT_ctx_reduce* ctx_reduce=new ECRYPT_ctx_reduce;
	u8* key_R=new u8[4]();
	u8* IV_R=new u8[3]();
	for(int i=0;i<4;i++){
		key_R[i]=i;
	}
	for(int i=0;i<3;i++){
		IV_R[i]=0;
	}
	ECRYPT_keysetup_reduce(ctx_reduce,key_R,32,24);
	ECRYPT_ivsetup_reduce(ctx_reduce,IV_R);
	u8* keyStream_R=new u8[KSLen]();
	//test encryption and decryption
	u8* plaintext=new u8[KSLen]();
	u8* ciphertext=new u8[KSLen]();
	for(int i=0;i<KSLen;i++){
		plaintext[i]=i;
	}
	cout<<"Plaintext:"<<endl;
	for(int i=0;i<KSLen;i++){
		printf("%x ",plaintext[i]);
	}
	cout<<endl;
	ECRYPT_encrypt_bytes_reduce(ctx_reduce,plaintext,ciphertext,KSLen);
	cout<<"Ciphertext:"<<endl;
	for(int i=0;i<KSLen;i++){
		printf("%x ",ciphertext[i]);
	}
	cout<<endl;

	ECRYPT_ctx_reduce* ctx_reduce_d=new ECRYPT_ctx_reduce;
	ECRYPT_keysetup_reduce(ctx_reduce_d,key_R,32,24);
	ECRYPT_ivsetup_reduce(ctx_reduce_d,IV_R);
	ECRYPT_decrypt_bytes_reduce(ctx_reduce_d,ciphertext,plaintext,KSLen);
	cout<<"Plaintext:"<<endl;
	for(int i=0;i<KSLen;i++){
		printf("%x ",plaintext[i]);
	}
	cout<<endl;
	delete [] key_R;
	delete [] IV_R;
	delete [] keyStream_R;
	*/
	


	//测试Grain re/*duce版本的CPU 的clock数
	//ECRYPT_ctx_reduce* ctx_reduce=new ECRYPT_ctx_reduce;
	//u8* key_R=new u8[4]();
	//u8* IV_R=new u8[3]();
	//for(int i=0;i<4;i++){
	//	key_R[i]=i;
	//}
	//for(int i=0;i<3;i++){
	//	IV_R[i]=0;
	//}
	//ECRYPT_keysetup_reduce(ctx_reduce,key_R,32,24);
	//ECRYPT_ivsetup_reduce(ctx_reduce,IV_R);
	//u8* keyStream_R=new u8[KSLen_Reduced];
	//clock_t start_R, finish_R;
	//double duration_R,speed_R;
	//start_R=clock();
	//ECRYPT_keystream_bytes_reduce(ctx_reduce,keyStream_R,KSLen_Reduced);
	//finish_R=clock();
	//duration_R=((double)finish_R-start_R)/CLOCKS_PER_SEC;
	////2.83 GHz CPU frequence
	//speed_R=duration_R*2.83*1000*1000*1000/((double)KSLen_Reduced*8);
	//printf("time：%4.4f sec\n"
	//	"The encryption speed is %3.4f cycles/bit \n"
	//	,duration_R,speed_R);
	
	
	/*
	for(int i=1;i<=6;i++){
		inputOutputDiff(i,1000);
	}
	*/
	//inputOutputDiff(4,10);

	
	//计算输出1bit密钥流需要多少个CPU clock
	//cout<<"-------------------------"<<endl;
	//ECRYPT_ctx* ctx=new ECRYPT_ctx;
	//u8* key=new u8[10]();
	//u8* IV=new u8[8]();
	//for(int i=0;i<10;i++){
	//	key[i]=0;
	//}
	//for(int i=0;i<8;i++){
	//	IV[i]=0;
	//}
	//ECRYPT_keysetup(ctx,key,80,64);
	//ECRYPT_ivsetup(ctx,IV);
	//u8* keyStream=new u8[KSLen]();
	////u32 KSLen=10;  //byte length
	//clock_t start, finish;
	//double duration, speed;
	//start=clock();
	//ECRYPT_keystream_bytes(ctx,keyStream,KSLen);
	//finish=clock();
	//duration=((double)finish-start)/CLOCKS_PER_SEC;
	////2.83 GHz CPU frequence
	//speed=duration*2.83*1000*1000*1000/((double)KSLen*8);
	////speed=duration*2.83*1000*1000*1000/((double)10000000);
	//printf("time：%4.4f sec\n"
	//	"The encryption speed is %3.4f cycles/bit \n"
	//	,duration,speed);
	//delete [] key;
	//delete [] IV;
	//delete [] keyStream;
	

	/*//helloworld test of grain v1
	ECRYPT_ctx* ctx=new ECRYPT_ctx;
	u8* key=new u8[10]();
	u8* IV=new u8[8]();
	for(int i=0;i<10;i++){
		key[i]=0;
	}
	for(int i=0;i<8;i++){
		IV[i]=0;
	}
	ECRYPT_keysetup(ctx,key,80,64);
	ECRYPT_ivsetup(ctx,IV);
	//generate keystream
	u32 KSLen=10;  //byte length
	u8* keyStream=new u8[KSLen]();
	
	ECRYPT_keystream_bytes(ctx,keyStream,KSLen);
	for(int i=0;i<KSLen;i++){
		printf("%x",keyStream[i]);
	}
	delete [] key;
	delete [] IV;
	delete [] keyStream;
	
	//测试输出差分的分布
	//选定一个输入差分的汉明重量
	//cout<<sizeof(long long)<<endl;
	
	u32 L=4;
	u32 Diff_Num=10;
	for(int i=1;i<=L;i++){
			//cout<<"\n************差分的韩明重量："<<i<<" 输出密钥流长度："<<j<<"**************"<<endl;
			//inputOutputDiff(i,Diff_Num);
	}
	*/
	//枚举并统计所有输入差分对应输出差分的分布
	//searchAllNearColStates(4);
	
	//统计每个输出差分文件的行数
	//cal_ave_rows("E:\\123\\");
	//u32 L=18;
	//u32 Diff_Num=100;
	//inputOutputDiff(L,Diff_Num);
	//cal_average_OutputDiff(L,Diff_Num);
	//cal_All_files();
	//cal_special_tables_ISD_prop();
	getchar();
	return 0;
}
//

//kevin edit, used for state loading
void grain_state_load(ECRYPT_ctx* ctx, u8* state){
	for(int i=0;i<10;i++){
		for (int j=0;j<8;++j) {
			ctx->NFSR[i*8+j]=((state[i]>>j)&1);  
		}
	}
	for(int i=10;i<20;i++){
		for (int j=0;j<8;++j) {
			ctx->LFSR[(i-10)*8+j]=((state[i]>>j)&1);  
		}
	}
}
//kevin edit for position index and rotate index
u32 posIdx(u32 pos){
	return (u32) (pos/8);
}
u32 rotateIdx(u32 pos){
	return (u32)(pos%8);
}
u8 grain_keystream_backward(ECRYPT_ctx* ctx){
	u8 L0,N0,outbit,L79,N79;
	//先保存当前的LFSR[79]和NFSR[79]
	L79=ctx->LFSR[(ctx->keysize)-1];
	N79=ctx->NFSR[(ctx->keysize)-1];
	//然后再循环移位寄存器 到上一个状态
	for (int i=(ctx->keysize)-1;i>0;--i) {
		ctx->NFSR[i]=ctx->NFSR[i-1];
		ctx->LFSR[i]=ctx->LFSR[i-1];
	}
	//利用当前LFSR[79]和NFSR[79]计算 上一个时刻的LFSR[0]和NFSR[0]
	L0=L(18)^L(29)^L(42)^L(57)^L(67)^L79;
	N0=N79^L0^N(18)^N(66)^NFTable[(N(17)<<9) | (N(20)<<8) | (N(28)<<7) | (N(35)<<6) | (N(43)<<5) | (N(47)<<4) | (N(52)<<3) | (N(59)<<2) | (N(65)<<1) | N(71)];
	//更新LFSR[0]和NFSR[0]
	ctx->NFSR[0]=N0;
	ctx->LFSR[0]=L0;
	//计算上一个时刻的输出bit
	outbit = N(79)^N(78)^N(76)^N(70)^N(49)^N(37)^N(24)^boolTable[(X4<<4) | (X3<<3) | (X2<<2) | (X1<<1) | X0];
	return outbit;
}

void ECRYPT_init(void){}
/*
 * Function: grain_keystream
 *
 * Synopsis
 *  Generates a new bit and updates the internal state of the cipher.
 */
u8 grain_keystream(ECRYPT_ctx* ctx) {
	u8 i,NBit,LBit,outbit;
	/* Calculate feedback and output bits */
	outbit = N(79)^N(78)^N(76)^N(70)^N(49)^N(37)^N(24)^boolTable[(X4<<4) | (X3<<3) | (X2<<2) | (X1<<1) | X0];
	NBit=L(80)^N(18)^N(66)^N(80)^NFTable[(N(17)<<9) | (N(20)<<8) | (N(28)<<7) | (N(35)<<6) | (N(43)<<5) | (N(47)<<4) | (N(52)<<3) | (N(59)<<2) | (N(65)<<1) | N(71)];
	LBit=L(18)^L(29)^L(42)^L(57)^L(67)^L(80);
	/* Update registers */
	for (i=1;i<(ctx->keysize);++i) {
		ctx->NFSR[i-1]=ctx->NFSR[i];
		ctx->LFSR[i-1]=ctx->LFSR[i];
	}
	ctx->NFSR[(ctx->keysize)-1]=NBit;
	ctx->LFSR[(ctx->keysize)-1]=LBit;
	return outbit;
}

/* Functions for the ECRYPT API */

void ECRYPT_keysetup(
  ECRYPT_ctx* ctx, 
  const u8* key, 
  u32 keysize,                /* Key size in bits. */ 
  u32 ivsize)				  /* IV size in bits. */ 
{
	ctx->p_key=key;
	ctx->keysize=keysize;
	ctx->ivsize=ivsize;
}

/*
 * Function: ECRYPT_ivsetup
 *
 * Synopsis
 *  Load the key and perform initial clockings.
 *
 * Assumptions
 *  The key is 10 bytes and the IV is 8 bytes. The
 *  registers are loaded in the following way:
 *  
 *  NFSR[0] = lsb of key[0]
 *  ...
 *  NFSR[7] = msb of key[0]
 *  ...
 *  ...
 *  NFSR[72] = lsb of key[9]
 *  ...
 *  NFSR[79] = msb of key[9]
 *  LFSR[0] = lsb of IV[0]
 *  ...
 *  LFSR[7] = msb of IV[0]
 *  ...
 *  ...
 *  LFSR[56] = lsb of IV[7]
 *  ...
 *  LFSR[63] = msb of IV[7]
 */
void ECRYPT_ivsetup(
  ECRYPT_ctx* ctx, 
  const u8* iv)
{
	u32 i,j;
	u8 outbit;
	/* load registers */
	for (i=0;i<(ctx->ivsize)/8;++i) {
		for (j=0;j<8;++j) {
			ctx->NFSR[i*8+j]=((ctx->p_key[i]>>j)&1);  
			ctx->LFSR[i*8+j]=((iv[i]>>j)&1);
		}
	}
	for (i=(ctx->ivsize)/8;i<(ctx->keysize)/8;++i) {
		for (j=0;j<8;++j) {
			ctx->NFSR[i*8+j]=((ctx->p_key[i]>>j)&1);
			ctx->LFSR[i*8+j]=1;
		}
	}
	/* do initial clockings */
	for (i=0;i<INITCLOCKS;++i) {
		outbit=grain_keystream(ctx);
		ctx->LFSR[79]^=outbit;
		ctx->NFSR[79]^=outbit;             
	}
}

/*
 * Function: ECRYPT_keystream_bytes
 *
 * Synopsis
 *  Generate keystream in bytes.
 *
 * Assumptions
 *  Bits are generated in order z0,z1,z2,...
 *  The bits are stored in a byte in order:
 *  
 *  lsb of keystream[0] = z0
 *  ...
 *  msb of keystream[0] = z7
 *  ...
 *  lsb of keystream[1] = z8
 *  ...
 *  msb of keystream[1] = z15
 *  ...
 *  ...
 *  ...
 *  Example: The bit keystream: 10011100 10110011 ..
 *  corresponds to the byte keystream: 39 cd ..
 */
void ECRYPT_keystream_bytes(
  ECRYPT_ctx* ctx, 
  u8* keystream, 
  u32 msglen)
{
	u32 i,j;
	for (i = 0; i < msglen; ++i) {
		keystream[i]=0;
		for (j = 0; j < 8; ++j) {
			keystream[i]|=(grain_keystream(ctx)<<j);
		}
	}
}
//kevin edit for backward keystream calculate
void ECRYPT_keystream_backward_bytes(
  ECRYPT_ctx* ctx, 
  u8* keystream, 
  u32 msglen)
{
	u32 i,j;
	for (i = 0; i < msglen; ++i) {
		keystream[i]=0;
		for (j = 0; j < 8; ++j) {
			keystream[i]|=(grain_keystream_backward(ctx)<<j);
			//grain_keystream_backward(ctx);
		}

	}
	/*//正向输出
	for (i = 0; i < msglen; ++i) {
		keystream[i]=0;
		for (j = 0; j < 8; ++j) {
			//keystream[i]|=(grain_keystream_backward(ctx)<<j);
			keystream[i]|=(grain_keystream(ctx)<<j);
		}

	}
	*/
	
}

void ECRYPT_encrypt_bytes(
  ECRYPT_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen)
{
	u32 i,j;
	u8 k;
	for (i = 0; i < msglen; ++i) {
		k=0;
		for (j = 0; j < 8; ++j) {	
			k|=(grain_keystream(ctx)<<j);
		}
		ciphertext[i]=plaintext[i]^k;
	}
}

void ECRYPT_decrypt_bytes(
  ECRYPT_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen)
{
	u32 i,j;
	u8 k=0;
	for (i = 0; i < msglen; ++i) {
		k=0;
		for (j = 0; j < 8; ++j) {
			k|=(grain_keystream(ctx)<<j);
		}
		plaintext[i]=ciphertext[i]^k;
	}
}

/*
unsigned int NFSR_feedBackFunc(){
	return LFSR[0]^NFSR[62]^NFSR[60]^NFSR[52]^NFSR[45]^NFSR[37]^NFSR[33]^NFSR[28]^NFSR[21]^NFSR[14]^
		NFSR[9]^NFSR[0]^(NFSR[63]&NFSR[60])^(NFSR[37]^NFSR[33])^(NFSR[15]&NFSR[9])^(NFSR[60]&NFSR[52]&NFSR[45])^
		(NFSR[33]&NFSR[28]&NFSR[21])^(NFSR[63]&NFSR[45]&NFSR[28]&NFSR[9])^(NFSR[60]&NFSR[52]&NFSR[37]&NFSR[33])^
		(NFSR[63]&NFSR[60]&NFSR[21]&NFSR[15])^(NFSR[63]&NFSR[60]&NFSR[52]&NFSR[45]&NFSR[37])^(NFSR[33]&NFSR[28]&NFSR[21]&NFSR[15]&NFSR[9])^
		(NFSR[52]&NFSR[45]&NFSR[37]&NFSR[33]&NFSR[28]&NFSR[21]);
}

unsigned int LFSR_feedBackFunc(){
	return LFSR[62]^LFSR[51]^LFSR[38]^LFSR[23]^LFSR[13]^LFSR[0];
}

unsigned int filter_func_h(){
	return NFSR[1]^NFSR[2]^NFSR[4]^NFSR[10]^NFSR[31]^NFSR[43]^NFSR[56]^func_h(LFSR[3],LFSR[25],LFSR[46],LFSR[64],NFSR[63]);
}

unsigned int func_h(unsigned int X0,unsigned int X1,unsigned int X2,unsigned int X3,unsigned int X4){
	return X1^X4^(X0&X3)^(X2&X3)^(X3&X4)^(X0&X1&X2)^(X0&X2&X3)^(X0&X2&X4)^(X1&X2&X4)^(X2&X3&X4);
}

void state_update(bool isInit,unsigned int output){
	//update NFSR
	unsigned int nb_NFSR;
	//if is in the initialization,the output bit will be feedback to update
	if(isInit)
		nb_NFSR=NFSR_feedBackFunc()^output;
	else
		nb_NFSR=NFSR_feedBackFunc();
	for(int i=0;i<79;i++){
		NFSR[i]=NFSR[i+1];
	}
	NFSR[79]=nb_NFSR;
	//update LFSR
	unsigned int nb_LFSR;
	if(isInit)
		nb_LFSR=LFSR_feedBackFunc()^output;
	else
		nb_LFSR=LFSR_feedBackFunc();
	for(int i=0;i<79;i++){
		LFSR[i]=LFSR[i+1];
	}
	LFSR[79]=nb_LFSR;
}

void keyInit(){
	//load key bits to NFSR
	for(int i=0;i<80;i++){
		NFSR[i]=KEY[i];
	}
	//load IV bits to LFSR
	for(int i=0;i<64;i++){
		LFSR[i]=IV[i];
	}
	for(int i=64;i<80;i++){
		// all other bits set to zero
		//LFSR.set(i);
		LFSR[i]=1;
	}
	// clock 160 times without producing any running key.
	// the output function is fed back and xored with the input, both to NFSR and LFSR
	unsigned int output;
	for(int i=0;i<160;i++){
		output=filter_func_h();
		state_update(true,output);
	}
}
//generate a bitLen binary sequence from the current state.
unsigned int* KSGenerator(unsigned int bitLen){
	unsigned int* res=new unsigned int[bitLen]();
	for(int i=0;i<bitLen;i++){
		res[i]=filter_func_h();
		state_update(false,0);
	}
	for(int i=0;i<80;i++){
		cout<<res[i]<<ends;
	}
	return res;
}

*/