#include "stdafx.h"
#include "head.h"


long long sum=0;
u32 table_num=0;
void cal_All_files(){
	u32 L=4;
	u32 d=2;
	//u32 HM=2;
	//定义一个计数器，用来检测试验的进度
	long long counter=0;
	//预先存储一个估计的总的计算量
	//long long t_Sum[5]={256,12720,669920,26294360,820384032};
	for(int i=3;i<=L;i++){
		//dir+="Grain_data_KSLen_"+int_2_string(i)+"_L_1-";
		u32 HM=i*8;
		u32 N=i*8;
		for(int j=1;j<=d;j++){
			//string dir="D:\\Grain_data_imp\\Grain_data_KSLen_"+int_2_string(i)+"_L_1-";
			string dir="D:\\Grain_data_imp\\Grain_data_KSLen_"+int_2_string(i)+"_L_1-";
			dir+=int_2_string(j)+"\\";
			cout<<"--------------proceed:"<<dir<<"--------------------"<<endl;
			for(int m=0;m<=HM;m++){
				//初始化组合向量
				
				if(m>=1){
					u32 *v=new u32[m+1]();
					for(int k=0;k<m;k++){
						v[k]=k+1;
					}
					v[m]=N+1;
					//根据当前组合进行操作
					u8 *f_name_1=new u8[i]();
					sum+=sub_routine(m,v,i,dir);
					//to be continued..
					while(sub_routine_enumerate(m,v,i,dir)){
						if((++counter) % 60000 ==0)
							cout<<"proceed "<<setprecision(3)<<(double)counter*100/pow((double)2,i*8)<<"%..."<<endl;
					}
					delete [] v;
				}else{
				//m=0
					u32 *v=new u32[m+1]();
					sum+=sub_routine(m,v,i,dir);
					delete [] v;
				}
				
			}
			//输出平均值
			if(table_num!=0){
				ofstream outfile;
				//string outName="log_special_states.txt";
				string outName="log_org_states.txt";
				string outDir="D:\\Grain_data_imp\\";
				outDir.append(outName);
				outfile.open(outDir.c_str(),ofstream::app);
				if(outfile){
					//outfile<<"(d,l):("<<j<<","<<i<<")对应的平均special table(HM:"<<HM<<")的大小为:"<<(double)sum/table_num
					//<<" 总共有："<<table_num<<"个special tables"<<endl;
					outfile<<"(d,l):("<<j<<","<<i<<")对应的平均org table(HM:"<<HM<<")的大小为:"<<(double)sum/table_num
					<<" 总共有："<<table_num<<"个org tables"<<endl;
					//cout<<"(d,l):("<<j<<","<<i<<")对应的平均special table(HM:"<<HM<<")的大小为:"<<(double)sum/table_num
					//<<" 总共有："<<table_num<<"个special tables"<<endl;
					cout<<"(d,l):("<<j<<","<<i<<")对应的平均org table(HM:"<<HM<<")的大小为:"<<(double)sum/table_num
					<<" 总共有："<<table_num<<"个org tables"<<endl;
				}
				outfile.close();
			}
			
			counter=0;
			sum=0;
			table_num=0;
		}
	}
}
bool sub_routine_enumerate(u32 m,u32 *v,int i,string dir){
	for(int k=m-1;k>=0;k--){
		if(v[k]+1!=v[k+1]){
			v[k]++;
			//根据当前组合进行操作 //继续搜索
			for(int u=k+1;u<m;u++)
				v[u]=v[u-1]+1;
			sum+=sub_routine(m,v,i,dir);
			
			return true;
		}
	}
	return false;
}

long long sub_routine(u32 m, u32 *v, u32 i, string dir){
	u8 *f_name=new u8[i]();
	//if(m>0){
	for(int u=0;u<m;u++){
		u32 p=posIdx(v[u]-1);
		u32 r=rotateIdx(v[u]-1);
		f_name[p]=f_name[p]^(1<<r);
	}
	//}
	string fileName=char2HexString(f_name,i);
	fileName+=".txt";
	delete [] f_name;
	return cal_table_size(dir,fileName);
	
}

long long cal_table_size(string dir,string fileName){
	dir.append(fileName);
	ifstream infile;
	map<string,string> data;
	infile.open(dir.c_str());
	long long i=0;
	if(infile){
		table_num++;
		//cout<<"file \'"<<fileName<<"\' start to load."<<endl;
		//cout<<".........."<<endl;
		char val[2048];
		
		while(infile.getline(val,sizeof(val))){
			i++;
		}
		//cout<<"equation number:"<<i<<endl;
	}else
		//cout<<"file \'"<<fileName<<"\' fail to load."<<endl;	
	infile.close();
	return i;
	
}
//统计重量小于等于2的所有ISD对应的KSD table的覆盖率
set<string> ISD_data;
void cal_special_tables_ISD_prop(){
	u32 L=4;
	u32 d=3;
	u32 HM=2;
	//定义一个计数器，用来检测试验的进度
	long long counter=0;
	//预先存储一个估计的总的计算量
	long long t_Sum[4]={160,12881,682801,26977161};
	for(int i=1;i<=L;i++){
		//dir+="Grain_data_KSLen_"+int_2_string(i)+"_L_1-";
		//u32 HM=i*8;
		u32 N=i*8;
		for(int j=1;j<=d;j++){
			//清空缓存
			ISD_data.clear();
			string dir="D:\\Grain_data_imp\\Grain_data_KSLen_"+int_2_string(i)+"_L_1-";
			dir+=int_2_string(j)+"\\";
			cout<<"--------------proceed:"<<dir<<"--------------------"<<endl;
			for(int m=0;m<=HM;m++){
				//初始化组合向量
				
				if(m>=1){
					u32 *v=new u32[m+1]();
					for(int k=0;k<m;k++){
						v[k]=k+1;
					}
					v[m]=N+1;
					//根据当前组合进行操作
					u8 *f_name_1=new u8[i]();
					sub_routine_SP(m,v,i,dir);
					//to be continued..
					while(sub_routine_enumerate_SP(m,v,i,dir)){
						if((++counter) % 10000 ==0)
							cout<<"proceed "<<setprecision(3)<<(double)counter*100/pow((double)2,i*8)<<"%..."<<endl;
					}
					delete [] v;
				}else{
				//m=0
					u32 *v=new u32[m+1]();
					sub_routine_SP(m,v,i,dir);
					delete [] v;
				}
				
			}
		
			ofstream outfile;
			//string outName="log_special_states.txt";
			string outName="Special_tables_ISD_coverage.txt";
			string outDir="D:\\Grain_data_imp\\";
			outDir.append(outName);
			outfile.open(outDir.c_str(),ofstream::app);
			if(outfile){
				outfile<<"(d,l):("<<j<<","<<i<<")对应的special table的ISD的覆盖率为"<<setprecision(3)<<(double)ISD_data.size()/t_Sum[j-1]<<endl;
				cout<<"(d,l):("<<j<<","<<i<<")对应的special table的ISD的覆盖率为"<<setprecision(3)<<(double)ISD_data.size()/t_Sum[j-1]<<endl;
				//outfile<<"(d,l):("<<j<<","<<i<<")对应的平均org table(HM:"<<HM<<")的大小为:"<<(double)sum/table_num
				//<<" 总共有："<<table_num<<"个org tables"<<endl;
				//cout<<"(d,l):("<<j<<","<<i<<")对应的平均special table(HM:"<<HM<<")的大小为:"<<(double)sum/table_num
				//<<" 总共有："<<table_num<<"个special tables"<<endl;
				//cout<<"(d,l):("<<j<<","<<i<<")对应的平均org table(HM:"<<HM<<")的大小为:"<<(double)sum/table_num
				//<<" 总共有："<<table_num<<"个org tables"<<endl;
			}
			outfile.close();
		
			
			counter=0;
			sum=0;
			table_num=0;
		}
	}
}


bool sub_routine_enumerate_SP(u32 m,u32 *v,int i,string dir){
	for(int k=m-1;k>=0;k--){
		if(v[k]+1!=v[k+1]){
			v[k]++;
			//根据当前组合进行操作 //继续搜索
			for(int u=k+1;u<m;u++)
				v[u]=v[u-1]+1;
				sub_routine_SP(m,v,i,dir);
			
			return true;
		}
	}
	return false;
}

void sub_routine_SP(u32 m, u32 *v, u32 i, string dir){
	u8 *f_name=new u8[i]();
	//if(m>0){
	for(int u=0;u<m;u++){
		u32 p=posIdx(v[u]-1);
		u32 r=rotateIdx(v[u]-1);
		f_name[p]=f_name[p]^(1<<r);
	}
	//}
	string fileName=char2HexString(f_name,i);
	fileName+=".txt";
	delete [] f_name;
	cal_table_size_SP(dir,fileName);
	
}

void cal_table_size_SP(string dir,string fileName){
	dir.append(fileName);
	ifstream infile;
	infile.open(dir.c_str());
	if(infile){
		//cout<<"file \'"<<fileName<<"\' start to load."<<endl;
		//cout<<".........."<<endl;
		char val[2048];
		while(infile.getline(val,sizeof(val))){
			string str(val);
			string::size_type pos=str.find(" ");
			//extract the key linear equation
			string ISD=str.substr(0,pos);
			ISD_data.insert(ISD);
		}
		//cout<<"equation number:"<<i<<endl;
	}else
		//cout<<"file \'"<<fileName<<"\' fail to load."<<endl;	
	infile.close();
}