//This is a file for time calculation
//Author:KevinLee         e-mail:lizhenqi@is.iscas.ac.cn 
//Copyright 2011.

#include "stdafx.h"
#include "head.h"

clock_t start,finish;
	
void start_cal(){
	start = clock();
}

void end_cal(double *time){
	double duration,seconds;
	int hours,minutes;
	finish = clock();
	duration = (double)(finish-start)/CLOCKS_PER_SEC;
	hours = (int)duration/3600;
	minutes = (int)(duration-hours*3600)/60;
	seconds = duration-hours*3600-minutes*60;
	time[0]=hours;
	time[1]=minutes;
	time[2]=seconds;
	time[3]=duration;
	return;
}