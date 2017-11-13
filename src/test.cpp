//============================================================================
// Name        : tsparser.cpp
// Author      : wdd
// Version     :
// Copyright   :
// Description : test ts parser
//============================================================================

#include <iostream>
using namespace std;
#include "ts.h"
int delta=0;
FILE *audio = fopen("./1.mp2","w+");
void cb(ts::stream_data* data){
	if(data->_s_type==ts::mpx){
		cout<<"type:"<<data->_s_type<<"\tlen:"<<data->_len<<"\tpts:"<<data->_pts
				<<"\tdts:"<<data->_dts<<"\tdelta:"<<data->_pts-delta<<endl;
		delta=data->_pts;
		fwrite(data->_data,1,data->_len,audio);
	}
}
int main() {
	ts::demuxer demxer(cb);
	FILE *file = fopen("./haha.ts","r");
	unsigned char data[188]={0};

	while(fread(data,1,188,file)>0){
		demxer.put_buffer(data);
	}
	fclose(audio);
	return 0;
}
