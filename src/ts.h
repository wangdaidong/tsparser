/*
 * ts.h
 *
 *  Created on: 2017年8月3日
 *      Author: root
 */

#ifndef TS_H_
#define TS_H_
#include <stdio.h>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <string>
#include <string.h>
#include <iostream>
#include <map>
#include <vector>
#include <functional>
using namespace std;

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned long long uint64;

namespace ts {
enum stream_type {
	invalid = -1,
	mpx = 0x03/*x=1,2,3 refrence ISO_IEC_11172*/,
	aac = 0xf,
	h264 = 0x1b,
	h265 = 0x27
};

struct stream_data {
	int _id = 0; //stream id
	int _flag = 0; //flag(0x00:invalid;0x01:start，has pes package;0x10:transporting)
	stream_type _s_type = invalid;
	const uint8* _data = 0; //data
	int _len = 0; //data length
	long long _pts = 0; //pts
	long long _dts = 0; //dts
	stream_data(int id, int flag, stream_type s_type, const uint8* data,
			int len, long long pts, long long dts) :
			_id(id), _flag(flag), _s_type(s_type), _data(data), _len(len), _pts(
					pts), _dts(dts) {
	}
};

typedef std::function<void(stream_data*)> Data_CB;

struct pgm_table {
	uint16 program_number = 0; //16;
	uint8 reserved_3 = 0; //3;
	uint16 program_map_PID = 0; //13
};

struct pmt_stream_info {
	uint8 stream_type; //8
	uint8 reserved_0; //3
	uint16 elementary_PID; //13
	uint8 reserved_1; //4
	uint16 ES_info_length; //12
};

class ts_header {
public:
	ts_header() = default;
	ts_header(const unsigned char* buff) {
		parse(buff);
	}
	~ts_header() = default;
	void parse(const unsigned char* buff);
public:
	uint8 sync_byte = 0; //8bit,同步字节，固定为0x47，表示后面的是一个TS分组，当然， 后面包中的数据是不会出现0x47的
	bool transport_error_indicator = false; //1bit,传输错误标志位，一般传输错误的话就不会处理这个包了
	bool payload_unit_start_indicator = false; //1bit,有效负载的开始标志，根据后面有效负载的内容不同功能也不同
	//payload_unit_start_indicator为1时，在前4个字节之后会有一个调整字节， 它的数值决定了负载内容的具体开始位置。
	bool transport_priority = false;      //1bit,传输优先级位，1表示高优先级
	uint16 pid = 0; //有效负载数据的类型 13bit
	uint8 transport_scrambling_control = 0; //2bit,加密标志位,00表示未加密
	uint8 adaption_field_control = 0; //2bit,调整字段控制,。01仅含有效负载，10仅含调整字段，11含有调整字段和有效负载。为00的话解码器不进行处理。
	uint8 continuity_counter = 0; //4bit,一个4bit的计数器，范围0-15

	//不再标准中，自己添加一个playload data offset方便计算,同时如果小于0则认为解析失败
	short playload_offset = 0;

};

class ts_sdt {
	//sercive description table
public:
	ts_sdt() = default;
	ts_sdt(const unsigned char *buff) {
		parse(buff);
	}
	~ts_sdt() = default;
	void parse(const unsigned char* buff);
public:
	uint8 table_id = 0; //8
	bool section_syntax_indicator = false; //1 通常设为“1”
	bool reserved_future_use_0 = false; //1
	uint8 reserved_0 = 0; //2
	uint16 section_length = 0; //12
	uint16 transport_stream_id = 0; //16 给出TS识别号
	uint8 reserved_1 = 0; //2
	uint8 version_number = 0; //5
	bool current_next_indicator = false; //1
	uint8 section_number = false; //8
	uint8 last_section_number = 0; //8
	uint16 original_nerwork_id = 0; //16
	uint8 reserved_future_use_1 = 0; //8

	uint16 service_id = 0; //16
	uint8 reserved_future_use_2 = 0; //6
	bool EIT_schedule_flag = false; //1
	bool EIT_present_following_flag = false; //1
	uint8 running_status = 0; //3
	bool freed_CA_mode = false; //1
	uint16 descriptors_loop_length = 0; //12

	uint8 descriptor_tag = 0; //8
	uint8 descriptor_length = 0; //8
	uint8 service_type = 0; //8
	uint8 service_provider_name_length = 0; //8
	string provider_name;
	uint8 service_name_length = 0; //8
	string service_name;

	uint32 CRC_32 = 0; //32
};

class ts_pat {
	//iso 2.4.4.3
public:
	ts_pat() = default;
	~ts_pat() = default;
	ts_pat(const unsigned char* buff) {
		parse(buff);
	}
	void parse(const unsigned char* buff);
	bool is_pmt(uint16 pid);
public:
	uint8 table_id = 0; //8; //固定为0x00，标志是该表是PAT
	bool section_syntax_indicator = false; //1; //段语法标志位，固定为1
	bool zero = false; //1; //0
	uint8 reserved_0 = 0; //2; //保留位
	uint16 section_length = 0; //12;//表示有用的字节数，包括CRC32
	uint16 transport_stream_id = 0; //16;//该传输流的ID，区别于一个网络中其它多路复用的流
	uint8 reserved_1 = 0; //2; //保留位
	uint8 version_number = 0; //5; //范围0-31，表示PAT的版本号
	bool current_next_indicator = false; // 1; //发送的PAT是当前有效还是下一个PAT有效
	uint8 section_number = 0; //8; //分段的号码。PAT可能分为多段传输，第一段为00，以后每个分段加1，最多可能有256个分段
	uint8 last_section_number = 0; //8; //最后一个分段的号码

	map<int, pgm_table> pgms;

	uint32 CRC_32 = 0; //32;
};

class ts_pmt {
public:
	ts_pmt() = default;
	~ts_pmt() = default;
	void parse(const unsigned char* buff);
	bool is_element_pid(uint16 pid);
public:
	uint8 table_id = 0; //8
	bool section_syntax_indicator = false; //1
	bool zero = false;
	uint8 reserved_0 = 0; //2
	uint16 section_length = 0; //12
	uint16 program_number = 0; //16
	uint8 reserved_1 = 0; //2
	uint8 version_number = 0; //5
	bool current_next_indicator = false; //1
	uint8 section_number = 0; //8
	uint8 last_section_number = 0; //8
	uint8 reserved_2 = 0; //3
	uint16 PCR_PID = 0; //13
	uint8 reserved_3 = 0; //4
	uint16 program_info_length = 0; //12
	std::map<uint16, pmt_stream_info> stream_info;
	uint32 CRC_32 = 0; //32
};

class ts_psi {
public:
	ts_psi() = default;
	~ts_psi() = default;
	ts_sdt _sdt;
	ts_pat _pat;
	ts_pmt _pmt;
};

class stream {
#define BUFFER_SIZE 1024*1024*4
public:
	stream() = default;
	stream(uint16 id, uint8 s_type, Data_CB cb, const char* file_path);
	~stream();
	void parse(const unsigned char* buff, int buff_len, bool pes);
private:
	int get_aac_buffer(const unsigned char* data, int data_len, int& start_pos,
			int& buffer_len);
	int get_mpx_buffer(const unsigned char* data, int data_len, int& start_pos,
			int& buffer_len);
	void parse_buffer(stream_data* s_data);
	void parse_pictrue(stream_data* s_data);
	void parse_aac(stream_data* s_data);
	void parse_mpx(stream_data* s_data);
	uint16 _id = 0;
	stream_type _stream_type = invalid; //0x1b h264; 0xf aac; 0x27 h265
	uint8 _stream_id = 0; //audio:110x xxxx; video:1110 xxxx

	uint64 _pts = 0;
	uint64 _pre_pts = 0;
	uint64 _last_pts = 0;
	uint64 _dts = 0;
	uint64 _pre_dts = 0;

	Data_CB _cb = nullptr;
	FILE* _file = nullptr;

	uint8* _frame_data = new uint8[BUFFER_SIZE];
	uint32 _frame_len = 0;
	uint32 _additonal_pts = 0; //在音频流中两个pes包之间有多个音频帧，从接收到pes包之后的第二帧pts需要额外增加
};

class demuxer {
public:
	demuxer() = default;
	demuxer(Data_CB cb, const char* file_path = nullptr);
	~demuxer() = default;
	int put_buffer(const unsigned char* buff);
private:
	bool has_stream(int pid);
	map<int, std::shared_ptr<stream>> m_streams;
	ts_psi m_psi;
	Data_CB m_cb = nullptr;
	const char* _file_path = nullptr;
};

} /* namespace ts */

#endif /* TS_H_ */
