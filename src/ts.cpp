/*
 * ts.cpp
 *
 *  Created on: 2017年8月3日
 *      Author: root
 */

#include "ts.h"

namespace ts {

/**
 * 解析ts的包头
 * @param buff
 */
void ts_header::parse(const unsigned char* buff) {
	sync_byte = buff[0];
	transport_error_indicator = buff[1] & 0x80;
	payload_unit_start_indicator = buff[1] & 0x40;
	transport_priority = buff[1] & 0x20;
	pid = ((buff[1] & 0x1f) << 8) + buff[2];
	transport_scrambling_control = (buff[3] & 0xc0) >> 6;
	adaption_field_control = (buff[3] & 0x30) >> 4;
	continuity_counter = buff[3] & 0x0f;

	//判断同步字节
	if (sync_byte != 0x47) {
		playload_offset = -1;
		return;
	}

	//判断传输错误标志
	if (transport_error_indicator) {
		playload_offset = -2;
		return;
	}

	//adaption_field_control==2 无playload data
	if (adaption_field_control == 2) {
		playload_offset = -3;
		return;
	}

	//跳过header获取数据
	playload_offset += 4;

	//adaption_field_control==3 跳过adaption_field 读取playload data
	if (adaption_field_control == 3)
		playload_offset += buff[4] + 1;

	//跳过data_byte 读取playload data ISO/IEC 13818-1 p19
	//tsheader.playload_offset += 1;
	//return tsheader;
}

/**
 * 解析SDT
 * @param buff
 */
void ts_sdt::parse(const unsigned char* buff) {
	buff++;
	table_id = buff[0]; //8
	section_syntax_indicator = (buff[1] & 0x80) >> 7; //1 通常设为“1”
	reserved_future_use_0 = (buff[1] & 0x40) >> 6; //1
	reserved_0 = (buff[1] & 0x30) >> 4; //2
	section_length = ((buff[1] & 0x0f) << 8) + buff[2]; //12
	transport_stream_id = (buff[3] << 8) + buff[4]; //16 给出TS识别号
	reserved_1 = (buff[5] & 0xc0) >> 6;
	version_number = (buff[5] & 0x3e) >> 1; //5
	current_next_indicator = buff[5] & 0x01; //1
	section_number = buff[6]; //8
	last_section_number = buff[7]; //8
	original_nerwork_id = (buff[8] << 8) + buff[9]; //16
	reserved_future_use_1 = buff[10]; //8

	service_id = (buff[11] << 8) + buff[12]; //16
	reserved_future_use_2 = (buff[13] & 0xfc) >> 2; //6
	EIT_schedule_flag = (buff[13] & 0x02) >> 1; //1
	EIT_present_following_flag = (buff[13] & 0x01); //1
	running_status = (buff[14] & 0xe0) >> 5; //3
	freed_CA_mode = (buff[14] & 0x10) >> 4; //1
	descriptors_loop_length = ((buff[14] & 0x0f) << 8) + buff[15]; //12
	descriptor_tag = buff[16]; //8
	descriptor_length = buff[17]; //8
	service_type = buff[18]; //8
	service_provider_name_length = buff[19]; //8
	char temp0[service_provider_name_length + 1];
	temp0[service_provider_name_length] = '\0';
	memcpy(temp0, &buff[20], service_provider_name_length);
	provider_name = temp0;

	service_name_length = buff[20 + service_provider_name_length]; //8
	char temp1[service_name_length + 1];
	temp1[service_name_length] = '\0';
	memcpy(temp1, &buff[21 + service_provider_name_length],
			service_name_length);
	service_name = temp1;

	int offset = 21 + service_provider_name_length + service_name_length;
	CRC_32 = (buff[offset] << 24) + (buff[offset + 1] << 16)
			+ (buff[offset + 2] << 8) + (buff[offset + 3]);
}

/**
 * 解析PAT，获取节目标号和ID的对应关系
 * @param buff
 */
void ts_pat::parse(const unsigned char* buff) {
	buff++;
	table_id = buff[0]; //8; //固定为0x00，标志是该表是PAT
	section_syntax_indicator = (buff[1] & 0x80) >> 7; //1; //段语法标志位，固定为1
	zero = (buff[1] & 0x40) >> 6; //1; //0
	reserved_0 = (buff[1] & 0x30) >> 4; //2; //保留位
	section_length = ((buff[1] & 0x0f) << 8) + buff[2]; //12;//表示有用的字节数，包括CRC32
	transport_stream_id = (buff[3] << 8) + buff[4]; //16;//该传输流的ID，区别于一个网络中其它多路复用的流
	reserved_1 = (buff[5] & 0xc0) >> 6; //2; //保留位
	version_number = (buff[5] & 0x3e) >> 1; //5; //范围0-31，表示PAT的版本号
	current_next_indicator = buff[5] & 0x01; // 1; //发送的PAT是当前有效还是下一个PAT有效
	section_number = buff[6]; //8; //分段的号码。PAT可能分为多段传输，第一段为00，以后每个分段加1，最多可能有256个分段
	last_section_number = buff[7]; //8; //最后一个分段的号码

	int crc32 = section_length - 1;
	CRC_32 = (buff[crc32] << 24) + (buff[crc32 + 1] << 16)
			+ (buff[crc32 + 2] << 8) + buff[crc32 + 3];

	int pgm_size = (section_length - 9) / 4;
	for (int i = 0; i < pgm_size; i++) {
		pgm_table t;
		t.program_number = (buff[8 + 4 * i] << 8) + buff[9 + 4 * i]; //16;
		t.reserved_3 = (buff[10 + 4 * i] & 0xe0) >> 5; //3;
		t.program_map_PID = ((buff[10 + 4 * i] & 0x1f) << 8) + buff[11 + 4 * i]; //13
		pgms[t.program_number] = t;
	}
}

/**
 * 通过PID查询是否存在对应的节目
 * @param pid
 * @return
 */
bool ts_pat::is_pmt(uint16 pid) {
	for (auto & ele : pgms) {
		if (ele.second.program_map_PID == pid)
			return true;
	}
	return false;
}

/**
 * 解析PMT，获取流的信息.
 * @param buff
 */
void ts_pmt::parse(const unsigned char* buff) {
	buff++;
	table_id = buff[0]; //8
	section_syntax_indicator = (buff[1] & 0x80) >> 7; //1
	zero = (buff[1] & 0x40) >> 6; //1
	reserved_0 = (buff[1] & 0x30) >> 4; //2
	section_length = ((buff[1] & 0x0f) << 8) + buff[2]; //12
	program_number = (buff[3] << 8) + buff[4]; //16
	reserved_1 = (buff[5] & 0xc0) >> 6; //2
	version_number = ((buff[5] & 0x3e) >> 1); //5
	current_next_indicator = buff[5] & 0x01; //1
	section_number = buff[6]; //8
	last_section_number = buff[7]; //8
	reserved_2 = (buff[8] & 0xe0) >> 5; //3
	PCR_PID = ((buff[8] & 0x1f) << 8) + buff[9]; //13
	reserved_3 = (buff[10] & 0xf0) >> 4; //4
	program_info_length = ((buff[10] & 0x0f) << 8) + buff[11]; //12

	int data_len = section_length + 3;
	CRC_32 = (buff[data_len - 4] << 24) + (buff[data_len - 3] << 16)
			+ (buff[data_len - 2] << 8) + buff[data_len - 1];
	int info_start = 12 + program_info_length;
	int info_end = data_len - 4;
	for (int pos = info_start; pos < info_end;) {
		if (pos + 5 > info_end)
			break;
		pmt_stream_info info;
		info.stream_type = buff[pos];
		info.reserved_0 = (buff[pos + 1] & 0xe0) >> 5;
		info.elementary_PID = ((buff[pos + 1] & 0x1f) << 8) + buff[pos + 2];
		info.reserved_1 = (buff[pos + 3] & 0xf0) >> 4;
		info.ES_info_length = ((buff[pos + 3] & 0x0f) << 8) + buff[pos + 4];
		pos = pos + info.ES_info_length + 5;
		stream_info[info.elementary_PID] = info;
	}
}

/**
 * 通过PID查询是否存在对应的流
 * @param pid
 * @return
 */
bool ts_pmt::is_element_pid(uint16 pid) {
	return (stream_info.find(pid) != stream_info.end());
}

/**
 * Constructor
 * @param id: stream id
 * @param s_type: stream type 0x1b h264; 0xf aac; 0x27 h265
 * @param cb: callback function
 * @param file_path: dump stream to file in to the path if not eq nullptr
 */
stream::stream(uint16 id, uint8 s_type, Data_CB cb, const char* file_path) {
	_id = id;
	_stream_type = stream_type(s_type);
	_cb = cb;
	if (file_path) {
		char file[100] = { 0 };
		const char* file_type;
		switch (_stream_type) {
		case h264:
			file_type = "h264";
			break;
		case aac:
			file_type = "aac";
			break;
		case h265:
			file_type = "h265";
			break;
		default:
			file_type = "unknown";
			break;
		}
		sprintf(file, "%s%d.%s", file_path, (int) _id, file_type);
		_file = fopen(file, "w+");
	}
}

/**
 * Destructor
 */
stream::~stream() {
	if (_file)
		fclose(_file);
	if (_frame_data)
		delete[] _frame_data;
}

/**
 * 解析一帧aac数据
 * @param data: 输入数据buffer
 * @param data_len: 输入数据长度
 * @param start_pos： 第一帧开始位置
 * @param buffer_len：第一帧数据长度
 * @return 0成功
 */
int stream::get_aac_buffer(const unsigned char* data, int data_len,
		int& start_pos, int& buffer_len) {
	//各个sample对应的每帧acc的pts
	static int addPts[13] = { 960, 1045, 1440, 1920, 2089, 2880, 3840, 4180,
			5760, 7680, 8359, 11520, 12539 };
	start_pos = buffer_len = 0;
	int i = 0;
	for (i = 0; i < (data_len - 9); i++) {
		//aac包头判断
		if ((data[i] & 0xff) == 0xff && (data[i + 1] & 0xf0) == 0xf0) {
			int hi = data[i + 3] & 0x03;
			int mid = data[i + 4] & 0xff;
			int low = data[i + 5] & 0xe0;
			int bufferlen = ((hi << 16) + (mid << 8) + (low)) >> 5;
			int sample_rate = (data[i + 2] & 0x3c) >> 2;
			//数据传输有丢失 导致
			if (bufferlen <= 0) {
				return -2;
			}

			//int frames = (data[i + 6] & 0xc0);
			//int header_len = (data[i+1]&0x01)==1?7:9;
			//如果检测到的数据长度恰好在边界上，则直接取数据
			if (i + bufferlen + 1 == data_len || i + bufferlen == data_len) {
				start_pos = i;
				buffer_len = bufferlen;
				if ((sample_rate >= 0 && sample_rate < 13)) {
					_pts += _additonal_pts;
					_additonal_pts = addPts[sample_rate];
				}
				return 1;
			}
			//如果检测到的数据长度比送进的数据长度长，则返回检测失败
			if (i + bufferlen + 1 > data_len)
				return -1;

			//正常情况一帧的结束，后面紧接着一帧的开始
			if ((data[i + bufferlen] & 0xff) == 0xff
					&& (data[i + bufferlen + 1] & 0xf0) == 0xf0) {
				start_pos = i;
				buffer_len = bufferlen;
				if ((sample_rate >= 0 && sample_rate < 13)) {
					_pts += _additonal_pts;
					_additonal_pts = addPts[sample_rate];
				}
				return 1;
			}
			return -1;
		}
	}
	return -1;
}

/**
 * 解析acc
 * @param s_data
 */
void stream::parse_aac(stream_data* s_data) {
	//判断是否有PES包，如果有就把上一次pes包之后的数据剩下的反给回调函数
	//并清空数据
	if (s_data->_flag == 0x01 && _frame_len != 0) {
		stream_data s(s_data->_id, 0, s_data->_s_type, _frame_data, _frame_len,
				_pre_pts, _pre_dts);
		_cb(&s);
		memset(_frame_data, 0, BUFFER_SIZE);
		_frame_len = 0;
	}

	int start_pos = 0, len = 0, offset = 0;
	memcpy(_frame_data + _frame_len, s_data->_data, s_data->_len);
	_frame_len += s_data->_len;
	while (true) {
		auto ret = get_aac_buffer(_frame_data + offset, _frame_len - offset,
				start_pos, len);
		if (ret >= 0) {
			stream_data s(s_data->_id, 0, s_data->_s_type,
					_frame_data + offset + start_pos, len, _pts, _dts);
			//QSC_LOG_INFO("stream::parse_aac dts = %ld, pts = %ld",_dts,_pts);
			_cb(&s);
			offset += len;
		} else {
			//将剩余数据放到buffer的最前面
			if (ret == -2)
				offset += 2;
			memmove(_frame_data, _frame_data + offset, _frame_len - offset);
			memset(_frame_data + offset, 0, offset);
			_frame_len -= offset;
			break;
		}
	}
}

/**
 * 解析一帧mpx数据x=1,2,3
 * @param data: 输入数据buffer
 * @param data_len: 输入数据长度
 * @param start_pos： 第一帧开始位置
 * @param buffer_len：第一帧数据长度
 * @return 0成功
 */
int stream::get_mpx_buffer(const unsigned char* data, int data_len,
		int& start_pos, int& buffer_len) {
	//各个bitrate index and layer 对应的bitrate
	static int bit_rate_idx[4][16] = { { 0 }, { 0, 32, 40, 48, 56, 64, 80, 96,
			112, 128, 160, 192, 224, 256, 320, 0 }, { 0, 32, 48, 56, 64, 80, 96,
			112, 128, 160, 192, 224, 256, 320, 384, 0 }, { 0, 32, 64, 96, 128,
			160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0 } };
	//sample_freq_index->sample_frequency
	static int sample_frequency[4] = { 44100, 48000, 32000, 0 };
	//layer=1,buffer length=384;layer=2,buffer length=1152;layer=3,buffer length=1152;
	static int buffer_length[4] = { 0, 384, 1152, 1152 };
	start_pos = buffer_len = 0;
	int i = 0;
	for (i = 0; i < (data_len - 2); i++) {
		//mp2包头判断
		if ((data[i] & 0xff) == 0xff && (data[i + 1] & 0xf0) == 0xf0) {
			unsigned char id = (data[i + 1] & 0x08) >> 3;
			if (id == 0)
				return -5;
			short layer = (data[i + 1] & 0x06) >> 1;
			//layer must eq 1,2,3.it present mp1,mp2,mp3
			if (layer > 3 || layer < 1)
				return -3;
			//unsigned char protec_bit = (data[i + 1] & 0x01);
			short bitrate_inx = (data[i + 2] & 0xf0) >> 4;
			int bit_rate = bit_rate_idx[layer][bitrate_inx];
			if (bit_rate == 0)
				return -6;

			unsigned short sample_freq = (data[i + 2] & 0x0c) >> 2;
			if (sample_freq > 2)
				return -4;
			//unsigned char padding = (data[i + 2] & 0x02) >> 1;
			//unsigned char pri_bit = (data[i + 2] & 0x01);

			//short mode = (data[i + 3] & 0xc0) >> 6;
			//short mode_exten = (data[i + 3] & 0x30) >> 4;
			//unsigned char copy_right = (data[i + 3] & 0x08) >> 3;
			//unsigned char orig = (data[i + 3] & 0x06) >> 2;
			//short emphasis = (data[i + 3] & 0x03);

			int pcm_count = buffer_length[layer];
			int sample_rate = sample_frequency[sample_freq];
			float duration = 1000.0 * pcm_count / sample_rate;
			int addPts = duration * 90;
			int bufferlen = bit_rate * duration / 8;
			//auto oo=bit_rate*duration/8;
			//int frames = (data[i + 6] & 0xc0);
			//int header_len = (data[i+1]&0x01)==1?7:9;
			//如果检测到的数据长度恰好在边界上，则直接取数据
			/*if (i + bufferlen + 1 == data_len || i + bufferlen == data_len) {
			 start_pos = i;
			 buffer_len = bufferlen;
			 //if ((sample_rate >= 0 && sample_rate < 13)) {
			 _pts += _additonal_pts;
			 _additonal_pts = addPts;
			 //}
			 return 1;
			 }*/
			//如果检测到的数据长度比送进的数据长度长，则返回检测失败
			if (i + bufferlen + 1 > data_len)
				return -1;
			_additonal_pts = addPts;

			//正常情况一帧的结束，后面紧接着一帧的开始
			if ((data[i + bufferlen] & 0xff) == 0xff
					&& (data[i + bufferlen + 1] & 0xf0) == 0xf0) {
				start_pos = i;
				buffer_len = bufferlen;
				//if ((sample_rate >= 0 && sample_rate < 13)) {
				//_pts += _additonal_pts;
				//_additonal_pts = addPts;
				//}
				return 1;
			}

			if ((data[i + bufferlen + 1] & 0xff) == 0xff
					&& (data[i + bufferlen + 2] & 0xf0) == 0xf0) {
				start_pos = i;
				buffer_len = bufferlen + 1;
				//if ((sample_rate >= 0 && sample_rate < 13)) {
				//_pts += _additonal_pts;
				//_additonal_pts = addPts;
				//}
				return 1;
			}
			return -1;
		}
	}
	return -1;
}

/**
 * 解析mpx x=1,2,3
 * @param s_data
 */
void stream::parse_mpx(stream_data* s_data) {
	//判断是否有PES包，如果有就把上一次pes包之后的数据剩下的反给回调函数
	//并清空数据
	if (s_data->_flag == 0x01 && _frame_len != 0) {
		//data must a frame
		if ((_frame_data[0] & 0xff) == 0xff
				&& (_frame_data[1] & 0xf0) == 0xf0) {
			stream_data s(s_data->_id, 0, s_data->_s_type, _frame_data,
					_frame_len, _pre_pts, _pre_dts);
			_cb(&s);
		}
		memset(_frame_data, 0, BUFFER_SIZE);
		_frame_len = 0;
	}

	int start_pos = 0, len = 0, offset = 0;
	memcpy(_frame_data + _frame_len, s_data->_data, s_data->_len);
	_frame_len += s_data->_len;
	while (true) {
		auto ret = get_mpx_buffer(_frame_data + offset, _frame_len - offset,
				start_pos, len);
		if (ret >= 0) {
			stream_data s(s_data->_id, 0, s_data->_s_type,
					_frame_data + offset + start_pos, len, _pts, _dts);
			//QSC_LOG_INFO("stream::parse_aac dts = %ld, pts = %ld",_dts,_pts);
			_cb(&s);
			offset += len;
			_pts += _additonal_pts;
		} else {
			//将剩余数据放到buffer的最前面
			if (ret == -2)
				offset += 2;
			memmove(_frame_data, _frame_data + offset, _frame_len - offset);
			memset(_frame_data + offset, 0, offset);
			_frame_len -= offset;
			break;
		}
	}
}

/**
 * 解析图像
 * @param s_data
 */
void stream::parse_pictrue(stream_data* s_data) {
	//两个pes包之间的间隔为图像的数据
	if (s_data->_flag == 0x01 && _frame_len != 0) {
		if (_cb) {
			stream_data s(s_data->_id, 0, s_data->_s_type, _frame_data,
					_frame_len, _pre_pts, _pre_dts);
			//QSC_LOG_INFO("stream::parse_pictrue dts = %ld, pts = %ld",_dts,_pts);
			_cb(&s);
		}
		_frame_len = 0;
		memset(_frame_data, 0, BUFFER_SIZE);
		//return;
	}
	memcpy(_frame_data + _frame_len, s_data->_data, s_data->_len);
	_frame_len += s_data->_len;
}

/**
 * 解析负载数据
 * @param s_data
 */
void stream::parse_buffer(stream_data* s_data) {
	switch (s_data->_s_type) {
	case ts::invalid:
		break;
	case ts::mpx:
		parse_mpx(s_data);
		break;
	case ts::aac:
		parse_aac(s_data);
		break;
	case ts::h264:
		parse_pictrue(s_data);
		break;
	case ts::h265:
		parse_pictrue(s_data);
		break;
	}
}

/**
 * 解析一个流数据
 * @param buff: 数据
 * @param buff_len: 数据长度
 * @param pes 是否有pes包
 */
void stream::parse(const unsigned char* buff, int buff_len, bool pes) {
	//pes标志位
	uint32 packet_start_code_prefix =
			(buff_len >= 3) ? (buff[0] << 16) + (buff[1] << 8) + buff[2] : 0;
	uint8 startpos = 0;
	if (pes && packet_start_code_prefix == 1) {
		_stream_id = buff[3];
		//uint16 PES_packet_length = (buff[4] << 8) + buff[5];
		uint8 PTS_DTS_flags = (buff[7] & 0xc0) >> 6;
		uint8 PES_header_data_length = buff[8];
		//流数据的起始位置
		startpos = 9 + PES_header_data_length;
		uint64 pts = 0, dts = 0;
		auto decode_pts = [](const unsigned char* p) {
			uint64 pts = (((uint64)p[0] & 0x0e) << 29);
			pts |= ((p[1] & 0xff) << 22);
			pts |= ((p[2] & 0xfe) << 14);
			pts |= ((p[3] & 0xff) << 7);
			pts |= ((p[4] & 0xfe) >> 1);
			return pts;
		};
		switch (PTS_DTS_flags) {
		case 3: // pts;dts
			pts = decode_pts(buff + 9);
			dts = decode_pts(buff + 14);
			break;
		case 2: //pts only
			pts = decode_pts(buff + 9);
			//if (_stream_type != aac)
			dts = pts;
			break;
		}
		_pre_pts = _pts;
		_pre_dts = _dts;
		if (_last_pts < pts)
			_last_pts = pts;
		_pts = pts;
		//if (_dts < dts)
		_dts = dts;
		_additonal_pts = 0;
		/*QSC_LOG_INFO("stream::parse pes type = %d,dts = %ld, pts = %ld",
		 (int)_stream_type,_dts,_pts);*/
	}

	//h264数据偏移
	if (_stream_type == 27) {
		if (buff[startpos] == 0 && buff[startpos + 1] == 0
				&& buff[startpos + 2] == 1) {
			startpos += 3;
			uint16 type = buff[startpos] & 0x1f;
			if (type == 9)
				startpos += 2;
		}

		if (buff[startpos] == 0 && buff[startpos + 1] == 0
				&& buff[startpos + 2] == 0 && buff[startpos + 3] == 1) {
			startpos += 4;
			uint16 type = buff[startpos] & 0x1f;
			if (type == 9)
				startpos += 2;
		}
	}

	int data_len = buff_len - startpos;
	stream_data s_data(_id,
			(pes && packet_start_code_prefix == 1) == true ? 0x01 : 0x10,
			_stream_type, &buff[startpos], data_len, _pts, _dts);
	parse_buffer(&s_data);

	if (_file)
		fwrite(&buff[startpos], 1, data_len, _file);
}

/**
 * Destructor
 * @param cb:回调函数
 * @param file_path：需要dump流文件添加路径,如果不需要=nullptr
 */
demuxer::demuxer(Data_CB cb, const char* file_path) :
		m_cb(cb), _file_path(file_path) {
}

/**
 * 判断流是否存在
 * @param pid
 * @return
 */
bool demuxer::has_stream(int pid) {
	return (m_streams.find(pid) != m_streams.end());
}

/**
 * put一帧ts包,188byte
 * @param buff
 * @return
 */
int demuxer::put_buffer(const unsigned char* buff) {
	if (buff == nullptr)
		return 0;

	ts_header tshdr(buff);
	if (tshdr.playload_offset < 0)
		return tshdr.playload_offset;

	//数据结束地址
	const uint8 * data_end = buff + 188;
	//跳到playload data
	buff += tshdr.playload_offset;
	if (buff >= data_end)
		return -4;

	//0表示pat
	if (tshdr.pid == 0x0) {
		m_psi._pat.parse(buff);
		return 0;
	}
	//11表示pat
	if (tshdr.pid == 0x11) {
		m_psi._sdt.parse(buff);
		return 0;
	}
	//PMT
	if (m_psi._pat.is_pmt(tshdr.pid)) {
		m_psi._pmt.parse(buff);
		return 0;
	}
	//判断是否为流ID
	if (m_psi._pmt.is_element_pid(tshdr.pid)) {
		//如果流不存在则创建
		if (!has_stream(tshdr.pid)) {
			auto id = m_psi._pmt.stream_info[tshdr.pid].elementary_PID;
			auto s_type = m_psi._pmt.stream_info[tshdr.pid].stream_type;
			m_streams[tshdr.pid] = std::make_shared<stream>(id, s_type, m_cb,
					_file_path);
		}
		m_streams[tshdr.pid]->parse(buff, data_end - buff,
				tshdr.payload_unit_start_indicator);
		return 0;
	}
	printf("ignore pid:%x", tshdr.pid);
	return 0;
}

} /* namespace ts */
