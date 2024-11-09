#pragma once
#include <string>
#include <cstdint>

constexpr auto BUCKET_SIZE = 6416999;

using namespace std;

struct ip_hdr {
	uint8_t ihl;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t chk_sum;
	uint32_t srcaddr;
	uint32_t dstaddr;
};

struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_no;
	uint32_t ack_no;
	uint8_t len;
	uint8_t tag;
	uint16_t wnd_size;
	uint16_t chk_sum;
	uint16_t urgt_p;
};

struct udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t uhl;
	uint16_t chk_sum;
};

struct key {
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dst_ip;
	uint16_t dst_port;
};

struct hash_func {
	size_t operator() (const key& key) const {
		uint32_t hash_value = 5381;
		uint32_t src_ip = key.src_ip;
		while (src_ip > 0) {
			hash_value += (hash_value << 5) + src_ip % 1000;
			src_ip >>= 8;
		}
		uint16_t src_port = key.src_port;
		while (src_port > 0) {
			hash_value += (hash_value << 5) + src_port % 1000;
			src_port >>= 8;
		}
		uint32_t dst_ip = key.dst_ip;
		while (dst_ip > 0) {
			hash_value += (hash_value << 5) + dst_ip % 1000;
			dst_ip >>= 8;
		}
		uint16_t dst_port = key.dst_port;
		while (dst_port > 0) {
			hash_value += (hash_value << 5) + dst_port % 1000;
			dst_port >>= 8;
		}
		return hash_value % BUCKET_SIZE;
	}
};

struct equal_key {
	bool operator() (const key &left, const key &right) const {
		if (left.src_ip != right.src_ip)
			return false;
		if (left.src_port != right.src_port)
			return false;
		if (left.dst_ip != right.dst_ip)
			return false;
		if (left.dst_port != right.dst_port)
			return false;
		return true;
	}
};

struct value {
	uint8_t protocol;
	uint32_t start_time;
	uint32_t end_time;
	int SYN_flag;
	int FIN_flag;
};

struct hash_key {
	uint32_t hash_key1;
	uint32_t hash_key2;
	uint32_t hash_key3;
};
/*struct packet {
	key k;
	int SYN_flag;
	int FIN_flag;
	uint32_t t_start;
	uint32_t t_finish;
};*/
