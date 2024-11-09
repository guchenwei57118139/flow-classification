#include <cstdint>

using namespace std;

constexpr auto BUCKET_SIZE = 524288;

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
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;

	bool operator== (const key& k) const {
		if (src_ip != k.src_ip)
			return false;
		if (dst_ip != k.dst_ip)
			return false;
		if (src_port != k.src_port)
			return false;
		if (dst_port != k.dst_port)
			return false;
		return true;
	}

	bool operator== (const int n) const {
		if (src_ip != n)
			return false;
		if (dst_ip != n)
			return false;
		if (src_port != n)
			return false;
		if (dst_port != n)
			return false;
		return true;
	}

	bool operator!= (const int n) const {
		if (src_ip == n && src_port == n && dst_ip == n && dst_port == n)
			return false;
		return true;
	}

	void operator= (key& k) {
		src_ip = k.src_ip;
		dst_ip = k.dst_ip;
		src_port = k.src_port;
		dst_port = k.dst_port;
	}

	void operator= (int n) {
		src_ip = n;
		dst_ip = n;
		src_port = n;
		dst_port = n;
	}
};

struct hash_func {
	size_t operator() (const key& k) const {
		uint32_t hash_value = 5381;
		uint32_t src_ip = k.src_ip;
		while (src_ip > 0) {
			hash_value += (hash_value << 5) + src_ip % 1000;
			src_ip >>= 8;
		}
		uint16_t src_port = k.src_port;
		while (src_port > 0) {
			hash_value += (hash_value << 5) + src_port % 1000;
			src_port >>= 8;
		}
		uint32_t dst_ip = k.dst_ip;
		while (dst_ip > 0) {
			hash_value += (hash_value << 5) + dst_ip % 1000;
			dst_ip >>= 8;
		}
		uint16_t dst_port = k.dst_port;
		while (dst_port > 0) {
			hash_value += (hash_value << 5) + dst_port % 1000;
			dst_port >>= 8;
		}
		return hash_value % BUCKET_SIZE;
	}
};

struct equal_key {
	bool operator() (const key& left, const key& right) const {
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
	uint32_t tf;
	uint32_t cf;
};

struct cuckoo {
	key k;
	uint32_t tf;
	uint32_t cf;
};

struct hash_key {
	uint32_t hash_key1;
	uint32_t hash_key2;
};
