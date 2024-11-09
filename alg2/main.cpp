#include "cuckoo_filter.h"

#include "pcap.h"

#include <string>
#include <fstream>
#include <iostream>
#include <unordered_map>

constexpr auto PARAM_INTERVAL_TIME = 300;
constexpr auto PARAM_LONG_DURATION = 3;

void count(string s) {
	cuckoo_filter* cf = new cuckoo_filter();
	unordered_map<key, value, hash_func, equal_key> m;
	uint32_t ts = 0;

	char errbuf[100];
	pcap_t* pfile = pcap_open_offline(const_cast<char*>((s + ".pcap").c_str()), errbuf);
	if (pfile == NULL) {
		cout << "pcap cannot find";
		return;
	}
	const u_char* pktdata = 0;
	pcap_pkthdr* pkthdr = 0;
	while (pcap_next_ex(pfile, &pkthdr, &pktdata) == 1) {
		uint32_t time = pkthdr->ts.tv_sec;
		if (time >= ts + PARAM_INTERVAL_TIME) {
			if (ts == 0)
				ts = time;
			else
				ts += PARAM_INTERVAL_TIME;

			for (int i = 0; i < COUNTERS_SIZE; ++i) {
				cuckoo c1 = cf->get_counter(1, i);
				cuckoo c2 = cf->get_counter(2, i);
				if (c1.cf >= PARAM_LONG_DURATION) {
					value v;
					v.tf = c1.tf;
					v.cf = c1.cf;
					m[c1.k] = v;
					cf->remove(c1.k);
				}
				if (c2.cf >= PARAM_LONG_DURATION) {
					value v;
					v.tf = c2.tf;
					v.cf = c2.cf;
					m[c2.k] = v;
					cf->remove(c2.k);
				}

				if (c1.k != 0 && time - c1.tf >= 2 * PARAM_INTERVAL_TIME)
					cf->remove(c1.k);
				if (c2.k != 0 && time - c2.tf >= 2 * PARAM_INTERVAL_TIME)
					cf->remove(c2.k);
			}
		}

		ip_hdr* iph_ptr = (ip_hdr*)pktdata;
		uint16_t ip_len = (iph_ptr->ihl) % 16 * 4;
		uint8_t protocol = (int)iph_ptr->protocol;
		uint32_t src_ip = ntohl(iph_ptr->srcaddr);
		uint32_t dst_ip = ntohl(iph_ptr->dstaddr);
		uint8_t tag;

		uint16_t src_port, dst_port;
		if (protocol == 6) {
			tcp_hdr* tcp_ptr = (tcp_hdr*)((char*)iph_ptr + ip_len);
			src_port = ntohs(tcp_ptr->src_port);
			dst_port = ntohs(tcp_ptr->dst_port);
			tag = tcp_ptr->tag;
		}
		else if (protocol == 17) {
			udp_hdr* udp_ptr = (udp_hdr*)((char*)iph_ptr + ip_len);
			src_port = ntohs(udp_ptr->src_port);
			dst_port = ntohs(udp_ptr->dst_port);
		}
		else
			continue;

		key k;
		k.src_ip = src_ip;
		k.dst_ip = dst_ip;
		k.dst_port = dst_port;
		k.src_port = src_port;

		auto it = m.find(k);
		if (it != m.end()) {
			if (it->second.tf != ts) {
				it->second.tf = ts;
				++it->second.cf;
			}
		}
		else
			cf->insert(k, ts);
	}
	pcap_close(pfile);

	ofstream f(s + "_test.txt");
	for (auto &it : m) {
		f << it.first.src_ip << " " << it.first.src_port << " " << it.first.dst_ip << " " << it.first.dst_port << " " << it.second.cf << endl;
	}
	f.close();

	delete cf;
}

void check(string s1, string s2) {
	unordered_map<key, int, hash_func, equal_key> standrd_result_map;
	unordered_map<key, int, hash_func, equal_key> result_map;

	ifstream standrd_result(s1 + s2 + ".txt");
	ifstream result(s1 + "_test.txt");
	string str;
	while (getline(standrd_result, str)) {
		key k;
		int count = 0;
		int start = 0;
		int i = 0;
		for (; i < str.size(); ++i) {
			if (str[i] == ' ') {
				if (count == 0)
					k.src_ip = stoll(str.substr(start, i - start));
				else if (count == 1)
					k.src_port = stoi(str.substr(start, i - start));
				else if (count == 2)
					k.dst_ip = stoll(str.substr(start, i - start));
				else if (count == 3)
					k.dst_port = stoi(str.substr(start, i - start));
				else if (count == 4)
					break;

				++count;
				start = i + 1;
			}
		}
		standrd_result_map[k] = 0;
	}
	while (getline(result, str)) {
		key k;
		int count = 0;
		int start = 0;
		for (int i = 0; i < str.size(); ++i) {
			if (str[i] == ' ') {
				if (count == 0)
					k.src_ip = stoll(str.substr(start, i - start));
				else if (count == 1)
					k.src_port = stoi(str.substr(start, i - start));
				else if (count == 2)
					k.dst_ip = stoll(str.substr(start, i - start));
				else if (count == 3)
					k.dst_port = stoi(str.substr(start, i - start));
				else if (count == 4)
					break;

				++count;
				start = i + 1;
			}
		}
		result_map[k] = 0;
	}
	standrd_result.close();
	result.close();

	if (s2 == "")
		cout << s1 << endl;
	int count = 0;
	for (auto &it : standrd_result_map) {
		if (result_map.find(it.first) != result_map.end()) {
			++count;
		}

	}
	cout << "Recall: " << (double)count / standrd_result_map.size() << " ";
	count = 0;
	for (auto &it : result_map) {
		if (standrd_result_map.find(it.first) != standrd_result_map.end())
			++count;
	}
	cout << "Precision: " << (double)count / result_map.size() << endl;
}

void func(string s) {
	count(s);
//	check(s, "");
	check(s, "1");
}

int main() {
	func("seu_tcp");
	func("seu_udp");
	func("nju_tcp");
	func("nju_udp");
}
