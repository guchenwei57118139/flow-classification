#include<iostream>
using namespace std;
#include<fstream>
#include<unordered_map>
#include"struct.h"
#include"fftw-3.3.5-dll64/fftw3.h"
#include"npcap-sdk/Include/pcap.h"
void count(string s)
{
	ofstream file1(s + "_after_before.txt");
	ofstream file2(s + "_before_before.txt");
	ofstream file3(s + "_before_after.txt");
	ofstream file4(s + "_after_after.txt");
	unordered_map<key, int, hash_func, equal_key> standrd_result_map;
	unordered_map<key, value, hash_func, equal_key>result_map;
	ifstream standrd_result(s + ".txt");
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
	char errbuf[100];
	pcap_t* pfile = pcap_open_offline(const_cast<char*>((s + ".pcap").c_str()), errbuf);
	if (pfile == NULL) {
		cout << "pcap cannot find";
		return;
	}
	pcap_pkthdr* pkthdr_first = 0;
	const u_char* pktdata_first = 0;

	pcap_next_ex(pfile, &pkthdr_first, &pktdata_first);
	uint32_t ts = pkthdr_first->ts.tv_sec;
	pcap_t* pfile2 = pcap_open_offline(const_cast<char*>((s + ".pcap").c_str()), errbuf);

	pcap_pkthdr* pkthdr = 0;
	const u_char* pktdata = 0;
	key k;
	/*value v;
	v.end_time = 0;
	v.start_time = 0;
	v.FIN_flag = 0;
	v.SYN_flag = 0;
	v.protocol = 0;*/

	while (pcap_next_ex(pfile2, &pkthdr, &pktdata) == 1) {
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
			k.dst_ip = dst_ip;
			k.dst_port = dst_port;
			k.src_ip = src_ip;
			k.src_port = src_port;
			//v.protocol = protocol;	

			auto it = standrd_result_map.find(k);
			if (it != standrd_result_map.end())
			{	
			//	result_map[k].protocol = 6;
				auto tmp = result_map.find(k);
				if (tmp == result_map.end())
				{
					if (tag >> 1 & 0x01 == 1)
					{
				//	v.start_time = pkthdr->ts.tv_sec;
				//	v.SYN_flag = 1;
						result_map[k].SYN_flag = 1;
						result_map[k].FIN_flag = 0;
						continue;
					}
					if ((tag & 0x01 == 1) || (tag >> 2 & 0x01 == 1))
					{
				//	v.end_time = pkthdr->ts.tv_sec;
					//	v.FIN_flag = 1;
						result_map[k].SYN_flag = 0;
						result_map[k].FIN_flag = 1;
						continue;
					}
					else
						continue;
				}
				else
				{
					if ((tag & 0x01 == 1) || (tag >> 2 & 0x01 == 1))
					{
						result_map[k].FIN_flag = 1;
						continue;
					}
				}
			}
			else
				continue;
		}
		else if (protocol == 17) {
			udp_hdr* udp_ptr = (udp_hdr*)((char*)iph_ptr + ip_len);
			src_port = ntohs(udp_ptr->src_port);
			dst_port = ntohs(udp_ptr->dst_port);
			k.dst_ip = dst_ip;
			k.dst_port = dst_port;
			k.src_ip = src_ip;
			k.src_port = src_port;
			//v.protocol = protocol;
			//v.start_time = ts;
			auto it = standrd_result_map.find(k);
			if (it != standrd_result_map.end())
			{
				auto tmp = result_map.find(k);
				if (tmp == result_map.end())
				{
				//	v.start_time = pkthdr->ts.tv_sec;
					result_map[k].start_time=pkthdr->ts.tv_sec;
					continue;
				}
				else
				{
					//v.end_time = pkthdr->ts.tv_sec;
					result_map[k].end_time=pkthdr->ts.tv_sec;
					continue;
				}
			}
			else
				continue;
		}
		else
			continue;
	}
	int count1 = 0, count2 = 0, count3 = 0, count4 = 0;
	if (s[4] == 't')
	{

		for (auto it : result_map)
		{
			if ((it.second.SYN_flag == 1) && (it.second.FIN_flag == 1))
			{
				++count1;
				file1 << it.first.src_ip << " " << it.first.src_port << " " << it.first.dst_ip << " " << it.first.dst_port << endl;
			}
			else if ((it.second.SYN_flag == 0) && (it.second.FIN_flag == 1))
			{
				++count2;
				file2 << it.first.src_ip << " " << it.first.src_port << " " << it.first.dst_ip << " " << it.first.dst_port << endl;
			}
			else if ((it.second.SYN_flag == 0) && (it.second.FIN_flag == 0))
			{
				++count3;
				file3 << it.first.src_ip << " " << it.first.src_port << " " << it.first.dst_ip << " " << it.first.dst_port << endl;
			}
			else if ((it.second.SYN_flag == 1) && (it.second.FIN_flag == 0))
			{
				++count4;
				file4 << it.first.src_ip << " " << it.first.src_port << " " << it.first.dst_ip << " " << it.first.dst_port << endl;
			}
		}
	}
	if (s[4] == 'u')
	{
		for (auto it : result_map)
		{
			if ((it.second.start_time - ts >= 300) && (it.second.end_time - ts <= 2100))
			{
				++count1;
				file1 << it.first.src_ip << " " << it.first.src_port << " " << it.first.dst_ip << " " << it.first.dst_port << endl;
			}
			if ((it.second.start_time - ts <= 300) && (it.second.end_time - ts <= 2100))
			{
				++count2;
				file2 << it.first.src_ip << " " << it.first.src_port << " " << it.first.dst_ip << " " << it.first.dst_port << endl;
			}
			if ((it.second.start_time - ts <= 300) && (it.second.end_time - ts >= 2100))
			{
				++count3;
				file3 << it.first.src_ip << " " << it.first.src_port << " " << it.first.dst_ip << " " << it.first.dst_port << endl;
			}
			if ((it.second.start_time - ts >= 300) && (it.second.end_time - ts >= 2100))
			{
				++count4;
				file4 << it.first.src_ip << " " << it.first.src_port << " " << it.first.dst_ip << " " << it.first.dst_port << endl;
			}
		}
	}
	cout << count1 << endl << count2 << endl << count3 << endl << count4 << endl;
}

void main()
{
	//count("seu_tcp");
//	count("seu_udp");
	count("nju_tcp");
//	count("nju_udp");
}