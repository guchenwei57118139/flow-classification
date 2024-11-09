#include "cuckoo_filter.h"

hash_key cuckoo_filter::hash_keys(key k) {
	uint32_t h = 0;
	while (k.src_port > 0) {
		h = h * 33 + k.src_port % 1000;
		k.src_port /= 1000;
	}
	while (k.dst_port > 0) {
		h = h * 33 + k.dst_port % 1000;
		k.dst_port /= 1000;
	}
	while (k.src_ip > 0) {
		h = h * 33 + k.src_ip % 1000;
		k.src_ip /= 1000;
	}
	while (k.dst_ip > 0) {
		h = h * 33 + k.dst_ip % 1000;
		k.dst_ip /= 1000;
	}

	hash_key hk;
	hk.hash_key1 = h % HASH_NUM1 % COUNTERS_SIZE;
	hk.hash_key2 = h % HASH_NUM2 % COUNTERS_SIZE;

	return hk;
}

void cuckoo_filter::insert(key k, uint32_t time) {
	hash_key hk = hash_keys(k);

	if (counters1[hk.hash_key1].k == k) {
		if (counters1[hk.hash_key1].tf != time) {
			counters1[hk.hash_key1].tf = time;
			++counters1[hk.hash_key1].cf;
		}
	}
	else if (counters2[hk.hash_key2].k == k) {
		if (counters2[hk.hash_key2].tf != time) {
			counters2[hk.hash_key2].tf = time;
			++counters2[hk.hash_key2].cf;
		}
	}
	else if (counters1[hk.hash_key1].k == 0) {
		counters1[hk.hash_key1].k = k;
		counters1[hk.hash_key1].tf = time;
		counters1[hk.hash_key1].cf = 0;
	}
	else if (counters2[hk.hash_key2].k == 0) {
		counters2[hk.hash_key2].k = k;
		counters2[hk.hash_key2].tf = time;
		counters2[hk.hash_key2].cf = 0;
	}
	else {
		cuckoo temp = counters1[hk.hash_key1];
		counters1[hk.hash_key1].k = k;
		counters1[hk.hash_key1].tf = time;
		counters1[hk.hash_key1].cf = 0;
		insert(temp, 1, 1);
	}
}

void cuckoo_filter::insert(cuckoo& c, int num, int count) {
	if (count <= 10) {
		hash_key hk = hash_keys(c.k);

		if (num == 1) {
			if (counters1[hk.hash_key1].k == 0)
				counters1[hk.hash_key1] = c;
			else {
				cuckoo temp = counters1[hk.hash_key1];
				counters1[hk.hash_key1] = c;
				insert(temp, 2, count + 1);
			}
		}
		else if (num == 2) {
			if (counters2[hk.hash_key2].k == 0)
				counters2[hk.hash_key2] = c;
			else {
				cuckoo temp = counters2[hk.hash_key2];
				counters2[hk.hash_key2] = c;
				insert(temp, 1, count + 1);
			}
		}
	}
}

void cuckoo_filter::remove(key k) {
	hash_key hk = hash_keys(k);

	if (counters1[hk.hash_key1].k == k)
		counters1[hk.hash_key1].k = 0;
	else if (counters2[hk.hash_key2].k == k)
		counters2[hk.hash_key2].k = 0;
}

cuckoo& cuckoo_filter::get_counter(int num, int  pos) {
	if (num == 1)
		return counters1[pos];
	else
		return counters2[pos];
}
