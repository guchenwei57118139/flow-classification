#include "struct.h"

#include <array>

constexpr auto HASH_NUM1 = 12571747;
constexpr auto HASH_NUM2 = 12571681;
constexpr auto COUNTERS_SIZE = 524288;

class cuckoo_filter {
private:
	array<cuckoo, COUNTERS_SIZE> counters1;
	array<cuckoo, COUNTERS_SIZE> counters2;

	hash_key hash_keys(key k);

public:
	void insert(key k, uint32_t time);
	void insert(cuckoo& c, int num, int count);
	void remove(key k);
	cuckoo& get_counter(int num, int  pos);
};
