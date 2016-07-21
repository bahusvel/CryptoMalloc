#include "list.h"
#include <sys/time.h>
//#include "mem_tree.h"

#define MAP_NODES 10000

#define TIMEIT_INIT()                                                          \
	struct timeval start;                                                      \
	struct timeval stop;                                                       \
	unsigned long stime;                                                       \
	unsigned long ftime;

#define TIMEIT(expression)                                                     \
	gettimeofday(&start, NULL);                                                \
	expression;                                                                \
	gettimeofday(&stop, NULL);                                                 \
	stime = 1000000 * start.tv_sec + start.tv_usec;                            \
	ftime = 1000000 * stop.tv_sec + stop.tv_usec;                              \
	printf(#expression " took: %ld us\n", ftime - stime);

int main() {
	TIMEIT_INIT()
	cor_map map;
	cor_map_node nodes[MAP_NODES];
	int i = 0;
	cor_map_node *np = &nodes[0];
	for (i = 0; i < MAP_NODES; i++, np = &nodes[i]) {
		// TODO do the rb_tree
		// cor_map
		np->alloc_size = 1000;
		np->key = (void *)(i * 1000L);
		cor_map_set(&map, np);
	}
	TIMEIT(np = cor_map_get(&map, (void *)(100 * 1000L)))
	/* these operations take mere microseconds for small values of MAP_NODES,
	 * how many MAP_NODES do I normally have? I don't think its that many...*/
	printf("GCC plz dont optimise %ld\n", np->key);
	// TODO time the rb_tree
	TIMEIT(np = cor_map_range(&map, (void *)(100 * 1000L + 10)))
	printf("GCC plz dont optimise %ld\n", np->key);
}
