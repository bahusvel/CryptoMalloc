#include <stdio.h>
#include <stdlib.h>

typedef struct cor_map_node {
	void *key;
	void *cryptoaddr;
	size_t alloc_size;
	size_t crypto_size;
	unsigned char flags;
	struct cor_map_node *next;
} cor_map_node;

typedef struct cor_map { cor_map_node *first; } cor_map;

#define COR_MAP_FOREACH(map_ptr, node_ptr)                                     \
	for (node_ptr = map_ptr->first; node_ptr != NULL; node_ptr = node_ptr->next)

static inline cor_map_node *cor_map_delete(cor_map *map, void *key) {
	cor_map_node *pnp;
	cor_map_node *np;
	for (np = map->first, pnp = map->first; np != NULL;
		 pnp = np, np = np->next) {
		if (np->key == key) {
			if (np == map->first) {
				map->first = np->next;
			} else {
				pnp->next = np->next;
			}
			return np;
		}
	}
	return NULL;
}

static inline cor_map_node *cor_map_get(cor_map *map, void *key) {
	cor_map_node *np;
	COR_MAP_FOREACH(map, np) {
		if (np->key == key) {
			return np;
		}
	}
	return NULL;
}

static inline cor_map_node *cor_map_range(cor_map *map, void *address) {
	cor_map_node *np;
	COR_MAP_FOREACH(map, np) {
		if (np->key <= address && address <= (np->key + np->alloc_size)) {
			return np;
		}
	}
	return NULL;
}

// this can auto delete, to avoid 2 round trips
static inline cor_map_node *cor_map_find_fit(cor_map *map, size_t size) {
	cor_map_node *np;
	COR_MAP_FOREACH(map, np) {
		if (np->alloc_size >= size) {
			return np;
		}
	}
	return NULL;
}

static inline void cor_map_set(cor_map *map, cor_map_node *node) {
	node->next = map->first;
	map->first = node;
}
