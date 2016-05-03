//
//  cor_map.c
//  COR-Framework-C
//
//  Created by denis lavrov on 20/04/16.
//  Copyright © 2016 bahus. All rights reserved.
//

#include "cor_map.h"
#include <stdlib.h>
#include <string.h>

cor_map *cor_map_create(){
	cor_map *map = (cor_map*) malloc(sizeof(cor_map));
	map->first = NULL;
	map->last = NULL;
	return map;
}

void cor_map_destroy(cor_map* map){
	free(map);
}

int cor_map_get(cor_map* map, void *key, MemNode *node){
	cor_map_node *np = map->first;
	while (np != NULL) {
		if (np->key == key) {
            node->fp = np->fp;
            node->alloc_size = np->alloc_size;
			return 1;
		}
		np = np->next;
	}
	return 0;
}

cor_map_node *create_node(void *key, FILE *fp, size_t alloc_size){
	cor_map_node *node = malloc(sizeof(cor_map_node));
    node->key = key;
	node->fp = fp;
	node->alloc_size = alloc_size;
    node->next = NULL;
	return node;
}

void cor_map_set(cor_map* map, void *key, FILE *fp, size_t size){
    MemNode node;
	if (cor_map_get(map, key, &node) == 0) {
		if (map->first == NULL) {
			map->first = create_node(key, fp, size);
			map->last = map->first;
		} else {
			cor_map_node *last_node = map->last;
			last_node->next = create_node(key, fp, size);
			map->last = last_node->next;
		}
	}
}

;
