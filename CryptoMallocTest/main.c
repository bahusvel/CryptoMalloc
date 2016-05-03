//
//  main.c
//  CryptoMallocTest
//
//  Created by denis lavrov on 3/05/16.
//  Copyright © 2016 Denis Lavrov. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char * argv[]) {
	char *str;
	
	/* Initial memory allocation */
	str = (char *) malloc(15);
	strcpy(str, "tutorialspoint");
	printf("String = %s,  Address = %u\n", str, str);
	
	/* Reallocating memory */
	str = (char *) realloc(str, 25);
	strcat(str, ".com");
	printf("String = %s,  Address = %u\n", str, str);
	
	free(str);
	
	return(0);
}
