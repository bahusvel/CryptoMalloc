//
//  reversestring.c
//  CryptoMalloc
//
//  Created by denis lavrov on 9/05/16.
//  Copyright © 2016 Denis Lavrov. All rights reserved.
//

#include <stdio.h>
#include <string.h>

char *reverse_string(char *str){
	char temp;
	size_t len = strlen(str) - 1;
	size_t i;
	size_t k = len;
	
	for(i = 0; i < len; i++)
	{
		temp = str[k];
		str[k] = str[i];
		str[i] = temp;
		k--;
		
		if(k == (len / 2))
		{
			break;
		}
	}
}

int main(){
	char *normal = "helloreversed";
	char *toreverse = malloc(strlen(normal));
	strcpy(toreverse, normal);
	reverse_string(toreverse);
	getchar();
	printf("%s\n", toreverse);
}