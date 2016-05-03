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
    // insert code here...
    char *crypto_string = malloc(100);
    strcpy(crypto_string, "ThisIsMyPassword");
    printf("%s\n", crypto_string);
    free(crypto_string);
    return 0;
}
