#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define TOKEN_LEN 15

/**
 * generate alpha-numeric string based on random char*
 * 
 * INPUT: fixed length of 16
 * OUTPUT: rotated string
 * */
char* generate_access_token(char* clientIdToken) {
    char *token = malloc(TOKEN_LEN * sizeof(char*));
    int i, key, used[TOKEN_LEN];
    int rotationIndex = TOKEN_LEN;

    memset(used, 0, TOKEN_LEN * sizeof(int));
    for (i = 0; i < TOKEN_LEN; i++) {
        do {
            key = rand() % rotationIndex;
        } while (used[key] == 1);
        token[i] = clientIdToken[key];
        used[key] = 1;
    }
    token[TOKEN_LEN] = '\0';
    return token;
}