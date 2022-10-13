#include <stdio.h>
#include "enc.h"

#define KEY_LEN 16
#define PLAINTEXT_LEN 16

void print_hex(char *a, int len);

int main(int argc, char *argv[]) {
    char nk = (KEY_LEN == 16) ? 4 : (KEY_LEN == 24) ? 6 : 8;
    char nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;
    char word_count = 4 * (nr + 1);
    char key_schedule[word_count][4];

    const char key[KEY_LEN] = {
        0x8d, 0x2e, 0x60, 0x36, 0x5f, 0x17, 0xc7, 0xdf,
        0x10, 0x40, 0xd7, 0x50, 0x1b, 0x4a, 0x7b, 0x5a
    };
    const char plaintext[KEY_LEN] = {
        0x59, 0xb5, 0x08, 0x8e, 0x6d, 0xad, 0xc3, 0xad,
        0x5f, 0x27, 0xa4, 0x60, 0x87, 0x2d, 0x59, 0x29
    };
    char ky[100][KEY_LEN], pt[1001][PLAINTEXT_LEN], ct[1000][KEY_LEN];

    for (int i = 0; i < KEY_LEN; i++)
        ky[0][i] = key[i];
    for (int i = 0; i < PLAINTEXT_LEN; i++)
        pt[0][i] = plaintext[i];
    
    for (int j, i = 0; i < 100; i++) {
        print_hex(&ky[i][0], KEY_LEN);

        print_hex(&pt[0][0], PLAINTEXT_LEN);

        key_expansion(ky[i], key_schedule, nk, nr, word_count, 0);
        for (j = 0; j < 1000; j++) {
            cipher(pt[j], ct[j], key_schedule, nr);
            for (int k = 0; k < PLAINTEXT_LEN; k++)
                pt[j + 1][k] = ct[j][k];
        }
        --j;
        
        print_hex(&ct[j][0], PLAINTEXT_LEN);
        printf("\n");

        if (KEY_LEN == 16)
            for (int k = 0; k < KEY_LEN; k++)
                ky[i + 1][k] = ky[i][k] ^ ct[j][k];
        else if (KEY_LEN == 24)
            for (int k = 0; k < KEY_LEN; k++) 
                ky[i + 1][k] = ky[i][k] ^ ( (k < 8) ? ct[j - 1][k + 8] : ct[j][k] );
        else if (KEY_LEN == 32)
            for (int k = 0; k < KEY_LEN; k++) 
                ky[i + 1][k] = ky[i][k] ^ ( (k < 16) ? ct[j - 1][k] : ct[j][k - 16] );
        
        for (int k = 0; k < PLAINTEXT_LEN; k++) 
            pt[0][k] = ct[j][k];
    }

    return 0;
}

void print_hex(char *a, int len) {
    for (int k = 0; k < len; k++)
        printf("%02x ", (unsigned char)a[k]);
    printf("\n");
}