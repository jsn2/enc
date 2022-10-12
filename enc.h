void key_expansion(char key[], char w[][4], char nk, char nr, char word_count, char dec);
void cipher(char in[16], char out[16], char key_schedule[][4], char nr);
void eq_inv_cipher(char in[16], char out[16], char key_schedule[][4], char nr);
