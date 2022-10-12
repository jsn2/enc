#include <stdio.h>
#include <string.h>
#include "enc.h"

#define SEPARATOR '/'
#define PRINT_USAGE printf("Usage: enc key_file in_file -d|-o out_file [-k 128|192|256]\n");

char is_key_size(const char *arg);
int read_key(char key[32], const char *filename, const char nk);
char *filename_from_path(char *path);
void refresh_progress(const long *total_units, char *percent_complete, const long units);
int close_file(FILE *fp, const char *filename);
int f_read(FILE *f, const char *filename, char in[16], int len);
int f_write(FILE *f, const char *filename, char out[16], int len);

/*
 * nb - Number of columns in state (4). 
 * nk - Number of 4-byte words in key (4, 6, 8).
 * nr - Number of rounds (10, 12, 14).
 */

int main(int argc, char *argv[]) {
    const unsigned short max_fname_size = 65535;
    char dec = 0;
    char nk = 8;
    char *src_fname = NULL;
    char dst_fname[max_fname_size + 1];

    // Initialise dst_fname
    for (int i = 0; i < max_fname_size + 1; i++)
        dst_fname[i] = 0;

    if (argc < 4) {
        PRINT_USAGE
        return 1;
    }

    // Read input filename
    src_fname = argv[2];

    // Check for -d or -o flag
    if (!strcmp("-d", argv[3]))
        dec = 1;
    else if (!strcmp("-o", argv[3])) {
        if (argc < 5) {
            PRINT_USAGE
            return 1;
        }
        else {
            if (strlen(argv[4]) > max_fname_size) {
                fprintf(stderr, "Output filename too big.\nMust be less than %d characters. [%d]\n", max_fname_size + 1, __LINE__);
                return 1;
            }
            else {
                for (int k = 0; dst_fname[k] = argv[4][k]; k++)
                    ;
            }
        }
    }
    else {
        PRINT_USAGE
        return 1;
    }

    // Check for -k flag
    {
        int a = dec ? 4 : 5;
        if (argc > a) {
            if (argc == a + 2) {
                if (!strcmp("-k", argv[a])) {
                    char temp = is_key_size(argv[a + 1]);
                    if (temp) 
                        nk = temp;
                    else {
                        PRINT_USAGE
                        return 1;
                    }
                }
            }
            else {
                PRINT_USAGE
                return 1;
            }
        }
    }

    // Read key
    char key[32];
    if (read_key(key, argv[1], nk))
        return 1;

    char in[16], out[16];
    char nr = (nk == 4) ? 10 : (nk == 6) ? 12 : 14;
    char word_count = 4 * (nr + 1);
    char key_schedule[word_count][4];

    // Get key schedule
    key_expansion(key, key_schedule, nk, nr, word_count, dec);

    // Open input file
    FILE *fin;
    if ((fin = fopen(src_fname, "rb")) == NULL) {
        fprintf(stderr, "Failed to open file '%s'. [%d]\n", src_fname, __LINE__);
        return 1;
    }

    // Find size of file
    if (fseek(fin, 0l, SEEK_END)) {
        fprintf(stderr, "Failed to set file position of file '%s'. [%d]\n", src_fname, __LINE__);
        close_file(fin, src_fname);
        return 1;
    }
    long fin_size = ftell(fin);
    if (fin_size == -1l) {
        fprintf(stderr, "Failed to read size of file '%s'. [%d]\n", src_fname, __LINE__);
        close_file(fin, src_fname);
        return 1;
    }

    // Set file position back to beginning
    if (fseek(fin, 0l, SEEK_SET)) {
        fprintf(stderr, "Failed to reset file position of file '%s'. [%d]\n", src_fname, __LINE__);
        close_file(fin, src_fname);
        return 1;
    }
    
    if (dec) {
        // Check file size is valid
        if (fin_size % 16) {
            fprintf(stderr, "Unexpected file format found in file '%s'. [%d]\n", src_fname, __LINE__);
            return 1;
        }

        // Get number of 16 byte units, current unit and percent complete for progress indicator
        const long total_units = fin_size / 16;
        long unit = 0;
        char percent_complete = -1;

        refresh_progress(&total_units, &percent_complete, unit++);

        // Read first 16 bytes from input file
        char in[16], out[16];
        if (f_read(fin, src_fname, in, 16))
            return 1;

        // Decrypt first 16 bytes
        eq_inv_cipher(in, out, key_schedule, nr);
        
        refresh_progress(&total_units, &percent_complete, unit++);

        // Get size of name of output filename
        unsigned short dst_fname_size = (unsigned short)out[0] << 8 | (unsigned short)out[1];

        // Get size of padding
        unsigned char padding_size = (unsigned char)out[2];

        // Get size of file content
        long src_fcontent_size = fin_size - 3l - (long)dst_fname_size - (long)padding_size;

        // Check file content size is valid
        if (src_fcontent_size < 0) {
            fprintf(stderr, "Unexpected file format found in file '%s'. [%d]\n", src_fname, __LINE__);
            return 1;
        }

        // Read filename
        int i = 3;
        for (int j = 0; j < (int)dst_fname_size; i++, j++) {
            dst_fname[j] = out[i];
            if (i == 15) {
                // Read more if entire filename still not read
                if (j + 1 < dst_fname_size) {
                    if (f_read(fin, src_fname, in, 16))
                        return 1;
                    eq_inv_cipher(in, out, key_schedule, nr);
                    refresh_progress(&total_units, &percent_complete, unit++);
                }
                i = -1;
            }
        }
        
        // Skip padding bytes
        for (int k = padding_size; k; k--, i++)
            if (i == 15) {
                if (k > 1)
                    if (f_read(fin, src_fname, in, 16))
                        return 1;
                i = -1;
            }
        
        // Open output file
        FILE *fout;
        if ((fout = fopen(dst_fname, "wb")) == NULL) {
            fprintf(stderr, "Failed to open file '%s'. [%d]\n", dst_fname, __LINE__);
            return 1;
        }

        // Write remaining file content, if any, from last 16 bytes to output file
        if (i > 0) {
            eq_inv_cipher(in, out, key_schedule, nr);
            if (f_write(fout, dst_fname, &out[i], 16 - i))
                return 1;
            refresh_progress(&total_units, &percent_complete, unit++);
            src_fcontent_size = src_fcontent_size - (16 - i);
        }
        
        // Read file content and write to output file
        for (int j = 0; j < src_fcontent_size; j += 16) {
            if (f_read(fin, src_fname, in, 16))
                return 1;
            eq_inv_cipher(in, out, key_schedule, nr);
            if (f_write(fout, dst_fname, out, 16))
                return 1;
            refresh_progress(&total_units, &percent_complete, unit++);
        }

        // Close fin and fout - report errors on close
        if (close_file(fout, dst_fname) || close_file(fin, src_fname))
            return 1;
        
        printf("\nComplete\n");
    }
    else {
        // Open output file
        FILE *fout;
        if ((fout = fopen(dst_fname, "wb")) == NULL) {
            fprintf(stderr, "Failed to open file '%s'. [%d]\n", dst_fname, __LINE__);
            return 1;
        }

        // Get input filename from path
        char *path = src_fname;
        src_fname = filename_from_path(path);

        // Check if size of filename can fit into 2 bytes
        unsigned short src_fname_size;
        {
            size_t temp = strlen(src_fname);
            src_fname_size = temp <= max_fname_size ? temp : 0;
        }
        if (!src_fname_size) {
            fprintf(stderr, "File name too long. [%d]\n", __LINE__);
            close_file(fin, path);
            return 1;
        }

        // Check output file size is not bigger than max file size
        const long max_file_size = (-1ul >> 1) - 15l; // Less 15 so size is multiple of 16
        unsigned char padding_size = 0;
        long bytes_rem = max_file_size - 3l - (long)src_fname_size - fin_size;
        while (bytes_rem % 16l) {
            bytes_rem--;
            padding_size++;
        }
        if (bytes_rem < 0) {
            fprintf(stderr, "File is %ld bytes too big. [%d]\n", (bytes_rem * -1l), __LINE__);
            close_file(fin, path);
            return 1;
        }

        // Get number of 16 byte units, current unit and percent complete for progress indicator
        const long total_units = (3l + (long)src_fname_size + padding_size + fin_size) / 16;
        long unit = 0;
        char percent_complete = -1;

        refresh_progress(&total_units, &percent_complete, unit++);

        // Add filename size and padding size
        char i = 3;
        in[0] = (char)(src_fname_size >> 8);
        in[1] = (char)(src_fname_size & 0x00ff);
        in[2] = padding_size;

        // Write filename size, padding size and filename to output file
        for (int j = 0; j < src_fname_size; i++, j++) {
            in[i] = src_fname[j];
            if (i == 15) {
                cipher(in, out, key_schedule, nr);
                if(f_write(fout, dst_fname, out, 16))
                    return 1;
                refresh_progress(&total_units, &percent_complete, unit++);
                i = -1;
            }
        }

        // Write padding bytes to output file
        {
            const char padding_bytes[15] = {
                0xe6, 0x7a, 0x40, 0xf5, 0x03, 0x37, 0x23, 0x5c,
                0x18, 0x03, 0xa2, 0xee, 0x1b, 0x44, 0xc3
            };
            for (int j = 0; j < padding_size; i++, j++) {
                in[i] = padding_bytes[j];
                if (i == 15) {
                    cipher(in, out, key_schedule, nr);
                    if(f_write(fout, dst_fname, out, 16))
                        return 1;
                    refresh_progress(&total_units, &percent_complete, unit++);
                    i = -1;
                }
            }
        }

        // Write file content to output file
        {
            int c;
            for (long j = 0; j < fin_size; i++, j++) {
                if((c = fgetc(fin)) == EOF) {
                    fprintf(stderr, "Failed to read from file '%s'. [%d]\n", path, __LINE__);
                    return 1;
                }
                in[i] = (char)c;
                if (i == 15) {
                    cipher(in, out, key_schedule, nr);
                    if(f_write(fout, dst_fname, out, 16))
                        return 1;
                    refresh_progress(&total_units, &percent_complete, unit++);
                    i = -1;
                }
            }
        }
        
        // Close input and output files - report errors on close
        if (close_file(fout, dst_fname) || close_file(fin, path))
            return 1;
        
        printf("\nComplete\n");
    }

    return 0;
}

char is_key_size(const char *arg) {
    char nk = 0;

    if (!strcmp(arg, "128"))
        nk = 4;
    else if (!strcmp(arg, "192"))
        nk = 6;
    else if (!strcmp(arg, "256"))
        nk = 8;
    
    return nk;
}

int read_key(char key[32], const char *filename, const char nk) {
    FILE *fp;

    // Open file
    if ((fp = fopen(filename, "rb")) == NULL) {
        fprintf(stderr, "Failed to open file '%s'. [%d]\n", filename, __LINE__);
        return 1;
    }

    // Read bytes into key
    for (int c, i = 0; i < nk * 4; i++) {
        if((c = fgetc(fp)) == EOF) {
            fprintf(stderr, "Failed to read from file '%s'. [%d]\n", filename, __LINE__);
            return 1;
        }
        key[i] = (char)c;
    }

    // Close file
    if (close_file(fp, filename))
        return 1;
    
    return 0;
}

int f_write(FILE *f, const char *filename, char out[16], int len) {
    // enc and write to file
    for (int c, i = 0; i < len; i++)  {
        c = fputc(out[i], f);
        if (c == EOF) {
            fprintf(stderr, "Error writing to file '%s'. [%d]\n", filename, __LINE__);
            close_file(f, filename);
            return 1;
        }
    }
    return 0;
}

int f_read(FILE *f, const char *filename, char in[16], int len) {
    for (int c, i = 0; i < len; i++) {
        if((c = fgetc(f)) == EOF) {
            fprintf(stderr, "Failed to read from file '%s'. [%d]\n", filename, __LINE__);
            close_file(f, filename);
            return 1;
        }
        in[i] = (char)c;
    }
    return 0;
}

int close_file(FILE *fp, const char *filename) {
    if (fp != NULL)
        if((fclose(fp)) == EOF) {
            fprintf(stderr, "Failed to close file '%s'. [%d]\n", filename, __LINE__);
            return 1;
        }
    return 0;
}

char *filename_from_path(char *path) {
    char *filename;

    for (filename = path; *path; path++)
        if (*path == SEPARATOR)
            if (*(++path))
                filename = path;
            else
                break;

    return filename;
}

void refresh_progress(const long *total_units, char *percent_complete, const long units) {
    char percent = units / (long double)*total_units * 100;
    if (percent > *percent_complete) {
        *percent_complete = percent;
        printf("\rIn progress [%d%%]\r", *percent_complete);
        fflush(stdout);
    }
}
