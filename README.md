# enc
A command line tool which encrypts/decrypts files using an implementation of the AES cipher.

Usage:  key_file input_file -d|-o output_file [-k 128|192|256].

The tool comes with 3 options as below:
    -o is used to define the name of the output file that the ciphertext will be stored in. This option cannot be used with -d.
    -d instructs the tool to decrypt the input file. This option cannot be used with -o.
    -k is used to specify which cipher key length the encryption algorithm should use. The options are (bits): 128, 192, 256 (default).

Note:
- During encryption, the input file name is preserved as part of the ciphertext. Consequently, after decryption, this preserved name is used as the name of the output file.
- Any additional bytes in the cipher key file will be ignored - the tool will fail if there are insufficient bytes for the specified key length.
- During both encryption and decryption, the input file is not modified.
