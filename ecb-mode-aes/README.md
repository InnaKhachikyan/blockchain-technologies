To build the program:

make


To run the program:

make test


This is a C file which handles only BMP files (no other format like jpeg or png) as the headers and padding logic for those might be different.
The program takes as an input a bmp file, reads the headers, finds the raw pixels, passes the pixel data to AES, the image is encrypted in blocks via AES.
I used AES from openssl.
The output is written in the output.bmp file.
The headers are not hashed, only the pixel data.
In the output file, the actual image patterns may be revealed.
