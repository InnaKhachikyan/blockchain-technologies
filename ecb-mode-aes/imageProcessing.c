#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <string.h>

#pragma pack(push, 1)
struct FileHeader {
    unsigned char signature[2];
    uint32_t fileSize;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t pixelOffset;
};

struct InfoHeader {
    uint32_t headerSize;
    int32_t width;
    int32_t height;
    uint16_t planes;
    uint16_t bitsPerPixel;
    uint32_t compression;
    uint32_t imageSize;
    int32_t xPixelsPerMeter;
    int32_t yPixelsPerMeter;
    uint32_t colorsUsed;
    uint32_t importantColors;
};
#pragma pack(pop)

unsigned char key[16];

void readHeaders(char *fileName, struct FileHeader *fileHeader, struct InfoHeader *infoHeader);
void imageProcessing(char *fileName, struct FileHeader *fileHeader, struct InfoHeader *infoHeader);
void outputHashedImage(char *outputFileName, struct FileHeader *fileHeader, struct InfoHeader *infoHeader, unsigned char *pixels, int pixelsSize);

int main(int argNum, char *args[]) {
    if(argNum < 2) {
        printf("Argument file not given\n");
        return 1;
    }

    if(sizeof(struct FileHeader) != 14 || sizeof(struct InfoHeader) != 40) {
        printf("STRUCT MISALIGNMENT\n");
    }

    struct FileHeader *fileHeader = (struct FileHeader*)malloc(sizeof(struct FileHeader));
    struct InfoHeader *infoHeader = (struct InfoHeader*)malloc(sizeof(struct InfoHeader));
    if(fileHeader == NULL || infoHeader == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }

    char *fileName = args[1];

    readHeaders(fileName, fileHeader, infoHeader);

    for(int i = 0; i < 16; i++) {
        key[i] = 42;
    }

    imageProcessing(fileName, fileHeader, infoHeader);

    free(fileHeader);
    fileHeader = NULL;
    free(infoHeader);
    infoHeader = NULL;

    return 0;
}

void readHeaders(char *fileName, struct FileHeader *fileHeader, struct InfoHeader *infoHeader) {
    FILE *file = fopen(fileName, "rb");
    if(file == NULL) {
        perror("Couldn't open the file\n");
        return;
    }

    if(fread(fileHeader, sizeof(struct FileHeader), 1, file) != 1) {
        perror("Couldn't read the file header\n");
        fclose(file);
        return;
    }

    if(fread(infoHeader, sizeof(struct InfoHeader), 1, file) != 1) {
        perror("Couldn't read the info header\n");
        fclose(file);
        return;
    }

    if(fileHeader->signature[0] != 'B' || fileHeader->signature[1] != 'M') {
        printf("Not a BMP file\n");
        fclose(file);
        exit(0);
    }

    fclose(file);
}

void imageProcessing(char *fileName, struct FileHeader *fileHeader, struct InfoHeader *infoHeader) {
    if(infoHeader->bitsPerPixel != 24 || infoHeader->compression != 0) {
        printf("Only 24-bit uncompressed BMP supported\n");
        return;
    }

    int padding = (4 - (infoHeader->width * 3) % 4) % 4;
    int rowSize = (infoHeader->width * 3) + padding;
    int pixelsSize = rowSize * abs(infoHeader->height);

    unsigned char *pixels = (unsigned char*)malloc((size_t)pixelsSize);
    if(pixels == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    FILE *file = fopen(fileName, "rb");
    if(file == NULL) {
        printf("Failed to open input file\n");
        free(pixels);
        return;
    }

    if(fseek(file, (long)fileHeader->pixelOffset, SEEK_SET) != 0) {
        printf("Failed to move ot the offset\n");
        fclose(file);
        free(pixels);
        return;
    }

    if(fread(pixels, 1, (size_t)pixelsSize, file) != (size_t)pixelsSize) {
        printf("Failed to read the pixel data\n");
        fclose(file);
        free(pixels);
        return;
    }

    fclose(file);

    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        printf("AES_set_encrypt_key failed\n");
        free(pixels);
        return;
    }

    size_t n = (size_t)pixelsSize;
    size_t i = 0;
    for (; i + 16 <= n; i += 16) {
        AES_ecb_encrypt(pixels + i, pixels + i, &aes_key, AES_ENCRYPT);
    }

    outputHashedImage("output.bmp", fileHeader, infoHeader, pixels, pixelsSize);

    free(pixels);
    pixels = NULL;
}

void outputHashedImage(char *outputFileName, struct FileHeader *fileHeader, struct InfoHeader *infoHeader, unsigned char *pixels, int pixelsSize) {
    FILE *outputFile = fopen(outputFileName, "wb");
    if(outputFile == NULL) {
        printf("Opening file failed\n");
        return;
    }

    fwrite(fileHeader, sizeof(struct FileHeader), 1, outputFile);
    fwrite(infoHeader, sizeof(struct InfoHeader), 1, outputFile);

    long pos = ftell(outputFile);
    if (fileHeader->pixelOffset > (uint32_t)pos) {
        size_t gap = fileHeader->pixelOffset - (uint32_t)pos;
        static const unsigned char zeros[64] = {0};
        while (gap) {
            size_t chunk = gap > sizeof zeros ? sizeof zeros : gap;
            fwrite(zeros, 1, chunk, outputFile);
            gap -= chunk;
        }
    } else {
        fseek(outputFile, (long)fileHeader->pixelOffset, SEEK_SET);
    }

    fwrite(pixels, 1, (size_t)pixelsSize, outputFile);
    fclose(outputFile);
}

