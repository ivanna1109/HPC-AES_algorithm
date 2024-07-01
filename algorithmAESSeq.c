#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include <stdint.h>
#include <time.h>

// rci niz konstanti koje se koriste za računanje ključeva
const int rci[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// ključevi runde
int rcons[11];

// 4x4 plain-text matrix name "column major order"
int stateMatrix[4][4];

// AES key
int aesOriginalKeyMatrix[4][4];

// AES round key
int aesRoundKeyMatrix[4][4];

// broj iteracija za ključeve
int iteration = 0;

// 'W' niz reči dužine 32 bita od kojih će biti konstruisani svi ključevi
int W[44];

int originalKey[4];
int cipherKey[] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0x31, 0x27, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};

// Ključ runde koji se sastoji od 4 32-bitne reči
int roundKey[4];


//---------------------------------------------METODE------------------------------------------------------

//Konvertovanje ključa matrice u niz od četiri 32-bitne reči
void cipherTo4WordKey() {
    for(int i = 0; i < 4; i++) {
        originalKey[i] = (cipherKey[i * 4] << 24) |
                         (cipherKey[i * 4 + 1] << 16) |
                         (cipherKey[i * 4 + 2] << 8) |
                         (cipherKey[i * 4 + 3]);
    }
}

// Konverzija 128-bitnih blokova u 4x4 matricu
void constructStateMatrix(const char *msg) {
    int brojac = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            stateMatrix[j][i] = (int)msg[brojac++];
        }
    }
}

//Kopiranje matrice
int** matrixCopy(int src[4][4]) {
    int** cpy = (int**)malloc(MATRIX_SIZE * sizeof(int*));
    for(int i = 0; i < MATRIX_SIZE; i++) {
        cpy[i] = (int*)malloc(MATRIX_SIZE * sizeof(int));
        for(int j = 0; j < MATRIX_SIZE; j++) {
            cpy[i][j] = src[i][j];
        }
    }
    return cpy;
}

//Korak levog cirkularnog šiftovanja vrsta matrice
void shiftRows(int src[4][4]) {
    int** cpy = matrixCopy(src);
    for(int i = 1; i < MATRIX_SIZE; i++) {
        for(int j = 0; j < MATRIX_SIZE; j++) {
            int newIndex = (j + i + MATRIX_SIZE) % MATRIX_SIZE;
            src[i][j] = cpy[i][newIndex];
        }
    }
    for(int i = 0; i < MATRIX_SIZE; i++) {
        free(cpy[i]);
    }
    free(cpy);
}

// Korak invertovanog levog cirkularnog šiftovanja (implementacija desnog cirkularnog šiftovanja)
void invShiftRows(int src[4][4]) {
    int** cpy = matrixCopy(src);
    for(int i = 1; i < MATRIX_SIZE; i++) {
        for(int j = 0; j < MATRIX_SIZE; j++) {
            int newIndex = (j - i + MATRIX_SIZE) % MATRIX_SIZE;
            src[i][j] = cpy[i][newIndex];
        }
    }
    for(int i = 0; i < MATRIX_SIZE; i++) {
        free(cpy[i]);
    }
    free(cpy);
}

//8-bitno oduzimanje
void subBytesStep(int src[4][4]) {
    for(int i = 0; i < MATRIX_SIZE; i++) {
        for(int j = 0; j < MATRIX_SIZE; j++) {
            int lowerNibble = src[i][j] & 15;
            int higherNibble = (src[i][j] & 240) >> 4;
            src[i][j] = S_BOX[higherNibble][lowerNibble];
        }
    }
}

// Invertovani subBytesStek upotrebom iste logike koja je prethodno primenjena, samo nad invertovanim S-Boxom
void invSubBytesStep(int src[4][4]) {
    for(int i = 0; i < MATRIX_SIZE; i++) {
        for(int j = 0; j < MATRIX_SIZE; j++) {
            int lowerNibble = src[i][j] & 15;
            int higherNibble = (src[i][j] & 240) >> 4;
            src[i][j] = INV_S_BOX[higherNibble][lowerNibble];
        }
    }
}

//Korak izračunavanja vrednosti za kolonu r
void mixColumn(int* r) {
    int a[4];
    int b[4];
    int h;
    int c;

    for(c = 0; c < 4; c++) {
        a[c] = r[c];
        b[c] = r[c] << 1;
        h = r[c] & 0x80;
        if(h == 0x80) {
            b[c] ^= 0x1b;
        }
    }

    r[0] = (MUL_2[a[0]] ^ a[3] ^ a[2] ^ MUL_3[a[1]]) & 0xFF;
    r[1] = (MUL_2[a[1]] ^ a[0] ^ a[3] ^ MUL_3[a[2]]) & 0xFF;
    r[2] = (MUL_2[a[2]] ^ a[1] ^ a[0] ^ MUL_3[a[3]]) & 0xFF;
    r[3] = (MUL_2[a[3]] ^ a[2] ^ a[1] ^ MUL_3[a[0]]) & 0xFF;
}

//Korak inverznog izračunavanja vrednosti kolona r, gde je r kolona
void invMixColumn(int* r) {
    int a[4];
    int b[4];
    int h;
    int c;

    for(c = 0; c < 4; c++) {
        a[c] = r[c];
        b[c] = (r[c] << 3) ^ r[c];
        h = r[c] & 0x80;
        if(h == 0x80) {
            b[c] ^= 0x1b;
        }
    }

    r[0] = (MUL_14[a[0]] ^ MUL_11[a[1]] ^ MUL_13[a[2]] ^ MUL_9[a[3]]) & 0xFF;
    r[1] = (MUL_14[a[1]] ^ MUL_11[a[2]] ^ MUL_13[a[3]] ^ MUL_9[a[0]]) & 0xFF;
    r[2] = (MUL_14[a[2]] ^ MUL_11[a[3]] ^ MUL_13[a[0]] ^ MUL_9[a[1]]) & 0xFF;
    r[3] = (MUL_14[a[3]] ^ MUL_11[a[0]] ^ MUL_13[a[1]] ^ MUL_9[a[2]]) & 0xFF;
}

//Primena mixColumn metode na svaku odgovarajuću kolonu 
//flag 'inv' signalizira da li primeniti miksovanje ili invertovano miksovanje  kolona
//Izračunava nove vrednosti za svaku od kolona prosleđene matrice pomoću opisanih linearnih transformacija
void mixColumns(int src[4][4], int inv) {
    for(int i = 0; i < 4; i++) {
        int r[4];
        for(int j = 0; j < 4; j++) {
            r[j] = src[j][i];
        }
        if(inv == 0) {
            mixColumn(r);
        } else {
            invMixColumn(r);
        }
        for(int k = 0; k < 4; k++) {
            src[k][i] = r[k];
        }
    }
}

// Niz od 4 reči veličine 32 bita na osnovu kojih se konstruiše matrica ključa
void aesKeyMatrix(int keyBytes[4]) {
    int aesRoundKeyMatrix[4][4];
    
     // Konvertovanje svake 32-bitne reči u niz od 16 8-bitnih reči
    unsigned char bytes[16];
    for (int i = 0; i < 4; i++) {
        bytes[i * 4] = (unsigned char)(keyBytes[i] & 255);            // najniži bajt
        bytes[i * 4 + 1] = (unsigned char)((keyBytes[i] >> 8) & 255); // drugi bajt
        bytes[i * 4 + 2] = (unsigned char)((keyBytes[i] >> 16) & 255);// treći bajt
        bytes[i * 4 + 3] = (unsigned char)((keyBytes[i] >> 24) & 255);// četvrti bajt
    }
    
    // Popunjavanje AES matrice cirkularnih ključeva
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            aesRoundKeyMatrix[j][i] = bytes[i * MATRIX_SIZE + j];
        }
    }
}

//Cirkularna rotacija integera
int rotWord(int word) {
    return (word << 8) | (word >> (32 - 8));
}

// Supstitucija reci upotrebom S-BOXa
int subWord(int word) {
    int result = 0;
    for (int i = 0; i < 4; i++) {
        int byte = (word >> (i * 8)) & 0xFF;
        int lowerNibble = byte & 0x0F;
        int higherNibble = (byte & 0xF0) >> 4;
        result |= S_BOX[higherNibble][lowerNibble] << (i * 8);
    }
    return result;
}

// Korak dodavanja ključa u matricu stanja
void addRoundKey(int key[4][4], int state[4][4]) {
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            state[i][j] ^= key[i][j];
        }
    }
}

//AES key scheduler algoritam za generisanje ključeva reči
void keySchedule() {
    if (iteration < N) {
        W[iteration] = originalKey[iteration];
    } else if (iteration >= N && iteration % N == 0) {
        W[iteration] = W[iteration - N] ^ subWord(rotWord(W[iteration - 1])) ^ rcons[iteration / N];
    } else if (iteration >= N && N > 6 && iteration % N == 4) {
        W[iteration] = W[iteration - N] ^ subWord(W[iteration - 1]);
    } else {
        W[iteration] = W[iteration - N] ^ W[iteration - 1];
    }
    iteration++;
}

// Kreiranje elemenata rcons niza
void rconsInit() {
    for (int i = 1; i < sizeof(rcons) / sizeof(rcons[0]); i++) {
        rcons[i] = rci[i - 1] << 24;
    }
}

// Kopiranje niza
int* arrayCopy(const int* arr, size_t length) {
    int* cpy = (int*)malloc(length * sizeof(int));
    if (cpy == NULL) {
        return NULL; // Error handling in case of memory allocation failure
    }
    memcpy(cpy, arr, length * sizeof(int));
    return cpy;
}

// Konverzija matrice stanje u šifrovani tekst
char* stateMatrixToCipher(int stateMatrix[4][4]) {
    char* result = (char*)malloc((MATRIX_SIZE * MATRIX_SIZE + 1) * sizeof(char));
    if (result == NULL) {
        return NULL; // Error handling in case of memory allocation failure
    }
    int index = 0;
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            result[index++] = (char)stateMatrix[j][i];
        }
    }
    result[MATRIX_SIZE * MATRIX_SIZE] = '\0';
    return result;
}

//Štampanje matrice
void printStateMatrix(){
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            printf("%d\t", stateMatrix[i][j]);
        }
        printf("\n");
    }
}

// Čitanje poruke iz tekstualnog fajla
char* loadData(char* filename){
    // Open the file in read mode
       FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fileSize < 0) {
        perror("Failed to determine file size");
        fclose(file);
        return NULL;
    }

    char* buffer = (char*)malloc(fileSize + 1);
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(file);
        return NULL;
    }

    size_t bytesRead = fread(buffer, 1, fileSize, file);
    printf("Bytes read: %zu\n", bytesRead);
    printf("Filesize read: %zu\n", fileSize);

    buffer[fileSize] = '\0';

    fclose(file);
    return buffer;
}

int main() {
    //merenje vremena izvrsavanja
    clock_t start, end;
    double cpu_time_used;

    start = clock();
    // Inicijalizacija niza konstantnih vrednosti
    rconsInit();
    // Konvertovanje ključa matrice u niz od četiri 32-bitne reči
    cipherTo4WordKey();
    // Generisanje četrdeset četiri 32-bitne reči za konstruktovanje round ključeva
    for (; iteration < 44;) {
        keySchedule();
    }
    // Konstruktovanje prvog round ključa
    int firstKeyBytes[] = {W[0], W[1], W[2], W[3]};
    aesKeyMatrix(firstKeyBytes);

    char* plainText = loadData("message.txt");

    if (plainText != NULL) {
        printf("File content:\n%s\n", plainText);
    } else {
        printf("Failed to read file content\n");
    }
    printf("Plain-text message: %s\n\n", plainText);

    printf("The state matrix:\n");
    constructStateMatrix(plainText);
    printStateMatrix();

    // Dodavanje inicijalnog ključa
    addRoundKey(aesRoundKeyMatrix, stateMatrix);

    // Ostatak koraka: bajt supstitucija, pomeranje redova, mešanje kolona i dodatak round ključa
    int firstKeyByteIndex = 4;
    for (int i = 0; i < 9; i++) {
        subBytesStep(stateMatrix);
        shiftRows(stateMatrix);
        mixColumns(stateMatrix, 0);

        // Generisanje još jednog ključa
        int keyBytes[] = {W[firstKeyByteIndex], W[firstKeyByteIndex + 1], W[firstKeyByteIndex + 2], W[firstKeyByteIndex + 3]};
        aesKeyMatrix(keyBytes);
        addRoundKey(aesRoundKeyMatrix, stateMatrix);
        firstKeyByteIndex += 4;
    }

    // Poslednji korak (bez mixColumns operacije)
    subBytesStep(stateMatrix);
    shiftRows(stateMatrix);

    // Generisanje round ključa za poslednji korak
    int keyBytes[] = {W[firstKeyByteIndex], W[firstKeyByteIndex + 1], W[firstKeyByteIndex + 2], W[firstKeyByteIndex + 3]};
    aesKeyMatrix(keyBytes);
    addRoundKey(aesRoundKeyMatrix, stateMatrix);

    // Prikazivanje finalne state matrice
    printf("\nThe final state matrix:\n");
    printStateMatrix();

    // Konvertovanje state matrice u cipher-text
    char *cipherText = stateMatrixToCipher(stateMatrix);
    printf("\nCipher-text message: %s\n\n", cipherText);
    free(cipherText);

    // ------------------------------------------------------DEKRIPCIJA--------------------------------------------------
    aesKeyMatrix(keyBytes);
    addRoundKey(aesRoundKeyMatrix, stateMatrix);

    invShiftRows(stateMatrix);
    invSubBytesStep(stateMatrix);

    // Prvih 9 rundi dešifrovanja
    for (int i = 0; i < 9; i++) {
        int revKeyBytes[] = {W[firstKeyByteIndex - 4], W[firstKeyByteIndex - 3], W[firstKeyByteIndex - 2], W[firstKeyByteIndex - 1]};
        aesKeyMatrix(revKeyBytes);
        addRoundKey(aesRoundKeyMatrix, stateMatrix);
        mixColumns(stateMatrix, 1);
        invShiftRows(stateMatrix);
        invSubBytesStep(stateMatrix);
        firstKeyByteIndex -= 4;
    }

    // Poslednji korak dešifrovanja
    int revKeyBytes[] = {W[0], W[1], W[2], W[3]};
    aesKeyMatrix(revKeyBytes);
    addRoundKey(aesRoundKeyMatrix, stateMatrix);

    //Ispisivanje rezultata dekripcije
    printf("The state matrix after decryption:\n");
    printStateMatrix();

    char *inverseCipherText = stateMatrixToCipher(stateMatrix);
    printf("\nThe result of decryption: %s\n", inverseCipherText);
    free(inverseCipherText);
    free(plainText);

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("Execution time: %f seconds\n", cpu_time_used);
    return 0;
}
