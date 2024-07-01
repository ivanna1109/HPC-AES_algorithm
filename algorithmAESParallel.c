#include <mpi.h>
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
void constructStateMatrix(const char *msg, int stateMatrix[MATRIX_SIZE][MATRIX_SIZE]) {
    int brojac = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            stateMatrix[j][i] = (int)msg[brojac++];
        }
    }
}

//Kopiranje matrice
int** matrixCopy(int src[MATRIX_SIZE][MATRIX_SIZE]) {
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
void shiftRows(int src[MATRIX_SIZE][MATRIX_SIZE]) {
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
void invShiftRows(int src[MATRIX_SIZE][MATRIX_SIZE]) {
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
void subBytesStep(int src[MATRIX_SIZE][MATRIX_SIZE]) {
    for(int i = 0; i < MATRIX_SIZE; i++) {
        for(int j = 0; j < MATRIX_SIZE; j++) {
            int lowerNibble = src[i][j] & 15;
            int higherNibble = (src[i][j] & 240) >> 4;
            src[i][j] = S_BOX[higherNibble][lowerNibble];
        }
    }
}

// Invertovani subBytesStek upotrebom iste logike koja je prethodno primenjena, samo nad invertovanim S-Boxom
void invSubBytesStep(int src[MATRIX_SIZE][MATRIX_SIZE]) {
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
void mixColumns(int src[MATRIX_SIZE][MATRIX_SIZE], int inv) {
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
void aesKeyMatrix(int keyBytes[MATRIX_SIZE], int aesRoundKeyMatrix[MATRIX_SIZE][MATRIX_SIZE]) {
    
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

// Supstitucija reči upotrebom S-BOX-a
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
void addRoundKey(int key[MATRIX_SIZE][MATRIX_SIZE], int state[MATRIX_SIZE][MATRIX_SIZE]) {
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
char* stateMatrixToCipher(int stateMatrix[MATRIX_SIZE][MATRIX_SIZE], char* result) {
    if (result == NULL) {
        return NULL;
    }
    int index = 0;
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            result[index++] = (char)stateMatrix[j][i];
        }
    }
    result[MATRIX_SIZE * MATRIX_SIZE] = '\0';
}

//Pražnjenje matrice
void clearMatrix(int matrix[MATRIX_SIZE][MATRIX_SIZE]) {
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            matrix[i][j] = 0; // Postavljanje svih elemenata na 0
        }
    }
}

//Štampanje matrice
void printStateMatrix(int stateMatrix[4][4]){
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            printf("%d\t", stateMatrix[i][j]);
        }
        printf("\n");
    }
}

// Čitanje poruke iz tekstualnog fajla
long readTextFromFile(const char* filename, char** buffer) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *buffer = (char*)malloc(size * sizeof(char));
    if (*buffer == NULL) {
        perror("Error allocating memory");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    fread(*buffer, sizeof(char), size, file);
    fclose(file);

    return size;
}

//Glavni program
int main(int argc, char** argv) {
    MPI_Init(&argc, &argv);

    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    // Inicijalizacija tajmera za merenje vremena izvršavanja
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
    MPI_Bcast(firstKeyBytes, 4, MPI_INT, 0, MPI_COMM_WORLD);
    int aesRoundKeyMatrix[MATRIX_SIZE][MATRIX_SIZE];
    aesKeyMatrix(firstKeyBytes, aesRoundKeyMatrix);

    //ucitavanje poruke iz fajla
    char* plainText = NULL;
    long text_size = 0;
    if (world_rank == 0) {
        text_size = readTextFromFile("message.txt", &plainText);
        printf("File size: %ld bytes\n", text_size);
        printf("Text read from file: %s\n", plainText);
        printf("The state matrix of message: \n");
        int stateMatrix[MATRIX_SIZE][MATRIX_SIZE];
        constructStateMatrix(plainText, stateMatrix);
        printStateMatrix(stateMatrix);
    }

    // Slanje veličine teksta svim procesima
    MPI_Bcast(&text_size, 1, MPI_LONG, 0, MPI_COMM_WORLD);

    // Izracunavanje veličine poruke za Scatter (da bude deljiva sa brojem procesa)
    int local_size = text_size / world_size;
    char* localPlainText = (char*)malloc((local_size + 1) * sizeof(char));
    if (localPlainText == NULL) {
        perror("Error allocating memory");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    // Scatter poruke među procesima
    MPI_Scatter(plainText, local_size, MPI_CHAR, localPlainText, local_size, MPI_CHAR, 0, MPI_COMM_WORLD);
    localPlainText[local_size] = '\0';  // Osiguravanje da je lokalni tekst nulti terminisan

    int stateMatrix[MATRIX_SIZE][MATRIX_SIZE];
    constructStateMatrix(localPlainText, stateMatrix);

    // Dodavanje inicijalnog ključa matrici
    addRoundKey(aesRoundKeyMatrix, stateMatrix);

    // Podela rundi između procesa
    int rounds_per_process = NUM_ROUNDS / world_size;
    int start_round = world_rank * rounds_per_process;
    int end_round = start_round + rounds_per_process;

    //AES enkripcija u prvih 9 rundi sa mixColumns metodom
    int firstKeyByteIndex = 4;
    for(int round = start_round; round < end_round; round++){
        subBytesStep(stateMatrix);
        shiftRows(stateMatrix);
        if (round != NUM_ROUNDS - 1) {
            mixColumns(stateMatrix, 0);
        }
        int keyBytes[] = {W[firstKeyByteIndex], W[firstKeyByteIndex + 1], W[firstKeyByteIndex + 2], W[firstKeyByteIndex + 3]};
        MPI_Bcast(&keyBytes, 4, MPI_INT, 0, MPI_COMM_WORLD);
        aesKeyMatrix(keyBytes, aesRoundKeyMatrix);
        addRoundKey(aesRoundKeyMatrix, stateMatrix);
        firstKeyByteIndex =+4;
    }

    //Poslednja runda enkripcije
    subBytesStep(stateMatrix);
    shiftRows(stateMatrix);

    int keyBytes[] = {W[firstKeyByteIndex], W[firstKeyByteIndex + 1], W[firstKeyByteIndex + 2], W[firstKeyByteIndex + 3]};
    aesKeyMatrix(keyBytes, aesRoundKeyMatrix);
    addRoundKey(aesRoundKeyMatrix, stateMatrix);

    //Konvertovanje matrice stanja u šifrovanu poruku
    char localCipherText[4];
    stateMatrixToCipher(stateMatrix, localCipherText);

    //Spajanje lokalnih šifrovanih delova poruke
    char cipherText[16];
    MPI_Gather(localCipherText, 4, MPI_CHAR, cipherText, 4, MPI_CHAR, 0, MPI_COMM_WORLD);


    //Ispisivanje šifrovane poruke i njene matrice stanja
    if (world_rank == 0) {
        printf("------------Encryption------------");
        printf("\nThe final state matrix:\n");
        printStateMatrix(stateMatrix);
        printf("Cipher-text message: %s\n", cipherText);
        clearMatrix(stateMatrix);
    }

    // ------------------------------------------DEKRIPCIJA--------------------------------------------------------
    
    if (world_rank == 0)
        printf("Starting decryption.......\n");

    // Scatter kriptovanog teksta među procesima
    char localCipherTextI[4];
    MPI_Scatter(cipherText, 4, MPI_CHAR, localCipherText, 4, MPI_CHAR, 0, MPI_COMM_WORLD);

    // Konvertovanje lokalnog kriptovanog teksta u stanje matrice
    int stateMatrixI[MATRIX_SIZE][MATRIX_SIZE];
    constructStateMatrix(localCipherTextI, stateMatrixI);

    //10. runda enkripcije = 1. runda dekripcije
    aesKeyMatrix(keyBytes, aesRoundKeyMatrix);
    addRoundKey(aesRoundKeyMatrix, stateMatrixI);

    invShiftRows(stateMatrixI);
    invSubBytesStep(stateMatrixI);

    // AES dekripcija u 9 rundi unazad 
    for (int round = NUM_ROUNDS - 1; round >= 0; round--) {
        int revKeyBytes[] = {W[firstKeyByteIndex - 4], W[firstKeyByteIndex - 3], W[firstKeyByteIndex - 2], W[firstKeyByteIndex - 1]};
        MPI_Bcast(&revKeyBytes, 4, MPI_INT, 0, MPI_COMM_WORLD);
        aesKeyMatrix(revKeyBytes, aesRoundKeyMatrix);
        addRoundKey(aesRoundKeyMatrix, stateMatrixI);
        if (round != 0) {
            mixColumns(stateMatrix, 1);
        }
        invShiftRows(stateMatrixI);
        invSubBytesStep(stateMatrixI);

        firstKeyByteIndex -= 4;
    }

    // Poslednji korak dešifrovanja
    int revKeyBytes[] = {W[0], W[1], W[2], W[3]};
    aesKeyMatrix(revKeyBytes, aesRoundKeyMatrix);
    addRoundKey(aesRoundKeyMatrix, stateMatrixI);

    // Ispis rezultata samo na procesu 0
    char* decryptedText = (char*)malloc((text_size + 1) * sizeof(char));
    char *decryptedTextF = (char*)malloc((MATRIX_SIZE * MATRIX_SIZE + 1) * sizeof(char));;
    MPI_Gather(decryptedText, local_size, MPI_CHAR, decryptedTextF, local_size, MPI_CHAR, 0, MPI_COMM_WORLD);

    if (world_rank == 0) {
        printf("The state matrix after decryption:\n");
        constructStateMatrix(plainText, stateMatrix);
        printStateMatrix(stateMatrix);
        char* finalResult = (char*)malloc((MATRIX_SIZE * MATRIX_SIZE + 1) * sizeof(char));;
        stateMatrixToCipher(stateMatrix, finalResult);
        printf("The result of decryption: %s\n", finalResult);
    }

    free(decryptedText);
    free(decryptedTextF);
    free(localPlainText);
    free(plainText);

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    if (world_rank == 0) {
        printf("Execution time: %f seconds\n", cpu_time_used);
    }

    MPI_Finalize();
    return 0;
}