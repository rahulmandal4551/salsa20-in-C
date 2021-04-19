#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

typedef unsigned int uii; /*represents a 32-bit word*/
#define maxm 100005U
/* ROTATE FUNCTION START*/

#define U32TO8_LITTLE(p, v)          \
        (p)[0] = 0xFFU & ((v));       \
        (p)[1] = 0xFFU & ((v) >>  8); \
        (p)[2] = 0xFFU & ((v) >> 16); \
        (p)[3] = 0xFFU & ((v) >> 24);

#define U8TO32_LITTLE(p)         \
        (((uii)((p)[0])     ) |  \
        ((uii)((p)[1]) <<  8) |  \
        ((uii)((p)[2]) << 16) |  \
        ((uii)((p)[3]) << 24))

uii LROTATE(uii value32, uii c_bit)
{
    switch (c_bit)
    {
    case 7:
    {
        unsigned char value8[4], tmp;
        U32TO8_LITTLE(value8, value32);
        tmp = value8[3];
        value8[3] = value8[2];
        value8[2] = value8[1];
        value8[1] = value8[0];
        value8[0] = tmp;
        tmp = 0x01 & value8[0];
        value32 = U8TO32_LITTLE(value8);
        value32 = value32 >> 1;
        if (tmp == 0x01)
            value32 ^= 0x80000000;
        return value32;
    }
    case 9:
    {
        unsigned char value8[4], tmp;
        U32TO8_LITTLE(value8, value32);
        tmp = value8[3];
        value8[3] = value8[2];
        value8[2] = value8[1];
        value8[1] = value8[0];
        value8[0] = tmp;
        tmp = 0x80 & value8[3];
        value32 = U8TO32_LITTLE(value8);
        value32 = value32 << 1;
        if (tmp == 0x80)
            value32 ^= 0x01;
        return value32;
    }
    case 13:
    {
        unsigned char value8[4], tmp;
        U32TO8_LITTLE(value8, value32);
        tmp = value8[0];
        value8[0] = value8[2];
        value8[2] = tmp;
        tmp = value8[1];
        value8[1] = value8[3];
        value8[3] = tmp;
        tmp = 0x07 & value8[0];
        value32 = U8TO32_LITTLE(value8);
        value32 = value32 >> 3;
        if (tmp & 0x1)
            value32 ^= 0x20000000;
        if (tmp & 0x2)
            value32 ^= 0x40000000;
        if (tmp & 0x4)
            value32 ^= 0x80000000;
        return value32;
    }
    case 18:
    {
        unsigned char value8[4], tmp;
        U32TO8_LITTLE(value8, value32);
        tmp = value8[0];
        value8[0] = value8[2];
        value8[2] = tmp;
        tmp = value8[1];
        value8[1] = value8[3];
        value8[3] = tmp;
        tmp = 0xc0000000 & value8[3];
        value32 = U8TO32_LITTLE(value8);
        value32 = value32 << 2;
        if (tmp & 0x80000000)
            value32 ^= 0x02;
        if (tmp & 0x40000000)
            value32 ^= 0x01;
        return value32;
    }
    default:
        return ((value32 << c_bit) | (value32 >> (32 - c_bit)));
    }
}

/* ROTATE FUCTION END */ 

// uii LROTATE(uii n1, uii n2)
// {
//     /*c bit cyclic rotation of 32 bit words*/
//     uii mask = 0xffffffff;
//     return (((n1 << n2) & mask) | (n1 >> (32 - n2)));
// }

void doubleround(uii round_matrix[], uii temp[])
{
    uii input[16], i;
    for (i = 0; i < 16; i++)
        input[i] = round_matrix[i];

    // FOR COLUMNROUND
    //quarterround 1

    uii mask = 0xffffffff;
    input[4] ^= LROTATE((input[0] + input[12]) & mask, 7);
    input[8] ^= LROTATE((input[0] + input[4]) & mask, 9);
    input[12] ^= LROTATE((input[4] + input[8]) & mask, 13);
    input[0] ^= LROTATE((input[8] + input[12]) & mask, 18);

    //quarterround 2
    input[9] ^= LROTATE((input[1] + input[5]) & mask, 7);
    input[13] ^= LROTATE((input[5] + input[9]) & mask, 9);
    input[1] ^= LROTATE((input[9] + input[13]) & mask, 13);
    input[5] ^= LROTATE((input[1] + input[13]) & mask, 18);

    //quarterround 3
    input[14] ^= LROTATE((input[6] + input[10]) & mask, 7);
    input[2] ^= LROTATE((input[10] + input[14]) & mask, 9);
    input[6] ^= LROTATE((input[2] + input[14]) & mask, 13);
    input[10] ^= LROTATE((input[2] + input[6]) & mask, 18);

    //quarterround 4
    input[3] ^= LROTATE((input[11] + input[15]) & mask, 7);
    input[7] ^= LROTATE((input[3] + input[15]) & mask, 9);
    input[11] ^= LROTATE((input[3] + input[7]) & mask, 13);
    input[15] ^= LROTATE((input[7] + input[11]) & mask, 18);

    // FOR ROWROUND
    input[1] ^= LROTATE((input[0] + input[3]), 7);
    input[2] ^= LROTATE((input[1] + input[0]), 9);
    input[3] ^= LROTATE((input[2] + input[1]), 13);
    input[0] ^= LROTATE((input[3] + input[2]), 18);

    input[6] ^= LROTATE((input[5] + input[4]), 7);
    input[7] ^= LROTATE((input[6] + input[5]), 9);
    input[4] ^= LROTATE((input[7] + input[6]), 13);
    input[5] ^= LROTATE((input[4] + input[7]), 18);

    input[11] ^= LROTATE((input[10] + input[9]), 7);
    input[8] ^= LROTATE((input[11] + input[10]), 9);
    input[9] ^= LROTATE((input[8] + input[11]), 13);
    input[10] ^= LROTATE((input[9] + input[8]), 18);

    input[12] ^= LROTATE((input[15] + input[14]), 7);
    input[13] ^= LROTATE((input[12] + input[15]), 9);
    input[14] ^= LROTATE((input[13] + input[12]), 13);
    input[15] ^= LROTATE((input[14] + input[13]), 18);

    for (i = 0; i < 16; i++)
        temp[i] = input[i];
}

uii littleendian(uii n0, uii n1, uii n2, uii n3)
{
    /*Converting 4-byte sequence to a word*/
    return (n0 ^ (n1 << 8) ^ (n2 << 16) ^ (n3 << 24));
}

void salsa20_encrypt(uii key_byte[], uii nonce_byte[], unsigned long long int blockCounter, uii key_len, uii input[])
{
    /*Convert byte number into words*/
    uii nonce_word[2], blockCounter_word[2], constant32_byte[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    uii constant16_byte[4] = {0x61707865, 0x3120646e, 0x79622d36, 0x6b206574}, idx, mask = 0xffffffff;

    /*length of key in words*/
    key_len /= 4;
    uii key_word[key_len];

    for (idx = 0; idx < key_len; idx++)
        key_word[idx] = littleendian(key_byte[idx * 4], key_byte[idx * 4 + 1], key_byte[idx * 4 + 2], key_byte[idx * 4 + 3]);
    for (idx = 0; idx < 2; idx++)
    {
        nonce_word[idx] = littleendian(nonce_byte[idx * 4], nonce_byte[idx * 4 + 1],
                                       nonce_byte[idx * 4 + 2], nonce_byte[idx * 4 + 3]);
    }
    blockCounter_word[0] = blockCounter >> 32;
    blockCounter_word[1] = blockCounter & 0xFFFFFFFF;

    uii round_matrix[16];
    if (key_len == 8)
    {
        /*Matrix for computing doubleround function for key length 32 byte*/
        uii roundMatrix32_byte[16] = {constant32_byte[0], key_word[0], key_word[1], key_word[2],
                                      key_word[3], constant32_byte[1], nonce_word[0], nonce_word[1],
                                      blockCounter_word[0], blockCounter_word[1], constant32_byte[2], key_word[4],
                                      key_word[5], key_word[6], key_word[7], constant32_byte[3]};
        for (idx = 0; idx < 16; idx++)
            round_matrix[idx] = roundMatrix32_byte[idx];
    }
    else if (key_len == 4)
    {
        /*Matrix for computing doubleround function for key length 16 byte*/
        uii roundMatrix16_byte[16] = {constant16_byte[0], key_word[0], key_word[1], key_word[2],
                                      key_word[3], constant16_byte[1], nonce_word[0], nonce_word[1],
                                      blockCounter_word[0], blockCounter_word[1], constant16_byte[2], key_word[0],
                                      key_word[1], key_word[2], key_word[3], constant16_byte[3]};
        for (idx = 0; idx < 16; idx++)
            round_matrix[idx] = roundMatrix16_byte[idx];
    }

    /* Salsa Expansion function (using doubleround 10 times) */
    uii temp[16];
    doubleround(round_matrix, temp);
    for (idx = 0; idx < 9; idx++)
        doubleround(temp, temp);
    for (idx = 0; idx < 16; idx++)
        input[idx] = round_matrix[idx] + (*(temp + idx));
}

void littleendian_inverse(uii input[], unsigned char output[])
{
    uii idx, mask = 0x00000000FF;
    for (idx = 0; idx < 16; idx++)
    {
        output[4 * idx] = input[idx] & mask;
        output[4 * idx + 1] = (input[idx] >> 8) & mask;
        output[4 * idx + 2] = (input[idx] >> 16) & mask;
        output[4 * idx + 3] = (input[idx] >> 24) & mask;
    }
}

uii key_byte[32], nonce_byte[8] = {3, 1, 4, 1, 5, 9, 2, 6}, key_len;
unsigned long long int blockCounter = 1LLU, plaintext_len, idx;

unsigned char plaintext[maxm];
uii encryptedtext_byte[maxm];

struct thread_func_args
{
    unsigned long long block_cntr;
    unsigned long long msg_idx;
};

void *thread_func_msg_block(void *args)
{
    unsigned long long j, idx = ((struct thread_func_args *)args)->msg_idx, block_cntr = ((struct thread_func_args *)args)->block_cntr;
    printf("Thread (id %ld) started with index %llu and block %llu\n", pthread_self(), idx, block_cntr);
    uii input[16];
    unsigned char output[64];
    salsa20_encrypt(key_byte, nonce_byte, block_cntr, key_len, input);
    littleendian_inverse(input, output);
    for (j = 0; j < 64 && (idx + j < plaintext_len); j++)
        encryptedtext_byte[idx + j] = plaintext[idx + j] ^ output[j];
    printf("Thread (id %ld) ended with index %llu and block %llu\n", pthread_self(), j + idx - 1, block_cntr);
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    char *input_file_name = "salsa_input.txt";
    char *output_file_name = "salsa_output.txt";
    if(argc == 2)
    {
        input_file_name = argv[1];
    }
    if (argc == 3)
    {
        input_file_name = argv[1];
        output_file_name = argv[2];
    }

    unsigned char secret_key[maxm];
    printf("Enter 32 or 16 byte key\n");
    fgets(secret_key, maxm, stdin);
    key_len = strlen(secret_key) - 1;
    if (key_len == 32 || key_len == 16)
    {
        for (idx = 0; idx < key_len; idx++)
            key_byte[idx] = secret_key[idx];
    }
    else
    {
        printf("Please check the length of secret key entered. You have to enter 32 or 16 character key.\n");
        return 0;
    }

    uii input_choice;
    printf("\nChoice 1 : input message in text format\nChoice 2 : input message in integer format\nEnter your choice: ");
    scanf("%u", &input_choice);
    if (input_choice == 1)
    {
        printf("The message in text format is being taken from %s\n", input_file_name);
        getchar();
        printf("The result text will be stored in %s\n", output_file_name);
        freopen(input_file_name, "r+", stdin);
        freopen(output_file_name, "w+", stdout);
        fgets(plaintext, maxm, stdin);
        plaintext_len = strlen(plaintext);
        printf("\nLength of the entered message: %llu\n", plaintext_len);
    }
    else if (input_choice == 2)
    {
        printf("Enter no of characters in message: ");
        scanf("%llu", &plaintext_len);
        printf("The result text will be stored in %s\n", output_file_name);
        freopen(input_file_name, "r+", stdin);
        freopen(output_file_name, "w+", stdout);
        // printf("Enter the ASCII values (space seperated) of each character of the message:\n");
        for (idx = 0; idx < plaintext_len; idx++)
            scanf("%hhu", &plaintext[idx]);
    }
    else
    {
        printf("Entered a Invalid Choice\n");
    }
    printf("Completed message Input\n");
    unsigned long long block_count = plaintext_len / 64 + (plaintext_len % 64 > 0);
    pthread_t thread_ids[block_count];
    for (idx = 0; idx < plaintext_len; idx += 64)
    {
        struct thread_func_args *args = (struct thread_func_args *)malloc(sizeof(struct thread_func_args));
        args->block_cntr = blockCounter; args->msg_idx = idx;
        int ret_val = pthread_create(&thread_ids[idx / 64], NULL, thread_func_msg_block, (void *)args);
        if (ret_val)
        {
            printf("THREAD %llu CREATION FAILED\n", idx / 64);
            return 0;
        }
        blockCounter += 1;
    }

    // wait until all other threads exits after completing their tasks
    for (idx = 0; idx < block_count; idx++)
    {
        pthread_join(thread_ids[idx], NULL);
    }

    printf("\nEncrypted Text (In ASCII values): \n");
    for (idx = 0; idx < plaintext_len; idx++)
        printf("%u ", encryptedtext_byte[idx]);
    printf("\n");
    printf("\n\n\nEncrypted Text (In Text format): \n");
    for (idx = 0; idx < plaintext_len; idx++)
        printf("%c", encryptedtext_byte[idx]);
    printf("\n");
    return 0;
}