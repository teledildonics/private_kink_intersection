#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crypto_hash_sha256.h"
#include "crypto_scalarmult_curve25519.h"
#include "randombytes.h"

#define MAX_STRLEN 256
#define MAX_SET_SIZE 255
#define POINT_SIZE 32
// about 8k

typedef struct {
    unsigned char encrypted_pref[POINT_SIZE];
    unsigned long long offset;
} pref_t;

pref_t alices_private_set[MAX_SET_SIZE];
pref_t bobs_private_set[MAX_SET_SIZE];

unsigned int alices_set_size;
unsigned int bobs_set_size;

unsigned char alices_ephemeral_key[POINT_SIZE];
unsigned char bobs_ephemeral_key[POINT_SIZE];

void print_hex(unsigned char * bytes, unsigned int length){
    unsigned int i = 0;
    for(i = 0; i < POINT_SIZE; i++){
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void initialize_ephemeral_keys(void){
    randombytes(alices_ephemeral_key,POINT_SIZE);
    randombytes(bobs_ephemeral_key,POINT_SIZE);
}

FILE* prefs;

int compare_prefs(const void* a, const void* b){
    return memcmp(((pref_t*) a)->encrypted_pref, ((pref_t*) b)->encrypted_pref, POINT_SIZE);
}

void sort_prefs(pref_t *the_set, unsigned int the_set_size){
    qsort(the_set, the_set_size, sizeof(pref_t), compare_prefs);
}

unsigned int init(unsigned char * the_filename, pref_t *the_set, unsigned char * the_ephemeral_key){
    unsigned char pref[MAX_STRLEN];
    unsigned char hashed_pref[crypto_hash_sha256_BYTES];
    pref_t element;
    unsigned int i = 0;
    if(prefs = fopen(the_filename, "r")){
        while(!feof(prefs)){
            if(fgets(pref, MAX_STRLEN, prefs)){
                crypto_hash_sha256(hashed_pref, pref, strlen(pref));
                crypto_scalarmult_curve25519(element.encrypted_pref, the_ephemeral_key, hashed_pref);
                memcpy(the_set[i].encrypted_pref, element.encrypted_pref, POINT_SIZE);
                //printf("EPref: ");
                //print_hex(element.encrypted_pref, POINT_SIZE);
                memset(&element, 0x0, sizeof(element));
                i++;
            }
        }
        fclose(prefs);
    }
    return i;
}

void update(pref_t * the_set, unsigned int the_set_size, unsigned char * the_ephemeral_key){
    unsigned int i = 0, j = 0;
    pref_t temp_pref;
    for(i = 0; i < the_set_size; i++){
        crypto_scalarmult_curve25519(temp_pref.encrypted_pref, the_ephemeral_key, the_set[i].encrypted_pref);
        memcpy(the_set[i].encrypted_pref, temp_pref.encrypted_pref, POINT_SIZE);
        //printf("EPref2: ");
        //print_hex(temp_pref.encrypted_pref, POINT_SIZE);
    }
}

void main(int argc, char* argv[]){
    initialize_ephemeral_keys();

    //printf("Alices key: ");
    //print_hex(alices_ephemeral_key, POINT_SIZE);

    //printf("Bobs key:   ");
    //print_hex(bobs_ephemeral_key, POINT_SIZE);

    // load, hash & encrypt all preferences
    //printf("Alices set\n");
    alices_set_size = init("alice.txt", alices_private_set, alices_ephemeral_key);
    sort_prefs(alices_private_set, alices_set_size);
    //printf("%u elements\n", alices_set_size);

    //printf("Bobs set\n");
    bobs_set_size = init("bob.txt", bobs_private_set, bobs_ephemeral_key);
    sort_prefs(bobs_private_set, bobs_set_size);
    //printf("%u elements\n", bobs_set_size);

    // all the preferences are loaded with a new ephemeral key
    // bob exponentiates the data he got from alice and sends this + his own
    update(alices_private_set, alices_set_size, bobs_ephemeral_key);
    sort_prefs(alices_private_set, alices_set_size);

    // alice updates bobs data
    update(bobs_private_set, bobs_set_size, alices_ephemeral_key);
    sort_prefs(bobs_private_set, bobs_set_size);

    int i;
    unsigned char pref[MAX_STRLEN];
    pref_t *found;
    // both can now find common preferences
    // this example is alice
    for(i = 0; i < (bobs_set_size > alices_set_size ? bobs_set_size : alices_set_size); i++){
        found = bsearch(alices_private_set+i, bobs_private_set, bobs_set_size, sizeof(pref_t), compare_prefs);
        if(found){
            if(prefs = fopen("alice.txt", "r")){
                fseek(prefs, found->offset, SEEK_SET);
                if(fgets(pref, MAX_STRLEN, prefs)){
                    printf("Shared Pref: %s", pref);
                }
                fclose(prefs);
            }
        }
    }
}
