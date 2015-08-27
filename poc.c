// Copyright (C) 2015 Teledildonics group
// Proof of concept secure kink exchange

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "crypto_hash_sha256.h"
#include "crypto_scalarmult_curve25519.h"
#include "randombytes.h"

#define MAX_STRLEN 256
#define MAX_SET_SIZE 256
#define POINT_SIZE 32
// about 8k

typedef struct {
    unsigned char encrypted_pref[POINT_SIZE];
    unsigned long offset;
} pref_t;

int compare_prefs(const void* a, const void* b){
    return memcmp(((pref_t*) a)->encrypted_pref, ((pref_t*) b)->encrypted_pref, POINT_SIZE);
}

void sort_prefs(pref_t *the_set, unsigned int the_set_size){
    qsort(the_set, the_set_size, sizeof(pref_t), compare_prefs);
}

unsigned int init(unsigned char * the_filename, pref_t *the_set, unsigned char * the_ephemeral_key){
    unsigned char pref[MAX_STRLEN];
    unsigned char hashed_pref[crypto_hash_sha256_BYTES];
    unsigned int i = 0;
    FILE* prefs;
    if(prefs = fopen(the_filename, "r")){
        while(!feof(prefs)){
            if(fgets(pref, MAX_STRLEN, prefs)){
                crypto_hash_sha256(hashed_pref, pref, strlen(pref));
                crypto_scalarmult_curve25519(the_set[i].encrypted_pref, the_ephemeral_key, hashed_pref);
                the_set[i].offset = ftell(prefs)-strlen(pref);
                i++;
            }
        }
        fclose(prefs);
    }
    return i;
}

unsigned int compare(pref_t *set_a, pref_t *set_b, unsigned char * data_file, int output, unsigned int active_set_size){
    int i;
    unsigned char pref[MAX_STRLEN];
    pref_t *found;
    FILE* prefs;
    unsigned int matches = 0;
    for(i = 0; i < active_set_size; i++){
        found = bsearch(set_a+i, set_b, active_set_size, sizeof(pref_t), compare_prefs);
        if(found && set_a[i].offset != -1){
            matches++;
            if(output){
                if(prefs = fopen(data_file, "r")){
                    fseek(prefs, set_a[i].offset, SEEK_SET);
                    if(fgets(pref, MAX_STRLEN, prefs)){
                        printf("%s contains shared pref: %s", data_file, pref);
                    }
                    fclose(prefs);
                }
            }
        }
    }
    return matches;
}

int network_ab[2], network_ba[2];

void* alice_thread(void* v){
    pref_t alices_private_set[MAX_SET_SIZE];
    pref_t bobs_private_set[MAX_SET_SIZE];
    pref_t shared_private_set[MAX_SET_SIZE];
    memset(alices_private_set, -1, sizeof(alices_private_set));
    unsigned char alices_ephemeral_key[POINT_SIZE];

    // initialize key
    randombytes(alices_ephemeral_key, POINT_SIZE);

    // negotiate appropriate set size
    unsigned int active_set_size = init("alice.txt", alices_private_set, alices_ephemeral_key);
    unsigned int bobs_set_size;

    write(network_ab[1], &active_set_size, sizeof(active_set_size));
    read(network_ba[0], &bobs_set_size, sizeof(bobs_set_size));
    if(active_set_size > bobs_set_size){
        active_set_size = bobs_set_size;
    }
    sort_prefs(alices_private_set, active_set_size);

    int i;
    for(i = 0; i < active_set_size; i++){
        // send Alice's point
        write(network_ab[1], alices_private_set[i].encrypted_pref, POINT_SIZE);

        // get it back encrypted
        read(network_ba[0], alices_private_set[i].encrypted_pref, POINT_SIZE);

        // get Bob's point
        read(network_ba[0], bobs_private_set[i].encrypted_pref, POINT_SIZE);
        bobs_private_set[i].offset = 0;

        // encrypt Bob's point
        crypto_scalarmult_curve25519(bobs_private_set[i].encrypted_pref, alices_ephemeral_key, bobs_private_set[i].encrypted_pref);

        // cheating/replay detection
        sort_prefs(shared_private_set, active_set_size);
        pref_t *result = bsearch(bobs_private_set+i, shared_private_set, active_set_size, sizeof(pref_t), compare_prefs);
        if(result){
            // duplicate ciphertext received, ABORT
            printf("ALICE FEELS SOMEBODY IS CHEATING\n");
            exit(0);
        }
        memcpy(shared_private_set[i].encrypted_pref, bobs_private_set[i].encrypted_pref, POINT_SIZE);

        // see if we are still interested
        sort_prefs(shared_private_set, active_set_size);
        if(compare(alices_private_set, shared_private_set, NULL, 0, active_set_size) < 1 && i > (active_set_size/2)){
            printf("ALICE FEELS LIKE THIS IS GOING NOWHERE\n");
            /*exit(0);*/
        }

        // send Bob's encrypted point back
        write(network_ab[1], bobs_private_set[i].encrypted_pref, POINT_SIZE);

    }

    sort_prefs(bobs_private_set, active_set_size);
    compare(alices_private_set, bobs_private_set, "alice.txt", 1, active_set_size);
}

void* bob_thread(void* v){
    pref_t bobs_private_set[MAX_SET_SIZE];
    pref_t alices_private_set[MAX_SET_SIZE];
    pref_t shared_private_set[MAX_SET_SIZE];
    memset(bobs_private_set, -1, sizeof(alices_private_set));
    unsigned char bobs_ephemeral_key[POINT_SIZE];

    // initialize key
    randombytes(bobs_ephemeral_key,POINT_SIZE);

    // negotiate appropriate set size
    unsigned int active_set_size = init("bob.txt", bobs_private_set, bobs_ephemeral_key);
    unsigned int alices_set_size;

    read(network_ab[0], &alices_set_size, sizeof(alices_set_size));
    if(active_set_size > alices_set_size){
        active_set_size = alices_set_size;
    }
    write(network_ba[1], &active_set_size, sizeof(active_set_size));
    sort_prefs(bobs_private_set, active_set_size);

    int i;
    for(i = 0; i < active_set_size; i++){
        // receive Alice's point
        read(network_ab[0], alices_private_set[i].encrypted_pref, POINT_SIZE);

        // encrypt it
        crypto_scalarmult_curve25519(alices_private_set[i].encrypted_pref, bobs_ephemeral_key, alices_private_set[i].encrypted_pref);

        // cheating/replay detection
        sort_prefs(shared_private_set, active_set_size);
        pref_t *result = bsearch(alices_private_set+i, shared_private_set, active_set_size, sizeof(pref_t), compare_prefs);
        if(result){
            // duplicate ciphertext received, ABORT
            printf("BOB FEELS SOMEBODY IS CHEATING\n");
            exit(0);
        }
        memcpy(shared_private_set[i].encrypted_pref, alices_private_set[i].encrypted_pref, POINT_SIZE);

        // see if we are still interested
        sort_prefs(shared_private_set, active_set_size);
        if(compare(bobs_private_set, shared_private_set, NULL, 0, active_set_size) < 1 && i > (active_set_size/2)){
            printf("BOB FEELS LIKE THIS IS GOING NOWHERE\n");
            /*exit(0);*/
        }

        // send encrypted point back
        write(network_ba[1], alices_private_set[i].encrypted_pref, POINT_SIZE);
        alices_private_set[i].offset = 0;

        // send Bob's point
        write(network_ba[1], bobs_private_set[i].encrypted_pref, POINT_SIZE);

        // get it back encrypted
        read(network_ab[0], bobs_private_set[i].encrypted_pref, POINT_SIZE);
    }

    sort_prefs(alices_private_set, active_set_size);
    compare(bobs_private_set, alices_private_set, "bob.txt", 1, active_set_size);
}

void main(int argc, char* argv[]){
    if(pipe(network_ab) < 0){
        perror("pipe");
    }
    if(pipe(network_ba) < 0){
        perror("pipe");
    }
    pthread_t alice, bob;
    pthread_create(&alice, NULL, alice_thread, NULL);
    pthread_create(&bob, NULL, bob_thread, NULL);
    pthread_join(alice, NULL);
    pthread_join(bob, NULL);
}
