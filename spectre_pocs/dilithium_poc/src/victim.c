#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "randombytes.h"
#include "sign.h"
#include "polyvec.h"
#include "packing.h"
#include "util.h"

void dump_keys(uint8_t* sk);

/* Run Victim First */
int main(void)
{
    size_t smlen;
    uint8_t m[MLEN + CRYPTO_BYTES];
    uint8_t sm[MLEN + CRYPTO_BYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    pid_t pid = getpid();
    printf("Current process PID: %d\n", pid);

    crypto_sign_keypair(pk, sk);
    dump_keys(sk);

    volatile msg_t* shared_channel = (msg_t*)create_shared_memory("sharedfile.txt");
    // clear message flag
    shared_channel->msg_flag = 1;
    printf("[+] shared channel set up\n");
    uint64_t trash = 0;

    while(1) {
        // shared memory wait for attacker
        MEM_BARRIER; INST_BARRIER;
        while(shared_channel->msg_flag == 0){ trash = (trash + 1) & 0xffff; };
        MEM_BARRIER; INST_BARRIER;
        printf("[+] Generate new signature\n");
        // new message
        randombytes(m, MLEN);
        // sign message
        crypto_sign(sm, &smlen, m, MLEN, sk);
        // copy signed message to shared memory
        memcpy((void *)shared_channel->msg, sm, smlen);
        // clear message flag
        MEM_BARRIER; INST_BARRIER;
        shared_channel->msg_flag = 0;
        MEM_BARRIER; INST_BARRIER;
    }
    return 0;
}

void dump_keys(uint8_t* sk) {
    // init file for pk and sk
    FILE *pk_file = fopen("pk.txt", "w");
    FILE *sk_file = fopen("sk.txt", "w");
    assert(pk_file != NULL);
    assert(sk_file != NULL);
    // unpack sk (get s1, s2)
    uint8_t rho[SEEDBYTES];
    uint8_t tr[SEEDBYTES];
    uint8_t key[SEEDBYTES];
    polyveck t0;
    polyvecl s1;
    polyveck s2;
    unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);
    // dump s1, s2
    for (int s1_vec_idx=0; s1_vec_idx<L; s1_vec_idx++) {
        for (int s1_coeff_idx=0; s1_coeff_idx<N; s1_coeff_idx++) {
            fprintf(sk_file, "%d ", s1.vec[s1_vec_idx].coeffs[s1_coeff_idx]);
        }
        fprintf(sk_file, "\n");
    }
    for (int s2_vec_idx=0; s2_vec_idx<K; s2_vec_idx++) {
        for (int s2_coeff_idx=0; s2_coeff_idx<N; s2_coeff_idx++) {
            fprintf(sk_file, "%d ", s2.vec[s2_vec_idx].coeffs[s2_coeff_idx]);
        }
        fprintf(sk_file, "\n");
    }
    // unpack pk (get A)
    polyvecl mat[K];
    polyvec_matrix_expand(mat, rho);
    polyvecl_ntt(&s1);
    polyvec_matrix_pointwise_montgomery(&t0, mat, &s1);
    polyveck_reduce(&t0);
    polyveck_invntt_tomont(&t0);
    polyveck_add(&t0, &t0, &s2);
    // dump A, t (t0)
    for (int mat_idx=0; mat_idx<K; mat_idx++) {
        // invntt
        polyvecl_invntt_tomont(&mat[mat_idx]);
        for (int mat_vec_idx=0; mat_vec_idx<L; mat_vec_idx++) {
            for (int mat_coeff_idx=0; mat_coeff_idx<N; mat_coeff_idx++) {
                fprintf(pk_file, "%d ", mat[mat_idx].vec[mat_vec_idx].coeffs[mat_coeff_idx]);
            }
            fprintf(pk_file, "\n");
        }
    }
    for (int t0_vec_idx=0; t0_vec_idx<K; t0_vec_idx++) {
        for (int t0_coeff_idx=0; t0_coeff_idx<N; t0_coeff_idx++) {
            fprintf(pk_file, "%d ", t0.vec[t0_vec_idx].coeffs[t0_coeff_idx]);
        }
        fprintf(pk_file, "\n");
    }
    fclose(pk_file);
    fclose(sk_file);
}
