// Sequential hash-chain speed (one core), same input layout as v2: prev(32)||pk(33)||i(8) = 73 bytes.
//
// This measures a genuine dependent chain: iteration i hashes the output of iteration i-1,
// so the hashes CANNOT be parallelised or pipelined. That is exactly the work a v2 cheater
// must do to recompute a chain segment, and the honest prover to plot.
//
// On OpenSSL 3 the one-shot SHA256() and the deprecated low-level SHA256_* API both dispatch
// through the provider layer per call, which is slow. The fast path is to fetch the EVP_MD
// once and reuse a single EVP_MD_CTX, re-initialising it each iteration. That routes to the
// architecture's optimised core (ARMv8 SHA-2 / x86 SHA-NI) with no per-call fetch overhead.
//
// Build (macOS, Homebrew OpenSSL 3):
//   cc -O3 -march=native chainrate.c -o chainrate \
//      -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto
// Run:  ./chainrate [num_hashes]   -> prints million hashes/sec (MH/s) on one core.
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
  long n = argc > 1 ? atol(argv[1]) : 50000000;
  unsigned char buf[73] = {0}, h[32] = {0};

  EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", NULL);   // fetch once, outside the loop
  if (!md) { fprintf(stderr, "EVP_MD_fetch failed\n"); return 2; }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { fprintf(stderr, "EVP_MD_CTX_new failed\n"); return 2; }

  struct timespec a, b;
  clock_gettime(CLOCK_MONOTONIC, &a);
  for (long i = 1; i < n; i++) {
    memcpy(buf, h, 32);                                // prev = previous digest
    for (int j = 0; j < 8; j++) buf[65 + j] = (i >> (56 - 8 * j)) & 0xff;  // i as 8-byte BE
    unsigned int outlen = 0;
    EVP_DigestInit_ex2(ctx, md, NULL);                 // reuse ctx, re-init (no re-fetch)
    EVP_DigestUpdate(ctx, buf, 73);
    EVP_DigestFinal_ex(ctx, h, &outlen);
  }
  clock_gettime(CLOCK_MONOTONIC, &b);

  double s = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
  printf("%.3f\n", n / s / 1e6);   // million hashes per second (MH/s), one core
  EVP_MD_CTX_free(ctx);
  EVP_MD_free(md);
  return h[0] == 42;   // consume h so the loop is not optimised away
}
