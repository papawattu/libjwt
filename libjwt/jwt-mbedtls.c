#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <types.h>
#include <errno.h>


#include "jwt.h"
#include "jwt-private.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "esp_system.h"
//#include "mbedtls/pem.h"


int mg_ssl_if_mbed_random(void *ctx, unsigned char *buf, size_t len) {
  while (len > 0) {
    uint32_t r = esp_random(); /* Uses hardware RNG. */
    for (int i = 0; i < 4 && len > 0; i++, len--) {
      *buf++ = (uint8_t) r;
      r >>= 8;
    }
  }
  (void) ctx;
  return 0;
}
int jwt_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
		      const char *str)
{
	printf("\n\ngot here\n");
    return 0;
}

int jwt_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len, const char *str)
{
    mbedtls_pk_context s_token_key;
    unsigned char hash[32];
     
    mbedtls_pk_init(&s_token_key);

    int r = mbedtls_pk_parse_key(&s_token_key, jwt->key,jwt->key_len,NULL,0);
    
    if (r != 0) {
        printf("Invalid gcp.key (0x%x)", r);
        return -1;
    }
    
    //bool is_rsa = mbedtls_pk_can_do(&s_token_key, MBEDTLS_PK_RSA);
    int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                       (const unsigned char *) str, strlen(str), hash);
    if (ret != 0) {
        printf("mbedtls_md failed: 0x%x", r);
        return 1;
    }
    
    *len = mbedtls_pk_get_len(&s_token_key);
    *out = malloc(*len);
    if (*out == NULL) {
        return ENOMEM;
    }
    
    ret = mbedtls_pk_sign(&s_token_key, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                        (unsigned char *) *out, len, mg_ssl_if_mbed_random, NULL);
    if (ret != 0) {
        printf("mbedtls_pk_sign failed: 0x%x\n", ret);
        free(*out);
        *out = NULL;
        return EINVAL;
    }

    return 0;   
}