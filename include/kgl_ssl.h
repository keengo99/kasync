#ifndef KSSH_H_99
#define KSSH_H_99
#include "kfeature.h"

#ifdef KSOCKET_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "kselector.h"
#include "kssl_bio.h"
#include "kmalloc.h"
#include "kcountable.h"
#include "kforwin32.h"
#define KGL_HTTP_NPN_ADVERTISE  "\x08http/1.1"
#ifdef SSL_READ_EARLY_DATA_SUCCESS
#define ENABLE_KSSL_EARLY 1
#endif
#ifdef SSL_ERROR_EARLY_DATA_REJECTED
#define ENABLE_KSSL_EARLY 1
#endif
KBEGIN_DECLS

typedef void (*kgl_ssl_npn_f)(void *ssl_ctx_data, const unsigned char **out, unsigned int *outlen);
typedef void *(*kgl_ssl_create_sni_f)(SSL *ssl, KOPAQUE server_ctx, const char *hostname);
typedef void (*kgl_ssl_free_sni_f)(void *sni);
typedef enum
{
	ret_error,
	ret_ok,
	ret_want_read,
	ret_want_write,
	ret_sni_resolve
} kssl_status;

typedef struct {
	SSL *ssl;
#ifdef ENABLE_KSSL_BIO
	kssl_bio bio[2];
#endif
#ifdef ENABLE_KSSL_EARLY
	u_char early_buf;
	uint8_t try_early_data : 1;
	uint8_t in_early : 1;
	uint8_t early_preread : 1;
#endif
	uint16_t handshake : 1;
} kssl_session;

void kssl_init(kgl_ssl_npn_f npn, kgl_ssl_create_sni_f create_sni, kgl_ssl_free_sni_f free_sni);
void kssl_init2();
void kssl_set_npn_callback(kgl_ssl_npn_f npn);
void kssl_set_sni_callback(kgl_ssl_create_sni_f create_sni, kgl_ssl_free_sni_f free_sni);
void kgl_ssl_ctx_set_early_data(SSL_CTX *ssl_ctx, bool early_data);
SSL_CTX *kgl_ssl_ctx_new_server_from_memory(const char *cert,const char *key, const char* ca_path, const char* ca_file, void* ssl_ctx_data);
SSL_CTX *kgl_ssl_ctx_new_server(const char *cert_file, const char *key_file, const char *ca_path,const char *ca_file,void *ssl_ctx_data);
SSL_CTX *kgl_ssl_ctx_new_client(const char *ca_path, const char *ca_file,void *ssl_ctx_data);

kssl_status kgl_ssl_shutdown(SSL *ssl);
kssl_status kgl_ssl_handshake(SSL *ssl);
kssl_status kgl_ssl_handshake_status(SSL *ssl, int re);
void kgl_ssl_get_next_proto_negotiated(SSL *ssl,const unsigned char **data, unsigned *len);
void kgl_ssl_ctx_set_protocols(SSL_CTX *ctx, const char *protocols);
bool kgl_ssl_ctx_set_cipher_list(SSL_CTX *ctx, const char *cipher);
extern int kangle_ssl_conntion_index;
extern int kangle_ssl_ctx_index;

typedef struct {
	kcountable_t refs;
	SSL_CTX *ctx;
} kgl_ssl_ctx;

INLINE void kgl_add_ref_ssl_ctx(kgl_ssl_ctx *ssl_ctx)
{
	katom_inc((void *)&ssl_ctx->refs);
}
INLINE void kgl_release_ssl_ctx(kgl_ssl_ctx *ssl_ctx)
{
	if (katom_dec((void *)&ssl_ctx->refs) == 0) {
		SSL_CTX_free(ssl_ctx->ctx);
		xfree(ssl_ctx);
	}
}
INLINE SSL_CTX *kgl_get_ssl_ctx(kgl_ssl_ctx *ssl_ctx)
{
	if (ssl_ctx == NULL) {
		return NULL;
	}
	return ssl_ctx->ctx;
}
INLINE kgl_ssl_ctx *kgl_new_ssl_ctx(SSL_CTX *ctx)
{
	kgl_ssl_ctx *ssl_ctx = xmemory_new(kgl_ssl_ctx);
	ssl_ctx->refs = 1;
	ssl_ctx->ctx = ctx;
	return ssl_ctx;
}
KEND_DECLS
#else
typedef void * kgl_ssl_ctx;
#endif
#endif
