#include <ctype.h>
#include "kgl_ssl.h"
#include "ksync.h"
#include "klog.h"
#include "kstring.h"
#ifdef KSOCKET_SSL
#include <errno.h>
#ifdef _WIN32
//#pragma comment(lib,"ssleay32.lib")
//#pragma comment(lib,"libeay32.lib")
#endif
#include "kconnection.h"
#include "kserver.h"
#define KGL_SSL_ERR_BUF_SIZE 256
static kmutex* ssl_lock = NULL;
int kangle_ssl_conntion_index;
int kangle_ssl_ctx_index;
static kgl_ssl_npn_f ssl_npn;
kgl_ssl_create_sni_f kgl_ssl_create_sni = NULL;
kgl_ssl_free_sni_f kgl_ssl_free_sni = NULL;

int kgl_ssl_sni(SSL* ssl, int* ad, void* arg);
typedef struct {
	kgl_str_t                 name;
	int                       mask;
} kgl_string_bitmask_t;
#define KGL_SSL_SSLv2    0x0002
#define KGL_SSL_SSLv3    0x0004
#define KGL_SSL_TLSv1    0x0008
#define KGL_SSL_TLSv1_1  0x0010
#define KGL_SSL_TLSv1_2  0x0020
#define KGL_SSL_TLSv1_3  0x0040
static kgl_string_bitmask_t  kgl_ssl_protocols[] = {
	{ kgl_string("SSLv2"), KGL_SSL_SSLv2 },
	{ kgl_string("SSLv3"), KGL_SSL_SSLv3 },
	{ kgl_string("TLSv1"), KGL_SSL_TLSv1 },
	{ kgl_string("TLSv1.1"), KGL_SSL_TLSv1_1 },
	{ kgl_string("TLSv1.2"), KGL_SSL_TLSv1_2 },
	{ kgl_string("TLSv1.3"), KGL_SSL_TLSv1_3 },
	{ kgl_null_string, 0 }
};


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
int kgl_ssl_sni(SSL* ssl, int* ad, void* arg) {
	kassert(kgl_ssl_create_sni);
	kconnection* c = (kconnection*)SSL_get_ex_data(ssl, kangle_ssl_conntion_index);
	if (c == NULL || c->sni) {
		return SSL_TLSEXT_ERR_OK;
	}
	const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (servername == NULL) {
		if (kserver_test_flag(c->server, KGL_SERVER_REJECT_NOSNI) > 0) {
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		} else {
			return SSL_TLSEXT_ERR_OK;
		}
	}
	SSL_CTX* ssl_ctx = NULL;
	c->sni = kgl_ssl_create_sni(kserver_get_opaque(c->server), servername, &ssl_ctx);
	if (ssl_ctx) {
		SSL_set_SSL_CTX(ssl, ssl_ctx);
	}
	return SSL_TLSEXT_ERR_OK;
}
#endif
#if defined(TLSEXT_TYPE_next_proto_neg) || defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
int kgl_ssl_npn_selected(SSL* ssl, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg) {
	const unsigned char* selected_protocol = (const unsigned char*)KGL_HTTP_NPN_ADVERTISE;
	unsigned int selected_len = sizeof(KGL_HTTP_NPN_ADVERTISE) - 1;
	if (kgl_ssl_create_sni) {
		int ret = kgl_ssl_sni(ssl, NULL, NULL);
		if (ret != SSL_TLSEXT_ERR_OK) {
			return ret;
		}
	}
	SSL_CTX* ctx = SSL_get_SSL_CTX(ssl);
	void* ssl_ctx_data = SSL_CTX_get_ex_data(ctx, kangle_ssl_ctx_index);
	ssl_npn(ssl, ssl_ctx_data, &selected_protocol, &selected_len);
	if (SSL_select_next_proto(
		(unsigned char**)out,
		outlen,
		selected_protocol,
		selected_len,
		in,
		inlen
	) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	//klog(KLOG_DEBUG,"SSL ALPN selected: %*s", *outlen, *out);
	return SSL_TLSEXT_ERR_OK;
}
int kgl_ssl_npn_selected2(SSL* ssl, unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg) {
	return kgl_ssl_npn_selected(ssl, (const unsigned char**)out, outlen, in, inlen, arg);
}
int kgl_ssl_npn_advertise(SSL* ssl, const unsigned char** out, unsigned int* outlen, void* arg) {
	SSL_CTX* ctx = SSL_get_SSL_CTX(ssl);
	void* ssl_ctx_data = SSL_CTX_get_ex_data(ctx, kangle_ssl_ctx_index);
	ssl_npn(ssl, ssl_ctx_data, out, outlen);
	return SSL_TLSEXT_ERR_OK;
}
#endif
static unsigned long __get_thread_id(void) {
	return (unsigned long)pthread_self();
}
static void __lock_thread(int mode, int n, const char* file, int line) {
	if (mode & CRYPTO_LOCK) {
		kmutex_lock(&ssl_lock[n]);
	} else {
		kmutex_unlock(&ssl_lock[n]);
	}
}
void kssl_set_npn_callback(kgl_ssl_npn_f npn) {
	ssl_npn = npn;
}
void kssl_set_sni_callback(kgl_ssl_create_sni_f create_sni, kgl_ssl_free_sni_f free_sni) {
	kgl_ssl_create_sni = create_sni;
	kgl_ssl_free_sni = free_sni;
}
void kssl_clean() {
#ifdef ENABLE_KSSL_BIO
	kgl_bio_clean_method();
#endif
#ifndef OPENSSL_IS_BORINGSSL
	int locks_num = CRYPTO_num_locks();
	for (int i = 0; i < locks_num; i++) {
		kmutex_destroy(&ssl_lock[i]);
	}
#endif
}
void kssl_init2() {
	SSL_load_error_strings();
	SSL_library_init();
	SSLeay_add_ssl_algorithms();
#ifndef OPENSSL_IS_BORINGSSL
	if ((CRYPTO_get_id_callback() == NULL) &&
		(CRYPTO_get_locking_callback() == NULL)) {
		//cuint_t n;

		CRYPTO_set_id_callback(__get_thread_id);
		CRYPTO_set_locking_callback(__lock_thread);

		int locks_num = CRYPTO_num_locks();
		ssl_lock = (kmutex*)xmalloc(sizeof(kmutex) * locks_num);
		for (int i = 0; i < locks_num; i++) {
			kmutex_init(&ssl_lock[i], NULL);
		}
	}
#endif
	kangle_ssl_conntion_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	kangle_ssl_ctx_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
#ifdef ENABLE_KSSL_BIO
	kgl_bio_init_method();
#endif
}
void kssl_init(kgl_ssl_npn_f npn, kgl_ssl_create_sni_f create_sni, kgl_ssl_free_sni_f free_sni) {
	kssl_set_sni_callback(create_sni, free_sni);
	kssl_set_npn_callback(npn);
	kssl_init2();
}
bool kgl_ssl_support_sendfile(kssl_session* ssl) {
#ifdef ENABLE_KSSL_BIO
	return false;
#else
#if defined(BIO_get_ktls_send) && !defined(_WIN32)
	return BIO_get_ktls_send(SSL_get_wbio(ssl->ssl)) == 1;
#endif
	return false;
#endif
}
static RSA* kgl_ssl_rsa512_key_callback(SSL* ssl_conn, int is_export, int key_length) {
	static RSA* key;

	if (key_length != 512) {
		return NULL;
	}
#if (OPENSSL_VERSION_NUMBER < 0x10100003L && !defined OPENSSL_NO_DEPRECATED)
	if (key == NULL) {
		key = RSA_generate_key(512, RSA_F4, NULL, NULL);
	}

#endif
	return key;
}
static bool kgl_ssl_ecdh_curve(SSL_CTX* ctx, const char* name) {
#ifndef OPENSSL_NO_ECDH
	/*
	 * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
	 * from RFC 4492 section 5.1.1, or explicitly described curves over
	 * binary fields.  OpenSSL only supports the "named curves", which provide
	 * maximum interoperability.
	 */

#if (defined SSL_CTX_set1_curves_list || defined SSL_CTRL_SET_CURVES_LIST)

	 /*
	  * OpenSSL 1.0.2+ allows configuring a curve list instead of a single
	  * curve previously supported.  By default an internal list is used,
	  * with prime256v1 being preferred by server in OpenSSL 1.0.2b+
	  * and X25519 in OpenSSL 1.1.0+.
	  *
	  * By default a curve preferred by the client will be used for
	  * key exchange.  The SSL_OP_CIPHER_SERVER_PREFERENCE option can
	  * be used to prefer server curves instead, similar to what it
	  * does for ciphers.
	  */

	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
#if SSL_CTRL_SET_ECDH_AUTO
	/* not needed in OpenSSL 1.1.0+ */
	SSL_CTX_set_ecdh_auto(ctx, 1);
#endif
	if (strcmp(name, "auto") == 0) {
		return true;
	}
	if (SSL_CTX_set1_curves_list(ctx, (char*)name) == 0) {
		klog(KLOG_ERR, "SSL_CTX_set1_curves_list(\"%s\") failed", name);
		return false;
	}
#else
	int      nid;
	const char* curve;
	EC_KEY* ecdh;
	if (ngx_strcmp(name, "auto") == 0) {
		curve = "prime256v1";
	} else {
		curve = name;
	}
	nid = OBJ_sn2nid(curve);
	if (nid == 0) {
		klog(KLOG_ERR, "OBJ_sn2nid(\"%s\") failed: unknown curve", curve);
		return false;
	}
	ecdh = EC_KEY_new_by_curve_name(nid);
	if (ecdh == NULL) {
		klog(KLOG_ERR, "EC_KEY_new_by_curve_name(\"%s\") failed", curve);
		return false;
	}

	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
	SSL_CTX_set_tmp_ecdh(ctx, ecdh);
	EC_KEY_free(ecdh);
#endif
#endif
	return true;
}
static bool kgl_ssl_session_digest_x509_list(SSL_CTX* ssl_ctx, EVP_MD_CTX* md) {
	size_t                   n, i;
	STACK_OF(X509_NAME)* list;
	unsigned int          len;
	u_char                buf[EVP_MAX_MD_SIZE];
	X509_NAME* name;
	list = SSL_CTX_get_client_CA_list(ssl_ctx);

	if (list != NULL) {
		n = sk_X509_NAME_num(list);
		for (i = 0; i < n; i++) {
			name = sk_X509_NAME_value(list, (int)i);
			if (X509_NAME_digest(name, EVP_sha1(), buf, &len) == 0) {
				klog(KLOG_ERR, "X509_NAME_digest() failed");
				return false;
			}

			if (EVP_DigestUpdate(md, buf, len) == 0) {
				klog(KLOG_ERR, "EVP_DigestUpdate() failed");
				return false;
			}
		}
	}
	return true;
}
static bool kgl_ssl_session_id_context_from_buffer(SSL_CTX* ssl_ctx, const char* cert) {
	EVP_MD_CTX* md;
	unsigned int          len;
	u_char                buf[EVP_MAX_MD_SIZE];
	md = EVP_MD_CTX_create();
	if (md == NULL) {
		return false;
	}
	if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 0) {
		klog(KLOG_ERR, "EVP_DigestInit_ex() failed");
		goto failed;
	}
	if (EVP_DigestUpdate(md, cert, strlen(cert)) == 0) {
		klog(KLOG_ERR, "EVP_DigestUpdate() failed");
		goto failed;
	}
	if (!kgl_ssl_session_digest_x509_list(ssl_ctx, md)) {
		goto failed;
	}
	if (EVP_DigestFinal_ex(md, buf, &len) == 0) {
		klog(KLOG_ERR, "EVP_DigestUpdate() failed");
		goto failed;
	}
	EVP_MD_CTX_destroy(md);
	if (SSL_CTX_set_session_id_context(ssl_ctx, buf, len) == 0) {
		klog(KLOG_ERR, "SSL_CTX_set_session_id_context() failed");
		return false;
	}
	return true;
failed:
	EVP_MD_CTX_destroy(md);
	return false;
}
static bool kgl_ssl_session_id_context(SSL_CTX* ssl_ctx, const char* cert_file) {

	EVP_MD_CTX* md;
	unsigned int          len;
	u_char                buf[EVP_MAX_MD_SIZE];
	FILE* fp;
	md = EVP_MD_CTX_create();
	if (md == NULL) {
		return false;
	}
	if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 0) {
		klog(KLOG_ERR, "EVP_DigestInit_ex() failed");
		goto failed;
	}
	if (EVP_DigestUpdate(md, cert_file, strlen(cert_file)) == 0) {
		klog(KLOG_ERR, "EVP_DigestUpdate() failed");
		goto failed;
	}
	fp = fopen(cert_file, "rb");
	if (fp != NULL) {
		char buffer[512];
		size_t total_read = 0;
		while (total_read < 1048576) {
			size_t read_len = fread(buffer, 1, sizeof(buffer), fp);
			if (read_len == 0) {
				break;
			}
			total_read += read_len;
			if (EVP_DigestUpdate(md, buffer, read_len) == 0) {
				klog(KLOG_ERR, "EVP_DigestUpdate() failed");
				break;
			}
		}
		fclose(fp);
	}
	if (!kgl_ssl_session_digest_x509_list(ssl_ctx, md)) {
		goto failed;
	}
	if (EVP_DigestFinal_ex(md, buf, &len) == 0) {
		klog(KLOG_ERR, "EVP_DigestUpdate() failed");
		goto failed;
	}
	EVP_MD_CTX_destroy(md);
	if (SSL_CTX_set_session_id_context(ssl_ctx, buf, len) == 0) {
		klog(KLOG_ERR, "SSL_CTX_set_session_id_context() failed");
		return false;
	}
	return true;
failed:
	EVP_MD_CTX_destroy(md);
	return false;
}

SSL_CTX* kgl_ssl_ctx_new(void* ssl_ctx_data) {
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	if (ctx == NULL) {
		fprintf(stderr, "ssl_ctx_new function error\n");
		return NULL;
	}
	/* client side options */

	SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
	SSL_CTX_set_options(ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);

	/* server side options */

	SSL_CTX_set_options(ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
	SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);

#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
	/* this option allow a potential SSL 2.0 rollback (CAN-2005-2969) */
	SSL_CTX_set_options(ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);
#endif
	SSL_CTX_set_options(ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
	SSL_CTX_set_options(ctx, SSL_OP_TLS_D5_BUG);
	SSL_CTX_set_options(ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);
	SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
	//ssl_prefer_server_ciphers on
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
#ifdef SSL_MODE_NO_AUTO_CHAIN
	SSL_CTX_set_mode(ctx, SSL_MODE_NO_AUTO_CHAIN);
#endif
	SSL_CTX_set_read_ahead(ctx, 0);
	SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
#if (OPENSSL_VERSION_NUMBER < 0x10100001L && !defined LIBRESSL_VERSION_NUMBER)
	SSL_CTX_set_tmp_rsa_callback(ctx, kgl_ssl_rsa512_key_callback);
#endif
	//disable SSLV2
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
	//kgl_ssl_dhparam(ssl_ctx);
	kgl_ssl_ecdh_curve(ctx, "auto");
	SSL_CTX_set_ex_data(ctx, kangle_ssl_ctx_index, ssl_ctx_data);
	return ctx;
}
SSL_CTX* kgl_ssl_ctx_new_client(const char* ca_path, const char* ca_file, void* ssl_ctx_data) {
	SSL_CTX* ctx = kgl_ssl_ctx_new(ssl_ctx_data);
	if (ctx == NULL) {
		fprintf(stderr, "cann't init_ctx\n");
		return NULL;
	}
	if (ca_path != NULL || ca_file != NULL) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		if (SSL_CTX_load_verify_locations(ctx, ca_file, ca_path) <= 0) {
			char err_buf[KGL_SSL_ERR_BUF_SIZE];
			ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
			klog(KLOG_ERR, "SSL_CTX_load_verify_locations error Error allocating handle: %s\n", err_buf);
			SSL_CTX_free(ctx);
			return NULL;
		}
	}
	const unsigned char s_server_session_id_context[100] = "msocket";
	SSL_CTX_set_session_id_context(ctx, (const unsigned char*)s_server_session_id_context, sizeof(s_server_session_id_context));
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
	if (ssl_npn && ssl_ctx_data) {
#ifdef TLSEXT_TYPE_next_proto_neg
		//SSL_CTX_set_next_proto_select_cb(ctx, kgl_ssl_npn_selected2, NULL);
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
		const unsigned char* alpn_protos = NULL;
		unsigned int alpn_protos_len = 0;
		ssl_npn(NULL, ssl_ctx_data, &alpn_protos, &alpn_protos_len);
		SSL_CTX_set_alpn_protos(ctx, alpn_protos, alpn_protos_len);
#endif
	}
	return ctx;
}
void kgl_ssl_ctx_set_early_data(SSL_CTX* ssl_ctx, bool early_data) {
	if (early_data) {
#ifdef SSL_ERROR_EARLY_DATA_REJECTED
		/* BoringSSL */
		SSL_CTX_set_early_data_enabled(ssl_ctx, 1);
#elif defined SSL_READ_EARLY_DATA_SUCCESS
		/* OpenSSL */
		SSL_CTX_set_max_early_data(ssl_ctx, 16384);
#endif
		return;
	}
#ifdef SSL_ERROR_EARLY_DATA_REJECTED
	/* BoringSSL */
	SSL_CTX_set_early_data_enabled(ssl_ctx, 0);
#elif defined SSL_READ_EARLY_DATA_SUCCESS
	/* OpenSSL */
	SSL_CTX_set_max_early_data(ssl_ctx, 0);
#endif
}

static int kgl_ssl_password_callback(char* buf, int size, int rwflag, void* userdata) {
	kgl_str_t* pwd = (kgl_str_t*)userdata;
	if (rwflag) {
		klog(KLOG_WARNING, "kgl_ssl_password_callback() is called for encryption");
		return 0;
	}
	if (pwd == NULL) {
		return 0;
	}

	if (pwd->len > (size_t)size) {
		klog(KLOG_ERR, "password is truncated to %d bytes", size);
	} else {
		size = (int)pwd->len;
	}
	kgl_memcpy(buf, pwd->data, size);
	return size;
}

static X509* kgl_ssl_load_certificate(const char** err, const kgl_ref_str_t* cert, STACK_OF(X509)** chain) {
	BIO* bio;
	X509* x509, * temp;
	u_long   n;

	if (strncmp(cert->data, "data:", sizeof("data:") - 1) == 0) {

		bio = BIO_new_mem_buf(cert->data + sizeof("data:") - 1,
			cert->len - (sizeof("data:") - 1));
		if (bio == NULL) {
			*err = "BIO_new_mem_buf() failed";
			return NULL;
		}

	} else {
		bio = BIO_new_file((char*)cert->data, "r");
		if (bio == NULL) {
			*err = "BIO_new_file() failed";
			return NULL;
		}
	}

	/* certificate itself */

	x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
	if (x509 == NULL) {
		*err = "PEM_read_bio_X509_AUX() failed";
		BIO_free(bio);
		return NULL;
	}

	/* rest of the chain */

	*chain = sk_X509_new_null();
	if (*chain == NULL) {
		*err = "sk_X509_new_null() failed";
		BIO_free(bio);
		X509_free(x509);
		return NULL;
	}

	for (;; ) {

		temp = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (temp == NULL) {
			n = ERR_peek_last_error();
			if (/*ERR_GET_LIB(n) == ERR_LIB_PEM
				&& */ERR_GET_REASON(n) == PEM_R_NO_START_LINE) {
				/* end of file */
				ERR_clear_error();
				break;
			}

			/* some real error */

			*err = "PEM_read_bio_X509() failed";
			BIO_free(bio);
			X509_free(x509);
			sk_X509_pop_free(*chain, X509_free);
			return NULL;
		}

		if (sk_X509_push(*chain, temp) == 0) {
			*err = "sk_X509_push() failed";
			BIO_free(bio);
			X509_free(x509);
			sk_X509_pop_free(*chain, X509_free);
			return NULL;
		}
	}

	BIO_free(bio);

	return x509;
}
static EVP_PKEY* kgl_ssl_load_certificate_key(const char** err, const kgl_ref_str_t* key, const kgl_array_t* passwords) {
	BIO* bio;
	EVP_PKEY* pkey;
	kgl_str_t* pwd;
	uint32_t        tries;
	pem_password_cb* cb;
	if (strncmp(key->data, "data:", sizeof("data:") - 1) == 0) {
		bio = BIO_new_mem_buf(key->data + sizeof("data:") - 1,
			key->len - (sizeof("data:") - 1));
		if (bio == NULL) {
			*err = "BIO_new_mem_buf() failed";
			return NULL;
		}

	} else {
		bio = BIO_new_file((char*)key->data, "r");
		if (bio == NULL) {
			*err = "BIO_new_file() failed";
			return NULL;
		}
	}

	if (passwords) {
		tries = (uint32_t)passwords->nelts;
		pwd = (kgl_str_t*)passwords->elts;
		cb = kgl_ssl_password_callback;

	} else {
		tries = 1;
		pwd = NULL;
		cb = NULL;
	}

	for (;; ) {

		pkey = PEM_read_bio_PrivateKey(bio, NULL, cb, pwd);
		if (pkey != NULL) {
			break;
		}

		if (tries-- > 1) {
			ERR_clear_error();
			(void)BIO_reset(bio);
			pwd++;
			continue;
		}

		*err = "PEM_read_bio_PrivateKey() failed";
		BIO_free(bio);
		return NULL;
	}

	BIO_free(bio);

	return pkey;
}

int kgl_ssl_certificate(SSL_CTX* ctx, const kgl_ref_str_t* cert, const kgl_ref_str_t* key, const kgl_array_t* passwords) {
	const char* err;
	X509* x509;
	EVP_PKEY* pkey;
	STACK_OF(X509)* chain = NULL;
	if (!cert || *cert->data == '\0') {
		cert = key;
	}
	x509 = kgl_ssl_load_certificate(&err, cert, &chain);
	if (x509 == NULL) {
		if (err != NULL) {
			klog(KLOG_ERR, "cannot load certificate \"%s\": %s", cert->data, err);
		}
		return -1;
	}

	if (SSL_CTX_use_certificate(ctx, x509) == 0) {
		klog(KLOG_ERR, "SSL_CTX_use_certificate(\"%s\") failed", cert->data);
		X509_free(x509);
		sk_X509_pop_free(chain, X509_free);
		return -1;
	}
	/*
	 * Note that x509 is not freed here, but will be instead freed in
	 * ngx_ssl_cleanup_ctx().  This is because we need to preserve all
	 * certificates to be able to iterate all of them through exdata
	 * (ngx_ssl_certificate_index, ngx_ssl_next_certificate_index),
	 * while OpenSSL can free a certificate if it is replaced with another
	 * certificate of the same type.
	 */

#ifdef SSL_CTX_set0_chain
	if (SSL_CTX_set0_chain(ctx, chain) == 0) {
		klog(KLOG_ERR, "SSL_CTX_set0_chain(\"%s\") failed", cert->data);
		sk_X509_pop_free(chain, X509_free);
		return -1;
	}
#else
	{
		int  n;

		/* SSL_CTX_set0_chain() is only available in OpenSSL 1.0.2+ */

		n = sk_X509_num(chain);

		while (n--) {
			x509 = sk_X509_shift(chain);

			if (SSL_CTX_add_extra_chain_cert(ctx, x509) == 0) {
				klog(KLOG_ERR, "SSL_CTX_add_extra_chain_cert(\"%s\") failed", cert->data);
				sk_X509_pop_free(chain, X509_free);
				return -1;
			}
		}

		sk_X509_free(chain);
	}
#endif

	pkey = kgl_ssl_load_certificate_key(&err, key, passwords);
	if (pkey == NULL) {
		if (err != NULL) {
			klog(KLOG_ERR, "cannot load certificate key \"%s\": %s", key->data, err);
		}
		return -1;
	}

	if (SSL_CTX_use_PrivateKey(ctx, pkey) == 0) {
		klog(KLOG_ERR, "SSL_CTX_use_PrivateKey(\"%s\") failed", key->data);
		EVP_PKEY_free(pkey);
		return -1;
	}
	EVP_PKEY_free(pkey);
	return 0;
}


static SSL_CTX* kgl_ssl_ctx_post_init(SSL_CTX* ctx, const char* ca_path, const char* ca_file, void* ssl_ctx_data) {

	if (!SSL_CTX_check_private_key(ctx)) {
		char err_buf[KGL_SSL_ERR_BUF_SIZE];
		ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
		klog(KLOG_ERR, "SSL check_private_key Error: %s\n", err_buf);
		SSL_CTX_free(ctx);
		return NULL;
	}
	if (ca_path != NULL || ca_file != NULL) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		if (SSL_CTX_load_verify_locations(ctx, ca_file, ca_path) <= 0) {
			char err_buf[KGL_SSL_ERR_BUF_SIZE];
			ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
			klog(KLOG_ERR, "SSL error %s:%d: Error allocating handle: %s\n",
				__FILE__, __LINE__, err_buf);
			SSL_CTX_free(ctx);
			return NULL;
		}
	}
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
	if (kgl_ssl_create_sni) {
		if (0 == SSL_CTX_set_tlsext_servername_callback(ctx, kgl_ssl_sni)) {
			fprintf(stderr, "kasync was built with SNI support, however, now it is linked "
				"dynamically to an OpenSSL library which has no tlsext support, "
				"therefore SNI is not available");
		}
	}
	if (ssl_npn && ssl_ctx_data) {
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
		SSL_CTX_set_alpn_select_cb(ctx, kgl_ssl_npn_selected, NULL);
#endif
#if TLSEXT_TYPE_next_proto_neg
		SSL_CTX_set_next_protos_advertised_cb(ctx, kgl_ssl_npn_advertise, NULL);
#endif
	}
	//SSL_CTX_sess_set_cache_size(ctx,1000);
	return ctx;
}
bool kgl_ssl_ctx_load_cert_key(SSL_CTX* ctx, const char* cert_file, const char* key_file) {
	if (cert_file == NULL || *cert_file == '\0') {
		cert_file = key_file;
	}
	if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
		char err_buf[KGL_SSL_ERR_BUF_SIZE];
		ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
		klog(KLOG_ERR,
			"SSL use certificate file [%s]: Error: %s\n",
			cert_file,
			err_buf);
		return false;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
		char err_buf[KGL_SSL_ERR_BUF_SIZE];
		ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
		klog(KLOG_ERR,
			"SSL use privatekey file [%s]: Error: %s\n",
			key_file,
			err_buf);
		return false;
	}
	return kgl_ssl_session_id_context(ctx, cert_file);
}
SSL_CTX* kgl_ssl_ctx_new_server2(const kgl_ref_str_t* cert_buffer, const kgl_ref_str_t* key_buffer, const char* ca_path, const char* ca_file, void* ssl_ctx_data) {
	SSL_CTX* ctx = kgl_ssl_ctx_new(ssl_ctx_data);
	if (ctx == NULL) {
		fprintf(stderr, "cann't init_ctx\n");
		return NULL;
	}
	if (kgl_ssl_certificate(ctx, cert_buffer, key_buffer, NULL) != 0) {
		SSL_CTX_free(ctx);
		return NULL;
	}
	kgl_ssl_session_id_context_from_buffer(ctx, cert_buffer->data);
	return kgl_ssl_ctx_post_init(ctx, ca_path, ca_file, ssl_ctx_data);
}
SSL_CTX* kgl_ssl_ctx_new_server(const char* cert_file, const char* key_file, const char* ca_path, const char* ca_file, void* ssl_ctx_data) {
	SSL_CTX* ctx = kgl_ssl_ctx_new(ssl_ctx_data);
	if (ctx == NULL) {
		fprintf(stderr, "cann't init_ctx\n");
		return NULL;
	}
	if (!kgl_ssl_ctx_load_cert_key(ctx, cert_file, key_file)) {
		SSL_CTX_free(ctx);
		return NULL;
	}
	return kgl_ssl_ctx_post_init(ctx, ca_path, ca_file, ssl_ctx_data);
}
kssl_status kgl_ssl_handshake_status(SSL* ssl, int re) {
	int err = SSL_get_error(ssl, re);
	//printf("ssl=[%p] ssl_get_error=[%d] re=[%d]\n", ssl, err, re);
	switch (err) {
	case SSL_ERROR_WANT_READ:
		return ret_want_read;
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
		return ret_want_write;
	case SSL_ERROR_SYSCALL:
#ifndef _WIN32
		if (errno == EAGAIN) {
			//return ret_error;
		}
#endif
		err = errno;
		//printf("system errno=%d\n",err);
		return ret_error;
	case SSL_ERROR_SSL:
	case SSL_ERROR_ZERO_RETURN:
		//printf("error = %d\n",err);
		return ret_error;
	case SSL_ERROR_WANT_X509_LOOKUP:
		//printf("SSL_ERROR_WANT_X509_LOOKUP\n");
		return ret_sni_resolve;
	default:
		//printf("error = %d\n",err);
		return ret_error;
	}
}
kssl_status kgl_ssl_handshake(SSL* ssl) {
	int re = SSL_do_handshake(ssl);
	if (re <= 0) {
		return kgl_ssl_handshake_status(ssl, re);
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
	if (ssl->s3) {
		ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
	}
#endif
#endif
	return ret_ok;
}
kssl_status kgl_ssl_shutdown(SSL* ssl) {
	int n = SSL_shutdown(ssl);
	if (n == 1) {
		return ret_ok;
	}
	int err = SSL_get_error(ssl, n);
	switch (err) {
	case SSL_ERROR_WANT_READ:
		return ret_want_read;
	case SSL_ERROR_WANT_WRITE:
		return ret_want_write;
	default:
		return ret_error;
	}
}
void kgl_ssl_get_next_proto_negotiated(SSL* ssl, const unsigned char** data, unsigned* len) {
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	SSL_get0_alpn_selected(ssl, data, len);
#ifdef TLSEXT_TYPE_next_proto_neg
	if (*len == 0) {
		SSL_get0_next_proto_negotiated(ssl, data, len);
	}
#endif
#else
#ifdef TLSEXT_TYPE_next_proto_neg
	SSL_get0_next_proto_negotiated(ssl, data, len);
#endif
#endif
}
bool kgl_ssl_ctx_set_cipher_list(SSL_CTX* ctx, const char* cipher) {
	return 1 == SSL_CTX_set_cipher_list(ctx, cipher);
}
void kgl_ssl_ctx_set_protocols(SSL_CTX* ctx, const char* protocols) {
#ifdef SSL_CTX_set_min_proto_version
	SSL_CTX_set_min_proto_version(ctx, 0);
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
#endif
#ifdef TLS1_3_VERSION
	SSL_CTX_set_min_proto_version(ctx, 0);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
#endif
	if (protocols == NULL || *protocols == '\0') {
		return;
	}
	char* buf = strdup(protocols);
	char* hot = buf;
	int mask = 0;
	for (;;) {
		while (*hot && isspace((unsigned char)*hot)) {
			hot++;
		}
		char* p = hot;
		while (*p && !isspace((unsigned char)*p)) {
			p++;
		}
		if (p == hot) {
			break;
		}
		if (*p) {
			*p = '\0';
			p++;
		}
		kgl_string_bitmask_t* h = kgl_ssl_protocols;
		while (h->name.data) {
			if (strcasecmp(h->name.data, hot) == 0) {
				KBIT_SET(mask, h->mask);
			}
			h++;
		}
		if (*p == '\0') {
			break;
		}
		hot = p;
	}
	xfree(buf);
#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
	/* only in 0.9.8m+ */
	SSL_CTX_clear_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
#endif
	if (!(mask & KGL_SSL_SSLv2)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	}
	if (!(mask & KGL_SSL_SSLv3)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
	}
	if (!(mask & KGL_SSL_TLSv1)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
	}
#ifdef SSL_OP_NO_TLSv1_1
	SSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1_1);
	if (!(mask & KGL_SSL_TLSv1_1)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
	}
#endif
#ifdef SSL_OP_NO_TLSv1_2
	SSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1_2);
	if (!(mask & KGL_SSL_TLSv1_2)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
	}
#endif
#ifdef SSL_OP_NO_TLSv1_3
	SSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1_3);
	if (!(mask & KGL_SSL_TLSv1_3)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
	}
#endif
}
#endif
