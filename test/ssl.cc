#include "gtest/gtest.h"
#include "kselector_manager.h"

TEST(ssl, server_ssl) {
	SSL_CTX* ssl_ctx = kgl_ssl_ctx_new_server_from_memory(
		"-----BEGIN CERTIFICATE-----\n\
MIIDETCCAfkCFGqw5HR92Ds5slo2Pfq8z3Bxdo1iMA0GCSqGSIb3DQEBCwUAMEUx\n\
CzAJBgNVBAYTAkNOMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n\
cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjIwMjIyMDMyMDM4WhcNMjMwMjIyMDMy\n\
MDM4WjBFMQswCQYDVQQGEwJDTjETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\n\
CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\n\
AQ8AMIIBCgKCAQEA4fPjieRPLf83Hgevm8x39KmfuJ5eVH/r5lPw9uBBC8VOdeqI\n\
Qdq96Cmi9VHdKvDxpEYoeQ5fkLqQzX/DKOWOPHpj+Wgp5C7c81fEHlSvMhKlQUbE\n\
7XkonEsBkdtJ6FrLufTsagfJ6BTTGgp8vRn6JpGEPecC7OLL/DTQsJxwdgmVdpXr\n\
wjGHC6LgoVUOfrASCTg4rZJDHKiKjfZtRa4N5iGUjFR3hEnTftpnubZAQi0tzaCE\n\
g6M0sga80tAAegdRhs+j4WKrm1lCipjNIi+klwbTlLeMENjrI3nvrwsfafzLP44v\n\
UYYgnwW7xlyG8AyveTYueoAvItVDyFpKMt1JlQIDAQABMA0GCSqGSIb3DQEBCwUA\n\
A4IBAQApjHj3b8SzeOOLdaJX0i6T/A3MN74HH7x3fMZMCrpmwWjTLq8KoKimyZgh\n\
XzPiaBVra2SVZE63RgWE3wkLOp84K0WF/cKVS5+ebaZ52aqy6ODVAsx14rjhlIRQ\n\
BgX7FBXWVJN/5DHru5sgsAA4UQLKF9/zh6IlWgtH5qJ3K6jx8JY90R9QMX1gJnJX\n\
ppspxmzNu2IPbg7wui6LAg0ETslp4ablsbeP8ew9lKQCR3ZbCunpiyn8FbGl8pAY\n\
lf+S1EJI0uY6kqmt3zmRTpv5ysIm7NLdcPdUYIquK0ceOr69LGni80g5r6vsGAWC\n\
ze3XUTzbzWM1/+07065mw7bYgl/U\n\
-----END CERTIFICATE-----",
"-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpgIBAAKCAQEA4fPjieRPLf83Hgevm8x39KmfuJ5eVH/r5lPw9uBBC8VOdeqI\n\
Qdq96Cmi9VHdKvDxpEYoeQ5fkLqQzX/DKOWOPHpj+Wgp5C7c81fEHlSvMhKlQUbE\n\
7XkonEsBkdtJ6FrLufTsagfJ6BTTGgp8vRn6JpGEPecC7OLL/DTQsJxwdgmVdpXr\n\
wjGHC6LgoVUOfrASCTg4rZJDHKiKjfZtRa4N5iGUjFR3hEnTftpnubZAQi0tzaCE\n\
g6M0sga80tAAegdRhs+j4WKrm1lCipjNIi+klwbTlLeMENjrI3nvrwsfafzLP44v\n\
UYYgnwW7xlyG8AyveTYueoAvItVDyFpKMt1JlQIDAQABAoIBAQCtqGVruFYGkw0I\n\
fn3AL0DOgIOqP8VeCkcC6ebbxvUXF9i6lbuNaZHlWgLNqtJhy3bce7Nlft+B+3GJ\n\
DzWuO+e6oZIuwJjZsA7O09h+OzW/NUdfSQXXQfQtUxRsxm4iL44+aHg+8aeDQGYS\n\
sJa4O7vfYp2Reffsmk6OkwUFh+aDQF6bWo0Dop6Ov1F3I/Q4/4BSMwGULf4TlvRC\n\
CebwlS9icjbM9sdZ+/+iywMupatbpjQ2iKohJvBYrapK0Kg1t+HyNBZo7rmbCku1\n\
+8lbfpkaNWAsdpHL0LoYcgIIPar2/BbPjED0BYsA70wj7LbT3JRqvWLJO1rMad5r\n\
gvXeclCtAoGBAPZWU/2RkDI3pTtbsr9DNhJq1ZuzvgWr/MHCyKv8eUn4Bq8vwjZr\n\
GzyLfijUnO887at/UM7m2rkG89FS4cMxT2RdXqriQfauKR1FRDeOrSLrYtx/260y\n\
H4Ry1sDNJ7DrQb118ooC3ppi4mg2tT+McUj/+KKvTRM2CGd51On0w+ufAoGBAOrQ\n\
3PcB09CUbgdPmUF4HLFIpaHNpi5gs6Hq8DtImxIr/dPytdHo7+yprmYxyMYzZ4d8\n\
fdMXgS7wmOUAeiztO6/GbdqdBQ4lUIRp5C2cx82iZek80uTCOA1b97pa1oVjasbm\n\
FwaW/bANHP5FTre8ENMiuOAIbDC9LdHyWRxQIX5LAoGBAIyS0RVXtvjhRlpsRsHc\n\
wgOakdFrrhmgfvm3hTqYNkLe1jmswGC7mGxhkhoM0o23sE14tw2LMe/6prKiYJE6\n\
F3tHyRktSsVRt8arW3V05xqRRvZbxGm+u7uiqSiXKnpMllRe9YyKfKuPmHIuHhpo\n\
s9EbubBk50/6OquKG9Vyx0czAoGBAIU0EHUKk1a6LKR3EhAii9xBwrvDxiZ+8sfC\n\
V565tEYdsHLgNyYphpjxNJ6CVUuh83PXOiVaKw0urP0TRTthJD+1R7IA6tI4drF2\n\
xFrfmjRbkIY728KrLlLdvez4BMNMP1EvSxaQ5r5M4gqX1GzEAaNUCh4EiSMo3epA\n\
GS7Hggh7AoGBALFfnYEL0BtqGL9Sm7pLk1smtQ5F1T4mR3VsPnBZED1+513b/54V\n\
mBktbUKiCi0n5NrLYQFnSLMAmGtn8stH+rSmB9pvk/YlSXbtRhmoeltO+WOx8i+4\n\
7raWgb152Nm97jiGKEb/AmEPj13m7Inu0XLfWdQI4ScpRNVeNqclzVhT\n\
-----END RSA PRIVATE KEY-----", NULL, NULL, NULL);
	ASSERT_FALSE(ssl_ctx == NULL);
	kserver* server = kserver_init();
	kgl_ssl_ctx* ctx2 = kgl_new_ssl_ctx(ssl_ctx);
	kgl_add_ref_ssl_ctx(ctx2);
	ASSERT_TRUE(kserver_open(server, "127.0.0.1", 0, 0, ctx2));//ipv4
	uint16_t port = ksocket_addr_port(&server->addr);
	ASSERT_TRUE(kserver_open(kserver_init(), "::1", 0, 0, ctx2)); //ipv6
}