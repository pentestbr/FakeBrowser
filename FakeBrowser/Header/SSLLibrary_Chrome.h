#pragma once
#include "stdafx.h"

#include "SSLLibrary.h"
#include "SSLLibrary_nss3.h"

namespace Behavior
{
#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#define TCP_CONNECTION_TIMEOUT 0x0000274c

	typedef HANDLE SSL_METHOD;
	typedef VOID SSL_CTX;
	typedef char* SSL;
	typedef VOID BIO;

	enum tls13_variant_t {
		tls13_default = 0,
		tls13_experiment = 1,
		tls13_experiment2 = 2,
		tls13_experiment3 = 3,
		tls13_draft21 = 4,
	};

//#pragma pack(push, 3)
//	//Refer windbg attached to chrome.dll(61.0.3163.100 x64) only for chrome 61.0.3163.100
//	struct SSLConnection {
//		void *method;
//		uint16_t version;
//		uint16_t conf_max_version;
//		uint16_t conf_min_version;
//		enum tls13_variant_t tls13_variant;
//		uint16_t max_send_fragment;
//		void *rbio;
//		void *wbio;
//		void* do_handshake;
//		void* init_buf;
//		void* init_msg;
//		uint32_t init_num;
//		void *s3;
//		void *d1;
//		void *msg_callback;
//		void *msg_callback_arg;
//		void *param;
//		void *cipher_list;
//		void *cert;
//		int rwstate;
//		unsigned initial_timeout_duration_ms;
//		void *session;
//		void *verify_callback;
//		void *custom_verify_callback;
//		void *info_callback;
//		char *psk_identity_hint;
//		void *psk_client_callback;
//		void *psk_server_callback;
//		void *ctx;
//		void *ex_data;
//		void *client_CA;
//		void *cached_x509_client_CA;
//		uint32_t options;
//		uint32_t mode;
//		uint32_t max_cert_list;
//		char *tlsext_hostname;
//		size_t supported_group_list_len;
//		uint16_t *supported_group_list;
//		void *session_ctx;
//		void *srtp_profiles;
//		void *srtp_profile;
//		void *tlsext_channel_id_private;
//		uint8_t *alpn_client_proto_list;
//		unsigned alpn_client_proto_list_len;
//	};
//#pragma pack(pop)
//
//	struct ssl_st : public SSLConnection {};
//
//	typedef struct ssl_st SSL;

	typedef struct bio_method_st {
		int type;
		const char *name;
		int(__cdecl *bwrite)(BIO *, const char *, int);
		int(__cdecl *bread)(BIO *, char *, int);
		int(__cdecl *bputs)(BIO *, const char *);
		int(__cdecl *bgets)(BIO *, const char *);
		long(__cdecl *bctrl)(BIO *, int, long, void *);
		int(__cdecl *create)(BIO *);
		int(__cdecl *destroy)(BIO *);
		long(__cdecl *callback_ctrl)(BIO *, int, PVOID);
	}BIO_METHOD;

	typedef struct buffer_ctx
	{
		BYTE *Buffer;
		DWORD BufferSize;
		DWORD DataSize;
		DWORD DataOffset;
	}BUFFER_CTX;

	typedef struct my_bio_ctx
	{
		BUFFER_CTX *ReadBuffer;
		BUFFER_CTX *WriteBuffer;
		PVOID Pair;
	}MY_BIO_CTX;

	typedef enum ssl_verify_result_t
	{
		ssl_verify_ok,
		ssl_verify_invalid,
		ssl_verify_retry
	}ssl_verify_result;

	typedef void(*SSL_library_initT)(void);
	typedef SSL_METHOD(*TLS_protocol_methodT)(void);
	typedef SSL_METHOD(*SSLv23_client_methodT)(void);
	typedef int(__cdecl *SSL_set_connect_stateT)(SSL *);
	typedef int(*SSL_do_handshakeT)(SSL *);
	typedef int(__fastcall *SSL_do_handshake54T)(SSL *);
	typedef int(__cdecl *SSL_writeT)(SSL *, BYTE *, DWORD);
	typedef int(__cdecl *SSL_readT)(SSL *, BYTE *, DWORD);
	typedef int(__cdecl *SSL3_write_app_dataT)(SSL *, BYTE *, DWORD);
	typedef int(__cdecl *SSL3_write_app_data61T)(SSL *,int *, BYTE *, DWORD);
	typedef int(__cdecl *SSL3_read_app_dataT)(SSL *, BYTE *, DWORD, DWORD);
	typedef int(__cdecl *SSL3_read_app_data54T)(SSL *, INT *, BYTE *, DWORD, DWORD);
	typedef  SSL_CTX*  (__cdecl *SSL_CTX_NEWT)(SSL_METHOD);
	typedef  SSL_CTX*  (__fastcall *SSL_CTX_NEW54T)(SSL_METHOD);
	typedef  SSL*  (__cdecl *SSL_newT)(SSL_CTX *);
	typedef  SSL*  (__fastcall *SSL_new54T)(SSL_CTX *);
	typedef int(__fastcall *SSL_free54T)(SSL *);
	typedef BOOL(__cdecl *SSL_set_fdT)(SSL*, PVOID);
	typedef void(__cdecl *BIO_set_callbackT)(BIO *, PVOID);
	typedef void(__cdecl *SSL_set_bioT)(SSL *, BIO *, BIO *);
	typedef void(__cdecl *SSL_set0_rbio)(SSL *, BIO *);
	typedef void(__cdecl *SSL_set0_wbio)(SSL *, BIO *);
	typedef int(__cdecl *SSL_get_errorT)(const SSL *ssl, int ret);
	typedef int(__fastcall *SSL_get_error54T)(const SSL *ssl, int ret);
	typedef unsigned int(__cdecl *ERR_get_errorT)(void);
	typedef unsigned int(__cdecl *get_error_valuesT)(int, int, const char **, int *, const char **, int *);

	typedef BIO* (__cdecl *BIO_newT)(PVOID);
	typedef BIO* (__fastcall *BIO_new54T)(PVOID);
	typedef int(__cdecl *BIO_readT)(BIO *b, void *buf, int len);
	typedef int(__cdecl *BIO_writeT)(BIO *b, void *buf, int len);
	typedef int(__cdecl *bio_make_pairT)(BIO*, BIO*, DWORD, BYTE *, DWORD, BYTE*);
	typedef int(__fastcall *bio_make_pair54T)(BIO*, BIO*, DWORD, BYTE *, DWORD, BYTE*);
	typedef int(__cdecl *BIO_new_bio_pairT)(BIO **, size_t, BIO **, size_t);
	typedef int(__cdecl *bio_ioT)(BIO *, void *buf, int len, size_t method_offset, int callback_flags, size_t *num);
	typedef void(__fastcall *CRYPTO_refcount_incT)(DWORD *count);

	typedef ssl_verify_result (__cdecl *custom_verify_callbackT)(SSL *ssl, BYTE *out_alert);

#define SSL_BAD_WRITE	0

#define SSL_ERROR_NONE 0
#define SSL_ERROR_SSL 1
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3

#define ERR_GET_LIB(packed_error) ((int)(((packed_error) >> 24 ) & 0xff))
#define	ERR_GET_REASON(packed_error) ((int)((packed_error) & 0xfff))

#define SSL_ERR_LIBRARY	(16)
#define SSL_R_SSL_HANDSHAKE_FAILURE	(215)
#define CT_HANDSHAKE 22
#define CT_APPLICATIONDATA 23
#define ALPN_HTTP_1_1_LENGTH 8
#define ALPN_HTTP_1_1 "http/1.1"	
#define OPENSSL_MALLOC_PREFIX 8
#define BIO_BUFFER_SIZE 20000
#define SSL_VERIFY_PEER 0x01

	typedef struct _ChromeFunctionInterface
	{
		//SSL
		SSL_library_initT SSL_library_init;
		//PVOID TLS_protocol_method;
		SSLv23_client_methodT SSLv23_client_method;
		union
		{
			SSL_CTX_NEWT SSL_CTX_NEW;
			SSL_CTX_NEW54T SSL_CTX_NEW54;
		};
		union
		{
			SSL_newT SSL_new;
			SSL_new54T SSL_new54;
		};
		SSL_set_bioT SSL_set_bio;

		union
		{
			SSL_do_handshakeT SSL_do_handshake;
			SSL_do_handshake54T SSL_do_handshake54;
		};

		union
		{
			SSL_get_errorT SSL_get_error;
			SSL_get_error54T SSL_get_error54;
		};
		ERR_get_errorT ERR_get_error;
		SSL_set_connect_stateT SSL_set_connect_state;
		SSL_writeT SSL_write;
		SSL_readT SSL_read;

		//chrome53
		SSL3_write_app_dataT ssl3_write_app_data;
		SSL3_read_app_dataT ssl3_read_app_data;
		get_error_valuesT get_error_values;

		//chrome54
		SSL3_read_app_data54T ssl3_read_app_data54;

		//chrome61
		SSL3_write_app_data61T ssl3_write_app_data61;

		//bio
		union
		{
			BIO_newT BIO_new;
			BIO_new54T BIO_new54;
		};
		BIO_readT BIO_read;
		BIO_writeT BIO_write;

		union
		{
			bio_make_pairT bio_make_pair;
			bio_make_pair54T bio_make_pair54;
		};

		BIO_new_bio_pairT BIO_new_bio_pair;

		//not-function
		PVOID biop_table;

		//chrome 53 table
		PVOID SSLv23_client_method_offset;
		PVOID ssl3_connect;

		//chrome 56 x64
		SSL_free54T SSL_free54;
		bio_ioT bio_io;
		CRYPTO_refcount_incT CRYPTO_refcount_inc;

	}ChromeFunctionInterface;

	typedef struct _ChromeOffsetTable
	{
		DWORD ssl_server_offset;
		DWORD ssl_server_bitfield;
		DWORD ssl_state_offset;
		DWORD ssl_state_value;
		DWORD ssl_handshake_func_offset;

		//chrome 56
		DWORD ssl_wbio_offset;
		DWORD ssl_rbio_offset;

		DWORD bio_init_offset;
		DWORD bio_flags_offset;
		DWORD bio_reference_offset;
		DWORD bio_ptr_offset;

		//chrome 59
		DWORD ssl_i_promise_to_verify_certs_after_the_handshake_offset;
		DWORD ssl_i_promise_to_verify_certs_after_the_handshake_bitfield;

		//chrome61
		DWORD ssl_verify_mode_offset;
		DWORD ssl_custom_verify_callback_offset;
	}ChromeOffsetTable;

#define BIO_BUFFER_SIZE 20000

	class CChromeSSL : public CSSL
	{
		friend int PR_Write(void *fd, void *buf, int amount);
		friend int PR_Read(void *fd, void *buf, int amount);

	public:
		static int m_BIOWrapperDebug;

		CChromeSSL(BOOL isFirefox = FALSE);
		~CChromeSSL();
		BOOL Init();
		BOOL Handshake(BOOL& isHttp2, BOOL useALPN = FALSE);
		BOOL DeInit();

		BOOL Encrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen, DWORD type);
		BOOL Decrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen);
		DWORD SetOpenSSLMode(BOOL enable) { m_OpenSSLMode = enable; }

		static CChromeSSL* getInstance() { return m_chrome; };
		static CChromeSSL* m_chrome;

	protected:
		// Chrome SSL API wrapper
		static SSL_CTX* SSL_CTX_NEW(SSL_METHOD);
		static SSL* SSL_new(SSL_CTX *);
		static BIO* BIO_new(PVOID bio_method_st);
		static int bio_make_pair(BIO*, BIO*, DWORD, BYTE *, DWORD, BYTE*);
		static void SSL_set_bio(SSL *, BIO *, BIO *);
		static int SSL_do_handshake(SSL *);
		static int SSL_get_error(const SSL *ssl, int ret);
		static int SSL_write(SSL *, BYTE *, DWORD);
		static int SSL_read(SSL *, BYTE *, DWORD);
		static void SSL_free(SSL *);
		static int BIO_read(BIO *b, void *buf, int len);
		static int BIO_write(BIO *b, void *buf, int len);
		static unsigned int ERR_get_error(void);
		static int my_BIO_new_bio_pair(BIO **pbio1, BIO **pbio2, DWORD Buffer1Size, BYTE *Buffer1, DWORD Buffer2Size, BYTE *Buffer2);
		static void SSL_CTX_i_promise_to_verify_certs_after_the_handshake(SSL_CTX *ctx);
		//Refer from Chrome source code https://cs.chromium.org/chromium/src/third_party/boringssl/src/ssl/ssl_lib.cc?type=cs&q=SSL_set_alpn_protos&sq=package:chromium&l=2028
		static int SSL_set_alpn_protos(SSL *ssl, const uint8_t *protos, unsigned protos_len);
		static void OPENSSL_free(void *orig_ptr);
		//chrome 61
		static void SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode, custom_verify_callbackT callback);

		// BIO method
		static int __cdecl BIOWriteWrapper(BIO *, const char *, int);
		static int __cdecl BIOReadWrapper(BIO *, char *, int);
		static long __cdecl BIOCtrlWrapper(BIO *, int cmd, long larg, void *parg);

	private:
		static SSL_METHOD SSLv23_client_method(void);
		static VOID SSL_set_connect_state(SSL *);
		static HMODULE m_hModule;
		static HMODULE m_hModule2;
		static HMODULE m_nssHModule;
		static DWORD ChromeMajorVersion;
		static ChromeFunctionInterface m_pfnTable;
		static ChromeOffsetTable m_offsetTable;
		static const BIO_METHOD kBIOMethod;
		static NSS3FunctionInterface m_nssPfnTable;
		static uint8_t** ptr_alpn_client_proto_list;

		BOOL LoadOffsetTable();
		BOOL LoadOpenSSL();

		SSL * m_SslClient;
		BYTE *m_pIoBuffer1;
		BYTE *m_pIoBuffer2;

		BIO *bio1, *bio2;

		BYTE *pClientToServerBuffer;
		DWORD cbClientToServerBuffer;

		BOOL m_OpenSSLMode;
		BOOL m_isFirefox;

		PRFileDesc* m_NSSSocket = nullptr;
		BYTE* m_response = nullptr;
		int m_recSize = 0;
	};
}