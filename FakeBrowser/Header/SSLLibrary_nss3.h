#pragma once
#include "stdafx.h"

#include <string>

namespace Behavior {

#define SSL_SECURITY 1  
#define SSL_HANDSHAKE_AS_CLIENT 5
#define SSL_HANDSHAKE_AS_SERVER 6

#define PR_INTERVAL_MIN 1000UL
#define PR_INTERVAL_MAX 100000UL
#define PR_INTERVAL_NO_WAIT 0UL
#define PR_INTERVAL_NO_TIMEOUT 0xffffffffUL

	/*typedef int32_t(*PR_Write)(VOID *fd, void *buf, int32_t amount);
	typedef int32_t(*PR_Read)(VOID *fd, void *buf, int32_t amount);*/

	struct PRIOMethods {
		VOID* file_type;
		VOID* close;
		VOID* read;
		VOID* write;
		VOID* available;
		VOID* available64;
		VOID* fsync;
		VOID* seek;
		VOID* seek64;
		VOID* fileInfo;
		VOID* fileInfo64;
		VOID* writev;
		VOID* connect;
		VOID* accept;
		VOID* bind;
		VOID* listen;
		VOID* shutdown;
		VOID* recv;
		VOID* send;
		VOID* recvfrom;
		VOID* sendto;
		VOID* poll;
		VOID* acceptread;
		VOID* transmitfile;
		VOID* getsockname;
		VOID* getpeername;
		VOID* getsockopt;
		VOID* setsockopt;
	};

	typedef struct PRIOMethods PRIOMethods;

	typedef struct _PRFileDesc
	{
		PRIOMethods *methods;
		VOID *secret;
		VOID *lower;
		VOID *higher;
		VOID *fd;
		ULONG identity;
	} PRFileDesc;

	union PRNetAddr {
		struct {
			uint16_t family;
			char data[14];
		} raw;
		struct {
			uint16_t family;
			uint16_t port;
			uint32_t ip;
			char pad[8];
		} inet;
	};

	typedef union PRNetAddr PRNetAddr;

	typedef struct _FakePRIOMethods
	{
		PVOID file_type;
		PVOID close;
		PVOID read;
		PVOID write;
	}FakePRIOMethods;

	typedef int(*SSLAuthCertificate) (
		void *arg,
		PRFileDesc *fd,
		BOOL checksig,
		BOOL isServer);

	typedef struct PRHostEnt {
		char *h_name;
		char **h_aliases;
#if defined(_WIN32)
		uint16_t h_addrtype;
		uint16_t h_length;
#else
		uint32_t h_addrtype;
		uint32_t h_length;
#endif
		char **h_addr_list;
	} PRHostEnt;

	typedef uint32_t PRIntervalTime;
	typedef int PRIntn;

	typedef void(__cdecl *PR_InitT)(int type, int priority, int maxPTDs);
	typedef ULONG(__cdecl *NSS_NoDB_InitT)(char *reserved);
	typedef int(__cdecl *PR_CreatePipeT)(PRFileDesc **, PRFileDesc**);
	typedef ULONG(__cdecl *PR_GetUniqueIdentityT)(const char *layer_name);
	typedef char *(__cdecl *PR_GetNameForIdentityT)(ULONG ident);
	typedef int(__cdecl *PR_ReadT)(PRFileDesc *, void *buf, int amount);
	typedef int(__cdecl *PR_WriteT)(PRFileDesc *, void *buf, int amount);
	typedef int(__cdecl *PR_GetErrorT)(void);
	typedef int(__cdecl *PR_CloseT)(PRFileDesc *fd);

	typedef PRFileDesc* (__cdecl *PR_AllocFileDescT)(PVOID osfd, const VOID *methods);
	typedef PRFileDesc* (__cdecl *SSL_ImportFDT)(PRFileDesc *model, PRFileDesc *fd);
	typedef PRFileDesc* (__cdecl *PR_NewTCPSocketT)(void);
	typedef ULONG(__cdecl *PR_GetHostByNameT)(const char *hostname, char *buf, PRIntn bufsize, PRHostEnt *hostentry);
	typedef PRIntn(__cdecl *PR_EnumerateHostEntT)(PRIntn enumIndex, const PRHostEnt *hostEnt, uint16_t port, PRNetAddr *address);
	typedef ULONG(__cdecl *PR_ConnectT)(PRFileDesc *fd, PRNetAddr *addr, PRIntervalTime timeout);
	typedef ULONG(__cdecl *SSL_ForceHandshakeT)(PRFileDesc *fd);
	typedef ULONG(__cdecl *SSL_ResetHandshakeT)(PRFileDesc *fd, BOOL asServer);
	typedef ULONG(__cdecl *SSL_OptionSetT)(PRFileDesc *fd, uint32_t option, BOOL on);
	typedef ULONG(__cdecl *SSL_SetURLT)(PRFileDesc *fd, const char *url);
	typedef ULONG(__cdecl *NSS_SetDomesticPolicyT)(void);
	typedef ULONG(__cdecl *SSL_CipherPrefSetDefaultT)(uint32_t cipher, BOOL enabled);
	typedef ULONG(__cdecl *SSL_AuthCertificateHookT)(PRFileDesc *fd, SSLAuthCertificate f, void *arg);


	typedef struct _NSS3FunctionInterface
	{
		PR_CreatePipeT fpnPR_CreatePipe;
		PR_GetUniqueIdentityT pfnPR_GetUniqueIdentity;
		PR_GetNameForIdentityT pfnPR_GetNameForIdentity;
		PR_ReadT pfnPR_Read;
		PR_WriteT pfnPR_Write;
		PR_GetErrorT pfnPR_GetError;
		PR_CloseT pfnPR_Close;
		PR_AllocFileDescT pfnPR_AllocFileDesc;
		PR_NewTCPSocketT pfnPR_NewTCPSocket;
		SSL_ImportFDT pfnSSL_ImportFD;
		PR_GetHostByNameT pfnPR_GetHostByName;
		PR_EnumerateHostEntT pfnPR_EnumerateHostEnt;
		PR_ConnectT pfnPR_Connect;
		SSL_ForceHandshakeT pfnSSL_ForceHandshake;
		SSL_ResetHandshakeT pfnSSL_ResetHandshake;
		SSL_OptionSetT pfnSSL_OptionSet;
		SSL_SetURLT pfnSSL_SetURL;
		NSS_SetDomesticPolicyT pfnNSS_SetDomesticPolicy;
		SSL_CipherPrefSetDefaultT pfnSSL_CipherPrefSetDefault;
		PR_InitT pfnPR_Init;
		NSS_NoDB_InitT pfnNSS_NoDB_Init;
		SSL_AuthCertificateHookT pfnSSL_AuthCertificateHook;
	}NSS3FunctionInterface;

	class CNSS3SSL
	{
	public:
		CNSS3SSL();
		~CNSS3SSL();
		BOOL Init();
		BOOL Handshake();
		BOOL ReceiveAndDecrypt(BYTE* &response, size_t &recSize);
		BOOL DeInit();
		BOOL Encrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen, DWORD msgCount, DWORD type) { return FALSE; }
		BOOL Decrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen, DWORD msgCount) { return FALSE; }
		BOOL get(std::string url, BYTE* &response, size_t &recSize);
	private:
		static HMODULE m_hModule;
		static NSS3FunctionInterface m_pfnTable;
		std::string m_hostName = "";
		std::string m_url = "";
		std::string m_path = "";
		std::string m_port = "";
		std::string m_protocol = "";
		BOOL Connect();
		BOOL InitLibrary();

		PRFileDesc *m_SSLSocket = nullptr;
	};
}
