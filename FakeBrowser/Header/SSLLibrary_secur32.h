#pragma once
#include "stdafx.h"
#define SECURITY_WIN32
#include <schannel.h>
#include <sspi.h>

#include "SSLLibrary.h"

#define TCP_CONNECTION_TIMEOUT 0x0000274c

namespace Behavior {

	class CSecur32SSL : public CSSL
	{
		friend class CChromeSSL;

	public:
		CSecur32SSL();
		~CSecur32SSL();
		static CSecur32SSL* getInstance() { return m_secure32; };
		BOOL Init();
		BOOL Handshake(BOOL& isHttp2,BOOL useALPN=FALSE);
		BOOL DeInit();

		BOOL Encrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen, DWORD type);
		BOOL Decrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen);
		
		static CSecur32SSL* m_secure32;

	protected:
		static BOOL InitLibrary();
		static SECURITY_STATUS	CreateCredentials(PCredHandle phCreds, PCCERT_CONTEXT pCertContext = NULL);
		static int EncryptData(PCtxtHandle hContext, BYTE *src, DWORD size, BYTE *dest, DWORD destSize, DWORD *cb);
		static int DecryptData(PCtxtHandle hContext, BYTE *src, DWORD size, BYTE *dest, DWORD destSize, DWORD *cb);

	private:
		static HMODULE m_hModule;
		static SecurityFunctionTable m_pfnTable;
		static HMODULE m_nssHModule;

		CredHandle m_hClientCred;
		CredHandle m_hServerCred;
		CtxtHandle m_hClientCtx;
		CtxtHandle m_hServerCtx;

		BYTE *pClientToServerBuffer;
		DWORD cbClientToServerBuffer;	
	};
}