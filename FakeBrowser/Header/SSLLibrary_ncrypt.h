#pragma once
#include "stdafx.h"
#include <sslprovider.h>
#include "SSLLibrary.h"

namespace Behavior
{
	typedef __checkReturn SECURITY_STATUS(WINAPI *NCryptOpenStorageProviderFn)(
		__out   NCRYPT_PROV_HANDLE *phProvider,
		__in_opt LPCWSTR pszProviderName,
		__in    DWORD   dwFlags);

	typedef __checkReturn SECURITY_STATUS(WINAPI* NCryptImportKeyFn)(
		__in    NCRYPT_PROV_HANDLE hProvider,
		__in_opt NCRYPT_KEY_HANDLE hImportKey,
		__in    LPCWSTR pszBlobType,
		__in_opt NCryptBufferDesc *pParameterList,
		__out   NCRYPT_KEY_HANDLE *phKey,
		__in_bcount(cbData) PBYTE pbData,
		__in    DWORD   cbData,
		__in    DWORD   dwFlags);

	class CNcryptSSL : public CSSL
	{
	public:
		CNcryptSSL();
		~CNcryptSSL();
		BOOL Init();
		BOOL Handshake(BOOL& isHttp2, BOOL useALPN = FALSE);
		BOOL DeInit();

		BOOL Encrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen, DWORD type);
		BOOL Decrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen);

	private:
		static HMODULE m_hModule;
		static NCRYPT_SSL_FUNCTION_TABLE *m_pfnTable;
		static NCryptOpenStorageProviderFn m_pfnNCryptOpenStorageProvider;
		static NCryptImportKeyFn m_pfnNCryptImportKey;

		NCRYPT_PROV_HANDLE m_hSslProvider = NULL;
		NCRYPT_PROV_HANDLE m_hServerContext = NULL;
		NCRYPT_PROV_HANDLE m_hClientContext = NULL;
		NCRYPT_PROV_HANDLE m_hServerPrivateKey = NULL;
		NCRYPT_PROV_HANDLE m_hServerPublicKey = NULL;

		NCRYPT_PROV_HANDLE m_hServerMasterKey = NULL;
		NCRYPT_PROV_HANDLE m_hClientMasterKey = NULL;

		NCRYPT_PROV_HANDLE m_hClientWriteKey = NULL;
		NCRYPT_PROV_HANDLE m_hClientReadKey = NULL;
		NCRYPT_PROV_HANDLE m_hServerWriteKey = NULL;
		NCRYPT_PROV_HANDLE m_hServerReadKey = NULL;

		BYTE *m_preMasterKey = nullptr;
		NCRYPT_SSL_CIPHER_SUITE m_CipherSuiteInfo;
		DWORD m_SndCount = 0;
		DWORD m_RcvCount = 0;
	};
}
