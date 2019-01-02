#include "stdafx.h"

#include "SSLLibrary_Chrome.h"
#include "Utility.h"

namespace Behavior
{
	int PR_Write(void *fd, void *buf, int amount)
	{
		//printf("\nPR_Write\n");
		return 0;
	};

	int PR_Read(void *fd, void *buf, int amount)
	{
		//printf("\nPR_Read\n");
		CChromeSSL* m_chrome = CChromeSSL::getInstance();
		memcpy(buf, m_chrome->m_response, m_chrome->m_recSize);
		return m_chrome->m_recSize;
	};

	HMODULE CChromeSSL::m_nssHModule = NULL;
	NSS3FunctionInterface CChromeSSL::m_nssPfnTable = { NULL };
	CChromeSSL* CChromeSSL::m_chrome = nullptr;

	static VOID PrintSSLErrorMessage(_TCHAR *funcName, int retcode, int ssl_error_code, int err_code)
	{
		_TCHAR *pwszRetCodeDesc = NULL;
		_TCHAR *pwszSSLErrorCodeDesc = NULL;
		_TCHAR *pwszErrLibDesc = NULL;
		_TCHAR *pwszErrReasonDesc = NULL;

		switch (retcode)
		{
		case SSL_BAD_WRITE:
			pwszRetCodeDesc = _T("SSL_BAD_WRITE");
			break;
		}

		switch (ssl_error_code)
		{
		case SSL_ERROR_SSL:
			pwszSSLErrorCodeDesc = _T("SSL_ERROR_SSL");
			break;
		}

		switch (ERR_GET_LIB(err_code))
		{
		case SSL_ERR_LIBRARY:
			pwszErrLibDesc = _T("SSL_ERR_LIBRARY");
			break;
		}

		switch (ERR_GET_REASON(err_code))
		{
		case SSL_R_SSL_HANDSHAKE_FAILURE:
			pwszErrReasonDesc = _T("SSL_R_SSL_HANDSHAKE_FAILURE");
			break;
		}

		_tprintf(_T("%s failed"), funcName);
		if (pwszRetCodeDesc)
			_tprintf(_T(", ret = %s"), pwszRetCodeDesc);
		else
			_tprintf(_T(", ret = %d"), retcode);

		if (pwszSSLErrorCodeDesc)
			_tprintf(_T(", SSL Error = %s"), pwszSSLErrorCodeDesc);
		else
			_tprintf(_T(", SSL Error = %d"), ssl_error_code);

		if (pwszErrLibDesc)
			_tprintf(_T(", Error Lib = %s"), pwszErrLibDesc);
		else
			_tprintf(_T(", Error Lib = %d"), ERR_GET_LIB(err_code));

		if (pwszErrReasonDesc)
			_tprintf(_T(", Reason = %s"), pwszErrReasonDesc);
		else
			_tprintf(_T(", Reason = %d"), ERR_GET_REASON(err_code));

		_tprintf(_T("\n"));
	}

	CChromeSSL::CChromeSSL(BOOL isFirefox):m_isFirefox(isFirefox)
	{
		cbClientToServerBuffer = 4096;
		pClientToServerBuffer = new BYTE[cbClientToServerBuffer];

		m_pIoBuffer1 = new BYTE[BIO_BUFFER_SIZE];
		m_pIoBuffer2 = new BYTE[BIO_BUFFER_SIZE];
		m_OpenSSLMode = FALSE;
		CChromeSSL::m_chrome = this;
	}

	CChromeSSL::~CChromeSSL()
	{
		DeInit();
	}

	BOOL CChromeSSL::Init()
	{
		SECURITY_STATUS ss;
		BOOL bRet = TRUE;

		if (m_hModule == NULL)
		{
			if (m_OpenSSLMode)
			{
				m_hModule = LoadLibrary(_T("Ssleay32.dll"));
				m_hModule2 = LoadLibrary(_T("libeay32.dll"));
			}
			else
			{
				m_hModule = LoadLibrary(_T("Chrome.dll"));
			}
			if (m_hModule == NULL) {
				printf("Init failed: Cannot find Chrome.dll");
				return FALSE;
			}
			if (m_OpenSSLMode)
			{
				bRet = LoadOpenSSL();
			}
			else
			{
				bRet = LoadOffsetTable();
			}

			if (!bRet)
			{
				FreeLibrary(m_hModule);
				m_hModule = NULL;
				printf("Init failed: LoadOffsetTable() failed");
				return FALSE;
			}
		}

		if (m_pfnTable.SSL_library_init == NULL)
		{
			_tprintf(_T("SSL_library_init is NULL\n"));
			return FALSE;
		}

		if (m_isFirefox) {
			if (m_nssHModule == NULL)
			{
				m_nssHModule = LoadLibrary(_T("NSS3.DLL"));
				if (m_nssHModule == NULL) {
					printf("Init failed: Cannot find NSS3.DLL");
					return FALSE;
				}
				m_nssPfnTable.pfnPR_GetUniqueIdentity = (PR_GetUniqueIdentityT)GetProcAddress(m_nssHModule, "PR_GetUniqueIdentity");
				m_nssPfnTable.pfnPR_Read = (PR_ReadT)GetProcAddress(m_nssHModule, "PR_Read");
				m_nssPfnTable.pfnPR_Write = (PR_WriteT)GetProcAddress(m_nssHModule, "PR_Write");
				m_nssPfnTable.pfnPR_GetError = (PR_GetErrorT)GetProcAddress(m_nssHModule, "PR_GetError");
				m_nssPfnTable.pfnPR_Close = (PR_CloseT)GetProcAddress(m_nssHModule, "PR_Close");
				m_nssPfnTable.pfnPR_NewTCPSocket = (PR_NewTCPSocketT)GetProcAddress(m_nssHModule, "PR_NewTCPSocket");
			}
		}

		m_pfnTable.SSL_library_init();

		return bRet;
	}

	static ssl_verify_result CertVerifyCallback(SSL *ssl, BYTE *out_alert)
	{
		return ssl_verify_ok;
	}

	BOOL CChromeSSL::Handshake(BOOL& isHttp2, BOOL useALPN)
	{
		if (m_socketIO == nullptr) {
			printf("\n\nCannot find the socket, handshake failed\n\n");
			return FALSE;
		}

		BOOL bRet = TRUE;
		SECURITY_STATUS ss;

		SSL_METHOD method;
		SSL_CTX *ctx = NULL;

		PVOID biop = NULL;
		BYTE* bBuffer = nullptr;
		size_t stRecSize = 0;
		size_t stAppSize = 0;
		std::map<pcpp::SSLRecordType, std::map<size_t, pcpp::SSLLayer*>> mapSSLLayer;
		pcpp::SSLLayer* lyrData = nullptr;

		isHttp2 = FALSE;

		if (m_isFirefox) {
			m_NSSSocket = m_nssPfnTable.pfnPR_NewTCPSocket();
			ULONG ident = m_nssPfnTable.pfnPR_GetUniqueIdentity("NSS layer");
			m_NSSSocket->identity = ident;

			/*Let m_nssPfnTable.pfnPR_Write function executing the PR_Write function,
			m_nssPfnTable.pfnPR_Read function executing the PR_Read function*/
			m_NSSSocket->methods->write = (VOID*)PR_Write;
			m_NSSSocket->methods->read = (VOID*)PR_Read;
		}

		method = SSLv23_client_method();
		if (method == NULL)
		{
			bRet = FALSE;
			goto exit;
		}

		ctx = SSL_CTX_NEW(method);
		if (ctx == NULL)
		{
			bRet = FALSE;
			goto exit;
		}

		if (ChromeMajorVersion >= 59 && ChromeMajorVersion <= 60)
		{
			SSL_CTX_i_promise_to_verify_certs_after_the_handshake(ctx);
		}
		else if (ChromeMajorVersion >= 61)
		{
			SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, CertVerifyCallback);
		}

		m_SslClient = SSL_new(ctx);
		if (m_SslClient == NULL)
		{
			bRet = FALSE;
			goto exit;
		}

		// init BIO
		if (m_OpenSSLMode)
		{
			if (!m_pfnTable.BIO_new_bio_pair(&bio1, BIO_BUFFER_SIZE, &bio2, BIO_BUFFER_SIZE))
			{
				bRet = FALSE;
				goto exit;
			}
		}
		else if (ChromeMajorVersion >= 56)
		{
			if (!my_BIO_new_bio_pair(&bio1, &bio2, BIO_BUFFER_SIZE, m_pIoBuffer1, BIO_BUFFER_SIZE, m_pIoBuffer2))
			{
				bRet = FALSE;
				goto exit;
			}
		}
		else
		{
			bio1 = BIO_new(m_pfnTable.biop_table);
			bio2 = BIO_new(m_pfnTable.biop_table);

			if (bio1 == NULL || bio2 == NULL)
			{
				bRet = FALSE;
				goto exit;
			}

			if (!bio_make_pair(bio1, bio2, BIO_BUFFER_SIZE, m_pIoBuffer1, BIO_BUFFER_SIZE, m_pIoBuffer2))
			{
				bRet = FALSE;
				goto exit;
			}
		}

		SSL_set_bio(m_SslClient, bio1, bio1);

		SSL_set_connect_state(m_SslClient);

		if (useALPN) {
			//ALPN
			int cur = 0;
			unsigned char protocols[128];

			protocols[cur++] = NGHTTP2_PROTO_VERSION_ID_LEN;

			memcpy(&protocols[cur], NGHTTP2_PROTO_VERSION_ID,
				NGHTTP2_PROTO_VERSION_ID_LEN);
			cur += NGHTTP2_PROTO_VERSION_ID_LEN;

			protocols[cur++] = ALPN_HTTP_1_1_LENGTH;
			memcpy(&protocols[cur], ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH);
			cur += ALPN_HTTP_1_1_LENGTH;

			SSL_set_alpn_protos(m_SslClient, protocols, cur);
		}

		while (1)
		{
			int c;
			//After called SSL_do_handshake function, the next handshake message will store in the buffer bio2
			int ret = SSL_do_handshake(m_SslClient);
			if (ret == 1)
			{
				_tprintf(_T("do hanndshake return success: %d\n"), ret);
				break;
			}

			ret = SSL_get_error(m_SslClient, ret);
			if (ret != SSL_ERROR_WANT_READ)
			{
				_tprintf(_T("strange state %d, give up"), ret);
				bRet = FALSE;
				goto exit;
			}

			//Read the ssl message from buffer bio2 to the self defined buffer by calling the BIO_read function
			c = BIO_read(bio2, pClientToServerBuffer, cbClientToServerBuffer);
			if (c <= 0)
			{
				_tprintf(_T("read failed: %d\n"), c);
				return FALSE;
			}

			Utility::FreeOBJ(&bBuffer);
			//Send the data in buffer bio2 to server
			if (m_socketIO->SendMsgToServer(pClientToServerBuffer, c)) {
				if (!m_socketIO->ReceiveMsgFromServer(bBuffer, stRecSize)) {
					bRet = FALSE;
					goto exit;
				}
			}
			else {
				bRet = FALSE;
				goto exit;
			}

			if (!Behavior::CreateSSLMessageByRawdata(mapSSLLayer, bBuffer, stRecSize)) {
				bRet = FALSE;
				goto exit;
			}

			if (mapSSLLayer.find(pcpp::SSL_HANDSHAKE) == mapSSLLayer.end() 
				|| mapSSLLayer[pcpp::SSL_HANDSHAKE].find(pcpp::SSL_SERVER_HELLO) == mapSSLLayer[pcpp::SSL_HANDSHAKE].end()) {
				bRet = FALSE;
				goto exit;
			}
			pcpp::SSLHandshakeLayer* lyrServerHello = (pcpp::SSLHandshakeLayer*)mapSSLLayer[pcpp::SSL_HANDSHAKE][pcpp::SSL_SERVER_HELLO];
			pcpp::SSLServerHelloMessage* msgServerHello = (pcpp::SSLServerHelloMessage*)lyrServerHello->getHandshakeMessageAt(0);

			//Try to find the ALPN from Server hello packet
			for (int i = 0; i != msgServerHello->getExtensionCount(); ++i) {
				if (msgServerHello->getExtension(i)->getType() == pcpp::SSL_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
					pcpp::SSLExtension* extALPN = msgServerHello->getExtension(i);
					if (extALPN->getData()[3] == 'h' && extALPN->getData()[4] == '2') {
						printf("\n\nFound ALPN from server hello packet\n\n");
						isHttp2 = TRUE;
						break;
					}
				}
			}

			
			if (mapSSLLayer.find(pcpp::SSL_APPLICATION_DATA) != mapSSLLayer.end()) {
				for (int i = 0; i != mapSSLLayer[pcpp::SSL_APPLICATION_DATA].size(); ++i) {
					lyrData = mapSSLLayer[pcpp::SSL_APPLICATION_DATA][i];
					stAppSize += lyrData->getDataLen();
				}
			}

			/*
			Write the ssl message received from server into buffer bio2 by calling BIO_write function, 
			then call the SSL_do_handshake function the next ssl message you need to sent to server will store in the buffer bio2,
			sometimes the application data will follow the ssl message in the same packet, so the size should minus application data size.
			*/
			c = BIO_write(bio2, bBuffer, stRecSize - stAppSize);
			if (c != stRecSize - stAppSize)
			{
				_tprintf(_T("Oops, buffer full QQ"));
			}
		}
		printf("\n\nHandshake with server successfully, you can send request now\n");

		//Sometimes the application data will follow the ssl message in the same packet, tyr to find the data and decrypt it.
		BYTE tmpBuffer[1000];
		DWORD size = 0;
		if (mapSSLLayer.find(pcpp::SSL_APPLICATION_DATA) != mapSSLLayer.end()) {
			for (int i = 0; i != mapSSLLayer[pcpp::SSL_APPLICATION_DATA].size(); ++i) {
				lyrData = mapSSLLayer[pcpp::SSL_APPLICATION_DATA][i];
				if (!Decrypt(lyrData->getData(), lyrData->getDataLen(), tmpBuffer, 1000, &size)) {
					bRet = FALSE;
					goto exit;
				}
			}
		}

	exit:

		return bRet;
	}

	BOOL CChromeSSL::Encrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen, DWORD type)
	{
		SECURITY_STATUS ss;

		int ret = SSL_write(m_SslClient, inBuffer, inSize);
		if (ret <= 0)
		{
			int sslerr = SSL_get_error(m_SslClient, ret);
			//_tprintf(_T("SSL_Write failed, ret = %d, last error lib = %d reason = %d\n"), ret, ERR_GET_LIB(err), ERR_GET_REASON(err));

			ULONG err = ERR_get_error();
			PrintSSLErrorMessage(_T("SSL_write"), ret, sslerr, err);
			Utility::WriteFile("rsp.txt",(BYTE*)"SSL_write encrypt failed, error: This site can, No context"
				, strlen("SSL_write encrypt failed, error: This site can, No context"));
			return FALSE;
		}

		ret = BIO_read(bio2, outBuffer, outSize);
		if (ret <= 0)
		{
			_tprintf(_T("not enough buffer QQ: %d\n"), ret);
			return FALSE;
		}
		*dwWriteen = ret;

		//If browser type is Firefox passed data encrypted by chrome.dll into NSS3.dll pfnPR_Write function.
		if (m_isFirefox) {
			printf("\nFirefox encrypt function\n");
			ss = m_nssPfnTable.pfnPR_Write(m_NSSSocket, (void*)inBuffer, inSize);
			if (GetLastError() && GetLastError() != TCP_CONNECTION_TIMEOUT) {
				_tprintf(_T("error code = 0x%08x\n"), GetLastError());
				Utility::WriteFile("rsp.txt", (BYTE*)"PR_Write encrypt failed, error: timeout, No context"
					, strlen("PR_Write encrypt failed, error: timeout, No context"));
				return FALSE;
			}
		}

		return TRUE;
	}

	BOOL CChromeSSL::Decrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen)
	{
		int ret;
		
		ret = BIO_write(bio2, inBuffer, inSize);
		if (ret <= 0 || ret != inSize)
		{
			_tprintf(_T("not enough buffer QQ: %d\n"), ret);
			return FALSE;
		}
		m_response = new BYTE[outSize];
		ret = SSL_read(m_SslClient, m_response, outSize);
		m_recSize = ret;

		if (ret <= 0)
		{
			int sslerr = SSL_get_error(m_SslClient, ret);
			ULONG err = ERR_get_error();
			PrintSSLErrorMessage(_T("SSL_read"), ret, sslerr, err);
			Utility::WriteFile("rsp.txt", (BYTE*)"SSL_read decrypt failed, error: This site can, No context"
				, strlen("SSL_read decrypt failed, error: This site can, No context"));
			return FALSE;
		}

		//If browser type is Firefox passed data decrypted by chrome.dll into NSS3.dll pfnPR_Read function.
		if (m_isFirefox) {
			int iResult = 0;
			iResult = m_nssPfnTable.pfnPR_Read(m_NSSSocket, outBuffer, outSize);
			if (GetLastError() && GetLastError() != TCP_CONNECTION_TIMEOUT) {
				_tprintf(_T("error code = 0x%08x\n"), GetLastError());
				Utility::WriteFile("rsp.txt", (BYTE*)"PR_Read decrypt failed, error: timeout, No context"
					, strlen("PR_Read decrypt failed, error: timeout, No context"));
				return FALSE;
			}
			*dwWriteen = iResult;
		}
		else {
			memcpy(outBuffer, m_response, ret);
			*dwWriteen = ret;
		}

		Utility::FreeOBJ(&m_response);
		return TRUE;
	}

	BOOL CChromeSSL::DeInit()
	{
		printf("\n\nDeInit called\n\n");
		BOOL bRet = TRUE;
		if (m_SslClient != nullptr)
		{
			if (ptr_alpn_client_proto_list != nullptr) {
				OPENSSL_free(*ptr_alpn_client_proto_list);
				*ptr_alpn_client_proto_list = nullptr;
			}
			//Osprey needs SSL_free event to know the connection was disconnected
			SSL_free(m_SslClient);
			m_SslClient = nullptr;
		}
		else
		{
			bRet = FALSE;
		}

		if (m_NSSSocket != nullptr) {
			//Osprey needs pfnPR_Close event to know the connection was disconnected
			m_nssPfnTable.pfnPR_Close(m_NSSSocket);
			m_NSSSocket = nullptr;
		}
		else
		{
			bRet = FALSE;
		}

		return bRet;
	}

	CSSL* Behavior::CreateChromeSSLInstance(BOOL isFirefox)
	{
		return new CChromeSSL(isFirefox);
	}
}