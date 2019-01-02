#include "StdAfx.h"

#include "SSLLibrary_secur32.h"
#include "Utility.h"

namespace Behavior
{
	HMODULE CSecur32SSL::m_hModule = NULL;
	SecurityFunctionTable CSecur32SSL::m_pfnTable = { NULL };
	CSecur32SSL* CSecur32SSL::m_secure32 = nullptr;

	extern VOID PrintSecurityStatusMessage(_TCHAR *funcName, SECURITY_STATUS ss);

	CSecur32SSL::CSecur32SSL()
	{
		cbClientToServerBuffer = 4096;
		pClientToServerBuffer = new BYTE[cbClientToServerBuffer];
	}

	CSecur32SSL::~CSecur32SSL()
	{
		DeInit();
	}

	BOOL CSecur32SSL::InitLibrary()
	{
		PSecurityFunctionTable pfuncTable;

		if (m_hModule == NULL)
		{
			HMODULE hSecur32 = NULL;

			m_hModule = LoadLibrary(_T("SECUR32.DLL"));
			if (m_hModule == NULL)
				return FALSE;

			INIT_SECURITY_INTERFACE pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(m_hModule, "InitSecurityInterfaceW");
			if (pInitSecurityInterface == NULL)
				return FALSE;

			pfuncTable = pInitSecurityInterface();

			if (pfuncTable == NULL)
				return FALSE;

			RtlCopyMemory(&m_pfnTable, pfuncTable, sizeof(SecurityFunctionTable));
		}

		return TRUE;
	}

	BOOL CSecur32SSL::Init()
	{
		// loads ncrypt function pointer
		return InitLibrary();
	}

	SECURITY_STATUS CSecur32SSL::CreateCredentials(PCredHandle phCreds, PCCERT_CONTEXT pCertContext)
	{
		SECURITY_STATUS ss;
		TimeStamp tsExpiry;

		SCHANNEL_CRED SchannelCred = { 0 };

		ZeroMemory(&SchannelCred, sizeof(SCHANNEL_CRED));

		SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
		if (pCertContext)
		{
			SchannelCred.cCreds = 1;
			SchannelCred.paCred = &pCertContext;
		}

		SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;

		SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
		SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;

		if (pCertContext)
		{
			SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_REVOCATION_CHECK_CHAIN;
		}
		else
		{
			SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_REVOCATION_CHECK_CHAIN;
		}

		ss = m_pfnTable.AcquireCredentialsHandle(NULL,
			UNISP_NAME_W,
			pCertContext ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
			NULL,
			&SchannelCred,
			NULL,
			NULL,
			phCreds,
			&tsExpiry);

		return ss;
	}

	BOOL CSecur32SSL::Handshake(BOOL& isHttp2, BOOL useALPN)
	{
		if (m_socketIO == nullptr) {
			printf("\n\nCannot find the socket, handshake failed\n\n");
			return FALSE;
		}

		BOOL bRet = TRUE;
		SECURITY_STATUS ss;
		SecBufferDesc        InBuffer;
		SecBufferDesc        OutBuffer;
		SecBuffer            inbuf;
		SecBuffer            InBuffers[2];
		SecBuffer            OutBuffers[1];
		DWORD           dwSSPIFlags;
		DWORD           dwSSPIOutFlags;
		TimeStamp       tsExpiry;
		DWORD           cbData;

		BYTE* bBuffer = nullptr;
		size_t stRecSize = 0;
		std::map<pcpp::SSLRecordType, std::map<size_t, pcpp::SSLLayer*>> mapSSLLayer;
		pcpp::SSLLayer* lyrData = nullptr;

		ss = CreateCredentials(&m_hClientCred);
		if (!SEC_SUCCESS(ss))
		{
			bRet = FALSE;
			_tprintf(_T("Create client credentials failed: 0x%08x\n"), ss);
			goto exit;
		}

		dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
			ISC_REQ_REPLAY_DETECT |
			ISC_REQ_CONFIDENTIALITY |
			ISC_RET_EXTENDED_ERROR |
			ISC_REQ_ALLOCATE_MEMORY |
			ISC_REQ_STREAM;

		BYTE bAlpn[22] =
		{
			0x12,0x0,0x0,0x0,0x2,0x0,0x0,0x0,0xc,0x0,0x2,0x68,0x32,0x8,0x68,0x74,0x74,0x70,0x2f,0x31,0x2e,0x31
		};

		if (useALPN) {
			inbuf.pvBuffer = bAlpn;
			inbuf.BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
			inbuf.cbBuffer = 22;
		}
		else {
			inbuf.pvBuffer = NULL;
			inbuf.BufferType = SECBUFFER_EMPTY;
			inbuf.cbBuffer = 0;
		}

		InBuffer.cBuffers = 1;
		InBuffer.pBuffers = &inbuf;
		InBuffer.ulVersion = SECBUFFER_VERSION;

		OutBuffers[0].pvBuffer = NULL;
		OutBuffers[0].BufferType = SECBUFFER_EMPTY;
		OutBuffers[0].cbBuffer = 0;

		OutBuffer.cBuffers = 1;
		OutBuffer.pBuffers = OutBuffers;
		OutBuffer.ulVersion = SECBUFFER_VERSION;

		//First called InitializeSecurityContext function the client hello message will store in the buffer OutBuffer
		ss = m_pfnTable.InitializeSecurityContext(
			&m_hClientCred,
			NULL,
			NULL,
			dwSSPIFlags,
			0,
			SECURITY_NATIVE_DREP,
			&InBuffer,
			0,
			&m_hClientCtx,
			&OutBuffer,
			&dwSSPIOutFlags,
			&tsExpiry);

		if (ss != SEC_I_CONTINUE_NEEDED) {
			bRet = FALSE;
			goto exit;
		}

		//_tprintf(_T("Client: Generate %d handshake data\n"), OutBuffers[0].cbBuffer);

		while (1)
		{
			Utility::FreeOBJ(&bBuffer);

			if (m_socketIO->SendMsgToServer((BYTE*)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer)) {
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

			InBuffers[0].pvBuffer = bBuffer;
			InBuffers[0].cbBuffer = stRecSize;
			InBuffers[0].BufferType = SECBUFFER_TOKEN;

			InBuffers[1].pvBuffer = NULL;
			InBuffers[1].cbBuffer = 0;
			InBuffers[1].BufferType = SECBUFFER_EMPTY;

			InBuffer.cBuffers = 2;
			InBuffer.pBuffers = InBuffers;
			InBuffer.ulVersion = SECBUFFER_VERSION;

			//
			// Set up the output buffers. These are initialized to NULL
			// so as to make it less likely we'll attempt to free random
			// garbage later.
			//

			OutBuffers[0].pvBuffer = NULL;
			OutBuffers[0].BufferType = SECBUFFER_TOKEN;
			OutBuffers[0].cbBuffer = 0;

			OutBuffer.cBuffers = 1;
			OutBuffer.pBuffers = OutBuffers;
			OutBuffer.ulVersion = SECBUFFER_VERSION;

			//
			// Call InitializeSecurityContext.
			//

			//InBuffer is the ssl message received from the server, the next ssl message need to send to server will store in the OutBuffer
			ss = m_pfnTable.InitializeSecurityContext(
				&m_hClientCred,
				&m_hClientCtx,
				NULL,
				dwSSPIFlags,
				0,
				SECURITY_NATIVE_DREP,
				&InBuffer,
				0,
				NULL,
				&OutBuffer,
				&dwSSPIOutFlags,
				&tsExpiry);

			if (ss == SEC_E_OK) /* require ... */
			{
				printf("\n\nHandshake with server successly, you can send request now\n");
				break;
			}
			else if (FAILED(ss))
			{
				bRet = FALSE;
				break;
			}
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

		BYTE tmpBuffer[1000];
		DWORD size = 0;
		if (mapSSLLayer.find(pcpp::SSL_APPLICATION_DATA) != mapSSLLayer.end()) {
			for (int i = 0; i != mapSSLLayer[pcpp::SSL_APPLICATION_DATA].size(); ++i) {
				lyrData = (pcpp::SSLApplicationDataLayer*)mapSSLLayer[pcpp::SSL_APPLICATION_DATA][i];
				if (!Decrypt(lyrData->getData(), lyrData->getDataLen(), tmpBuffer, 1000, &size)) {
					bRet = FALSE;
					goto exit;
				}
			}
		}

	exit:
		if (!bRet) {
			DeInit();
		}

		return bRet;
	}

	int CSecur32SSL::EncryptData(PCtxtHandle hContext, BYTE *src, DWORD size, BYTE *dest, DWORD destSize, DWORD *cb)
	{
		SECURITY_STATUS ss;
		SecPkgContext_StreamSizes Sizes;
		DWORD encryptedLength;

		DWORD cbIoBufferLength;

		SecBufferDesc   Message;
		SecBuffer       Buffers[4];

		ss = m_pfnTable.QueryContextAttributes(hContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
		if (ss != SEC_E_OK)
		{
			return -1;
		}

		//_tprintf(_T("Max payload = %d, header size = %d, tailer size = %d\n"), Sizes.cbMaximumMessage, Sizes.cbHeader, Sizes.cbTrailer);

		DWORD targetSize = size;
		if (targetSize > Sizes.cbMaximumMessage) targetSize = Sizes.cbMaximumMessage;
		if (targetSize < Sizes.cbBlockSize) targetSize = Sizes.cbBlockSize;
		targetSize += Sizes.cbHeader + Sizes.cbTrailer;

		if (destSize < targetSize)
		{
			*cb = targetSize;
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return -1;
		}

		cbIoBufferLength = Sizes.cbHeader +
			Sizes.cbMaximumMessage +
			Sizes.cbTrailer;

		BYTE *pbIoBuffer = new BYTE[cbIoBufferLength];
		if (pbIoBuffer == NULL) {
			SetLastError(ERROR_OUTOFMEMORY);
			return -1;
		}

		PBYTE pbMessage;
		pbMessage = pbIoBuffer + Sizes.cbHeader;
		DWORD cbMessage;

		cbMessage = size > Sizes.cbMaximumMessage ? Sizes.cbMaximumMessage : size;
		RtlCopyMemory(pbMessage, src, cbMessage);

		Buffers[0].pvBuffer = pbIoBuffer;
		Buffers[0].cbBuffer = Sizes.cbHeader;
		Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

		Buffers[1].pvBuffer = pbMessage;
		Buffers[1].cbBuffer = cbMessage;
		Buffers[1].BufferType = SECBUFFER_DATA;

		Buffers[2].pvBuffer = pbMessage + cbMessage;
		Buffers[2].cbBuffer = Sizes.cbTrailer;
		Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

		Buffers[3].pvBuffer = NULL;
		Buffers[3].cbBuffer = 0;
		Buffers[3].BufferType = SECBUFFER_EMPTY;

		Message.ulVersion = SECBUFFER_VERSION;
		Message.cBuffers = 4;
		Message.pBuffers = Buffers;

		//BufferCount = 
		//FD = hContext
		// 1
		//  BufTotalLen = cbMessage 

		ss = m_pfnTable.EncryptMessage(hContext, 0, &Message, 0);
		if (!SEC_SUCCESS(ss))
		{
			PrintSecurityStatusMessage(_T("EncryptMessage"), ss);
			Utility::FreeOBJ(&pbIoBuffer);
			SetLastError(ss);
			return -1;
		}

		encryptedLength = Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer;
		if (encryptedLength > destSize)
		{
			_tprintf(_T("oops, output buffer too small\n"));
		}
		else
			RtlCopyMemory(dest, pbIoBuffer, encryptedLength);

		*cb = encryptedLength;

		if (Buffers[3].pvBuffer)
			m_pfnTable.FreeContextBuffer(Buffers[3].pvBuffer);

		Utility::FreeOBJ(&pbIoBuffer);

		return cbMessage;
	}

	int CSecur32SSL::DecryptData(PCtxtHandle hContext, BYTE *src, DWORD size, BYTE *dest, DWORD destSize, DWORD *cb)
	{
		SECURITY_STATUS ss;
		SecPkgContext_StreamSizes Sizes;


		DWORD cbIoBufferLength;

		SecBufferDesc   Message;
		SecBuffer       Buffers[4];
		SecBuffer *     pDataBuffer;
		SecBuffer *     pExtraBuffer;

		ss = m_pfnTable.QueryContextAttributes(hContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);

		cbIoBufferLength = Sizes.cbHeader +
			Sizes.cbMaximumMessage +
			Sizes.cbTrailer;

		BYTE *pbIoBuffer = new BYTE[cbIoBufferLength];
		if (pbIoBuffer == NULL) {
			SetLastError(ERROR_OUTOFMEMORY);
			return -1;
		}

		RtlCopyMemory(pbIoBuffer, src, size);

		Buffers[0].pvBuffer = pbIoBuffer;
		Buffers[0].cbBuffer = size;
		Buffers[0].BufferType = SECBUFFER_DATA;

		Buffers[1].BufferType = SECBUFFER_EMPTY;
		Buffers[2].BufferType = SECBUFFER_EMPTY;
		Buffers[3].BufferType = SECBUFFER_EMPTY;

		Message.ulVersion = SECBUFFER_VERSION;
		Message.cBuffers = 4;
		Message.pBuffers = Buffers;

		ss = m_pfnTable.DecryptMessage(hContext, &Message, 0, NULL);
		if (ss == SEC_E_INCOMPLETE_MESSAGE) {
			_tprintf(_T("oops, incomplete message\n"));
			Utility::FreeOBJ(&pbIoBuffer);
			return 0;
		}

		if (ss == SEC_E_OK)
		{
			BOOL copied = FALSE;
			for (int i = 1; i < 4; i++)
			{
				BOOL needFree = FALSE;
				if (Buffers[i].pvBuffer && Buffers[i].BufferType != SECBUFFER_EMPTY)
				{
					if (Buffers[i].pvBuffer >= pbIoBuffer && Buffers[i].pvBuffer < pbIoBuffer + cbIoBufferLength)
					{
						// good
					}
					else
					{
						//_tprintf(_T("Found allocated buffer at index %d\n"), i);
						needFree = TRUE;
					}
				}

				if (!copied && Buffers[i].BufferType == SECBUFFER_DATA)
				{
					//_tprintf(_T("data buffer found at %d, length = %d\n"), i, Buffers[i].cbBuffer);
					if (Buffers[i].cbBuffer > destSize)
					{
						_tprintf(_T("cannot hold the data\n"));
					}

					if (Buffers[i].cbBuffer > 0)
					{

						RtlCopyMemory(dest, Buffers[i].pvBuffer, Buffers[i].cbBuffer);
						*cb = Buffers[i].cbBuffer;
						copied = TRUE;
					}

				}
				else if (Buffers[i].BufferType == SECBUFFER_EXTRA) {
					//m_pfnTable.FreeContextBuffer(Buffers[i].pvBuffer);
					_tprintf(_T("extra data buffer found at %d, length = %d, pvBuffer = %x\n"), i, Buffers[i].cbBuffer, Buffers[i].pvBuffer);

					if (!copied)
					{
						DecryptData(hContext, src + size - Buffers[i].cbBuffer, Buffers[i].cbBuffer, dest, destSize, cb);
					}
				}
				else if (Buffers[i].BufferType != SECBUFFER_EMPTY &&
					Buffers[i].BufferType != SECBUFFER_STREAM_TRAILER)
				{
					_tprintf(_T("unknown type: %d at index %d\n"), Buffers[i].BufferType, i);
				}

				if (needFree)
					m_pfnTable.FreeContextBuffer(Buffers[i].pvBuffer);

			}

			Utility::FreeOBJ(&pbIoBuffer);
			return 1;
		}
		else
		{
			PrintSecurityStatusMessage(_T("DecryptMessage"), ss);
		}
		Utility::FreeOBJ(&pbIoBuffer);
		SetLastError(ss);
		return 0;

	}

	BOOL CSecur32SSL::Encrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen, DWORD type)
	{
		//printf("\nEncrypt data\n");
		SECURITY_STATUS ss;
		if (EncryptData(&m_hClientCtx, inBuffer, inSize, outBuffer, outSize, dwWriteen) < 0)
		{
			_tprintf(_T("error code = 0x%08x\n"), GetLastError());
			Utility::WriteFile("rsp.txt", (BYTE*)"EncryptMessage encrypt failed", strlen("EncryptMessage encrypt failed"));
			return FALSE;
		}

		return TRUE;
	}

	BOOL CSecur32SSL::Decrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen)
	{
		//printf("\nDecrypt data\n");
		SECURITY_STATUS ss;

		if (DecryptData(&m_hClientCtx, inBuffer, inSize, outBuffer, outSize, dwWriteen) <= 0)
		{
			_tprintf(_T("error code = 0x%08x\n"), GetLastError());
			Utility::WriteFile("rsp.txt", (BYTE*)"DecryptMessage decrypt failed", strlen("DecryptMessage decrypt failed"));
			return FALSE;
		}

		return TRUE;
	}

	BOOL CSecur32SSL::DeInit()
	{
		printf("\n\nDeInit called\n\n");
		SECURITY_STATUS ss;
		BOOL bRet = TRUE;

		ss = m_pfnTable.DeleteSecurityContext(&m_hClientCtx);
		if (!(SEC_SUCCESS(ss))) bRet = FALSE;
		ss = m_pfnTable.DeleteSecurityContext(&m_hServerCtx);
		if (!(SEC_SUCCESS(ss))) bRet = FALSE;

		return bRet;
	}

	CSSL* Behavior::CreateSecur32SSLInstance()
	{
		return new CSecur32SSL();
	}
}