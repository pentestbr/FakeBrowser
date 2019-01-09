#include "stdafx.h"

#include "SSLLibrary_ncrypt.h"
#include "Protocol.h"
#include "Utility.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

namespace Behavior
{
	HMODULE CNcryptSSL::m_hModule = NULL;
	NCRYPT_SSL_FUNCTION_TABLE * CNcryptSSL::m_pfnTable = NULL;
	NCryptOpenStorageProviderFn CNcryptSSL::m_pfnNCryptOpenStorageProvider = NULL;
	NCryptImportKeyFn CNcryptSSL::m_pfnNCryptImportKey = NULL;

	CNcryptSSL::CNcryptSSL()
	{
	}

	CNcryptSSL::~CNcryptSSL()
	{
		DeInit();
	}

	BOOL CNcryptSSL::Init()
	{
		SECURITY_STATUS ss;
		NCRYPT_SSL_FUNCTION_TABLE *pTable;

		if (m_hModule == NULL)
		{
			m_hModule = LoadLibrary(_T("Ncrypt.dll"));
			if (m_hModule == NULL)
				return FALSE;

			m_pfnTable = new NCRYPT_SSL_FUNCTION_TABLE;

			m_pfnTable->EncryptPacket = (SslEncryptPacketFn)GetProcAddress(m_hModule, "SslEncryptPacket");
			m_pfnTable->DecryptPacket = (SslDecryptPacketFn)GetProcAddress(m_hModule, "SslDecryptPacket");
			m_pfnTable->OpenPrivateKey = (SslOpenPrivateKeyFn)GetProcAddress(m_hModule, "SslOpenPrivateKey");
			m_pfnTable->GenerateMasterKey = (SslGenerateMasterKeyFn)GetProcAddress(m_hModule, "SslGenerateMasterKey");
			m_pfnTable->ImportMasterKey = (SslImportMasterKeyFn)GetProcAddress(m_hModule, "SslImportMasterKey");
			m_pfnTable->LookupCipherSuiteInfo = (SslLookupCipherSuiteInfoFn)GetProcAddress(m_hModule, "SslLookupCipherSuiteInfo");
			m_pfnTable->GenerateSessionKeys = (SslGenerateSessionKeysFn)GetProcAddress(m_hModule, "SslGenerateSessionKeys");
			m_pfnTable->OpenProvider = (SslOpenProviderFn)GetProcAddress(m_hModule, "SslOpenProvider");
			m_pfnTable->CreateHandshakeHash = (SslCreateHandshakeHashFn)GetProcAddress(m_hModule, "SslCreateHandshakeHash");
			m_pfnTable->HashHandshake = (SslHashHandshakeFn)GetProcAddress(m_hModule, "SslHashHandshake");
			m_pfnTable->ComputeFinishedHash = (SslComputeFinishedHashFn)GetProcAddress(m_hModule, "SslComputeFinishedHash");
			m_pfnTable->GetCipherSuitePRFHashAlgorithm = (SslGetCipherSuitePRFHashAlgorithmFn)GetProcAddress(m_hModule, "SslGetCipherSuitePRFHashAlgorithm");
			m_pfnTable->FreeObject = (SslFreeObjectFn)GetProcAddress(m_hModule, "SslFreeObject");


			m_pfnNCryptOpenStorageProvider = (NCryptOpenStorageProviderFn)GetProcAddress(m_hModule, "NCryptOpenStorageProvider");
			m_pfnNCryptImportKey = (NCryptImportKeyFn)GetProcAddress(m_hModule, "NCryptImportKey");

			if (m_pfnTable->EncryptPacket == NULL ||
				m_pfnTable->DecryptPacket == NULL ||
				m_pfnTable->OpenPrivateKey == NULL ||
				m_pfnTable->GenerateMasterKey == NULL ||
				m_pfnTable->ImportMasterKey == NULL ||
				m_pfnTable->LookupCipherSuiteInfo == NULL ||
				m_pfnTable->GenerateSessionKeys == NULL ||
				m_pfnTable->OpenProvider == NULL ||
				m_pfnNCryptOpenStorageProvider == NULL ||
				m_pfnNCryptImportKey == NULL
				)
				return FALSE;
		}

		// loads ncrypt function pointer
		return TRUE;
	}

	//Do SSL handshake with server
	BOOL CNcryptSSL::Handshake(BOOL& isHttp2, BOOL useALPN)
	{
		if (m_socketIO == nullptr) {
			printf("\n\nCannot find the socket, handshake failed\n\n");
			return FALSE;
		}

		BOOL bRet = FALSE;
		SECURITY_STATUS ss;
		DWORD dwProtocol = TLS1_2_PROTOCOL_VERSION;
		std::map<pcpp::SSLRecordType, std::map<size_t, pcpp::SSLLayer*>> mapSSLLayer;
		BYTE* bBuffer = nullptr;
		size_t stRecSize = 0;
		
		/*
		Declare SSL handshake related variables
		*/
		pcpp::SSLHandshakeLayer* lyrClientHello = nullptr;
		pcpp::SSLClientHelloMessage* msgClientHello = nullptr;
		pcpp::SSLHandshakeLayer* lyrServerHello = nullptr;
		pcpp::SSLServerHelloMessage* msgServerHello = nullptr;
		pcpp::SSLHandshakeLayer* lyrCertificate = nullptr;
		pcpp::SSLCertificateMessage* msgCertificate = nullptr;
		pcpp::SSLHandshakeLayer* lyrServerDone = nullptr;
		pcpp::SSLServerHelloDoneMessage* msgServerDone = nullptr;
		pcpp::SSLChangeCipherSpecLayer* lyrChangeCipherSpec = nullptr;
		pcpp::SSLHandshakeLayer* lyrClientKeyExc = nullptr;
		pcpp::SSLClientKeyExchangeMessage* msgClientKeyExc = nullptr;
		pcpp::SSLHandshakeLayer* lyrClientFinished = nullptr;
		pcpp::SSLHandshakeLayer* lyrServerFinished = nullptr;
		pcpp::SSLLayer* lyrData = nullptr;
		PCCERT_CONTEXT pCertContext = nullptr;

		/*
		SSL session key related variables
		*/
		BYTE *publicKeyBlob = nullptr;
		BYTE *preMasterSecret = nullptr;
		DWORD cb = 0;
		NCRYPT_PROV_HANDLE hNcryptProvider = NULL;
		NCRYPT_HASH_HANDLE phHandshakeHash = NULL;

		ss = m_pfnTable->OpenProvider(&m_hSslProvider, L"Microsoft SSL Protocol Provider", NULL);
		if (!SEC_SUCCESS(ss))
		{
			_tprintf(_T("Open provider failed: 0x%08x\n"), ss);
			return FALSE;
		}

		/*
		Create client hello message.
		So far mapSSLLayer[Protocol::SSL_HANDSHAKE] inclueds client hello message
		*/
		Protocol::SSLClientHello* clientHello = new Protocol::SSLClientHello(useALPN, dwProtocol, TLS_RSA_WITH_AES_128_CBC_SHA);
		if (!Behavior::CreateSSLMessageByRawdata(mapSSLLayer, (BYTE*)clientHello, htons(clientHello->m_recordLayer.length) + 5)) {
			bRet = FALSE;
			goto exit;
		}

		if (mapSSLLayer.find(pcpp::SSL_HANDSHAKE) == mapSSLLayer.end() || mapSSLLayer[pcpp::SSL_HANDSHAKE].find(pcpp::SSL_CLIENT_HELLO) == mapSSLLayer[pcpp::SSL_HANDSHAKE].end()) {
			bRet = FALSE;
			goto exit;
		}
		lyrClientHello = (pcpp::SSLHandshakeLayer*)mapSSLLayer[pcpp::SSL_HANDSHAKE][pcpp::SSL_CLIENT_HELLO];
		msgClientHello = (pcpp::SSLClientHelloMessage*)lyrClientHello->getHandshakeMessageAt(0);

		Utility::FreeOBJ(&bBuffer);
		stRecSize = 0;
		//Send client hello message to server
		if (m_socketIO->SendMsgToServer(lyrClientHello->getData(), lyrClientHello->getDataLen())) {
			if (!m_socketIO->ReceiveMsgFromServer(bBuffer, stRecSize)) {
				bRet = FALSE;
				goto exit;
			}
		}
		else {
			bRet = FALSE;
			goto exit;
		}

		/*
		Create SSL structure by receiving packet from server,
		the ssl messages received from server will inclueds server hello, certificate, server hello done.

		So far mapSSLLayer[Protocol::SSL_HANDSHAKE] inclueds client hello message, server hello, certificate, server hello done.
		*/
		if (!Behavior::CreateSSLMessageByRawdata(mapSSLLayer, bBuffer, stRecSize)) {
			bRet = FALSE;
			goto exit;
		}

		if (mapSSLLayer[pcpp::SSL_HANDSHAKE].size() != 4) {
			printf("Something error druing init");
			bRet = FALSE;
			goto exit;
		}

		if (mapSSLLayer[pcpp::SSL_HANDSHAKE].find(pcpp::SSL_SERVER_HELLO) == mapSSLLayer[pcpp::SSL_HANDSHAKE].end()
			|| mapSSLLayer[pcpp::SSL_HANDSHAKE].find(pcpp::SSL_CERTIFICATE) == mapSSLLayer[pcpp::SSL_HANDSHAKE].end()
			|| mapSSLLayer[pcpp::SSL_HANDSHAKE].find(pcpp::SSL_SERVER_DONE) == mapSSLLayer[pcpp::SSL_HANDSHAKE].end()) {
			bRet = FALSE;
			goto exit;
		}
		lyrServerHello = (pcpp::SSLHandshakeLayer*)mapSSLLayer[pcpp::SSL_HANDSHAKE][pcpp::SSL_SERVER_HELLO];
		msgServerHello = (pcpp::SSLServerHelloMessage*)lyrServerHello->getHandshakeMessageAt(0);
		lyrCertificate = (pcpp::SSLHandshakeLayer*)mapSSLLayer[pcpp::SSL_HANDSHAKE][pcpp::SSL_CERTIFICATE];
		msgCertificate = (pcpp::SSLCertificateMessage*)lyrCertificate->getHandshakeMessageAt(0);
		lyrServerDone = (pcpp::SSLHandshakeLayer*)mapSSLLayer[pcpp::SSL_HANDSHAKE][pcpp::SSL_SERVER_DONE];
		msgServerDone = (pcpp::SSLServerHelloDoneMessage*)lyrServerDone->getHandshakeMessageAt(0);
		
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

		
		printf("\n\nServer Certificate Info:");
		pCertContext = (PCCERT_CONTEXT)CertCreateContext(CERT_STORE_CERTIFICATE_CONTEXT, X509_ASN_ENCODING, msgCertificate->getCertificate(0)->getData(), msgCertificate->getCertificate(0)->getDataLength(), CERT_CREATE_CONTEXT_NOCOPY_FLAG, NULL);

		if (!pCertContext) {
			_tprintf(_T("\nfailed to extract server certificate: %d"), GetLastError());
			bRet = FALSE;
			goto exit;
		}

		printf("\nCertificate Algorithm OID: %s\n", pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
		DWORD dwSize =
			CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Issuer, CERT_X500_NAME_STR, NULL, 0);

		LPTSTR wcName = new TCHAR[dwSize];
		CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Issuer, CERT_X500_NAME_STR, wcName, dwSize);
		printf("Certificate Issuer: %s", wcName);
		for (int i = 0; i != dwSize; ++i) {
			printf("%c", wcName[i]);
		}

		// Client import public key
		bRet = CryptDecodeObject(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB,
			pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
			pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
			CRYPT_DECODE_NOCOPY_FLAG,
			NULL,
			&cb);

		if (!bRet)
		{
			_tprintf(_T("\nfailed to open decode public key: %d"), GetLastError());
			bRet = FALSE;
			goto exit;
		}

		publicKeyBlob = new BYTE[cb];
		if (!publicKeyBlob)
		{
			bRet = FALSE;
			goto exit;
		}

		bRet = CryptDecodeObject(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB,
			pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
			pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
			CRYPT_DECODE_NOCOPY_FLAG,
			publicKeyBlob,
			&cb);

		if (!bRet)
		{
			_tprintf(_T("\nfailed to open decode public key: %d"), GetLastError());
			bRet = FALSE;
			goto exit;
		}

		ss = m_pfnNCryptOpenStorageProvider(&hNcryptProvider, MS_KEY_STORAGE_PROVIDER, 0);
		if (!SEC_SUCCESS(ss))
		{
			_tprintf(_T("\noops when open storage provider 0x%x\n"), ss);
			bRet = FALSE;
			goto exit;
		}

		ss = m_pfnNCryptImportKey(hNcryptProvider, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, &m_hServerPublicKey, publicKeyBlob, cb, 0);
		if (!(SEC_SUCCESS(ss)))
		{
			_tprintf(_T("\noops when import public key2 0x%x\n"), ss);
			bRet = FALSE;
			goto exit;
		}

		/*
		Prepare variables to generate pre-master secret and clien-side master key
		master_secret = PRF(pre_master_secret, "master secret",
		ClientHello.random + ServerHello.random)
		*/
		NCryptBufferDesc  bufferDesc;
		NCryptBuffer paramlist[3];
		BYTE* serverRandom = nullptr;
		BYTE* clientRandom = nullptr;
		pcpp::SSLCipherSuite* cipherSuite = nullptr;

		clientRandom = msgClientHello->getClientHelloHeader()->random;

		serverRandom = msgServerHello->getServerHelloHeader()->random;

		cipherSuite = msgServerHello->getCipherSuite();

		paramlist[0].BufferType = NCRYPTBUFFER_SSL_SERVER_RANDOM;
		paramlist[0].cbBuffer = 32;
		paramlist[0].pvBuffer = serverRandom;

		paramlist[2].BufferType = NCRYPTBUFFER_SSL_CLIENT_RANDOM;
		paramlist[2].cbBuffer = 32;
		paramlist[2].pvBuffer = clientRandom;

		paramlist[1].BufferType = NCRYPTBUFFER_SSL_HIGHEST_VERSION;
		paramlist[1].cbBuffer = sizeof(DWORD);
		paramlist[1].pvBuffer = &dwProtocol;

		bufferDesc.ulVersion = NCRYPTBUFFER_VERSION;
		bufferDesc.cBuffers = 3;
		bufferDesc.pBuffers = paramlist;

		BYTE smallBuffer[1];
		cb = 1;

		//Generate pre-master secret and clien-side master key
		ss = m_pfnTable->GenerateMasterKey(m_hSslProvider, NULL, m_hServerPublicKey, &m_hClientMasterKey, dwProtocol, cipherSuite->getID(), &bufferDesc, NULL, 0, &cb, NCRYPT_SSL_CLIENT_FLAG);
		if (!(SEC_SUCCESS(ss)) && ss != NTE_BUFFER_TOO_SMALL)
		{
			_tprintf(_T("\noops when generate master key1 0x%x\n"), ss);
			bRet = FALSE;
			goto exit;
		}

		preMasterSecret = new BYTE[cb];
		if (!preMasterSecret)
		{
			bRet = FALSE;
			goto exit;
		}

		ss = m_pfnTable->GenerateMasterKey(m_hSslProvider, NULL, m_hServerPublicKey, &m_hClientMasterKey, dwProtocol, cipherSuite->getID(), &bufferDesc, preMasterSecret, cb, &cb, NCRYPT_SSL_CLIENT_FLAG);

		if (!(SEC_SUCCESS(ss)))
		{
			_tprintf(_T("\noops when generate master key2 0x%x\n"), ss);
			bRet = FALSE;
			goto exit;
		}

		Protocol::SSLClientKeyExchange* clientKeyExchange = new Protocol::SSLClientKeyExchange(preMasterSecret, cb, dwProtocol);
		/*
		So far 
		mapSSLLayer[Protocol::SSL_HANDSHAKE] inclueds client hello message, server hello, certificate, server hello done, client key exchange
		*/
		if (!Behavior::CreateSSLMessageByRawdata(mapSSLLayer, (BYTE*)clientKeyExchange
			, htons(clientKeyExchange->m_recordLayer.length) + 5)) {
			bRet = FALSE;
			goto exit;
		}

		/*
		So far 
		mapSSLLayer[Protocol::SSL_HANDSHAKE] inclueds client hello message, server hello, certificate, server hello done, client key exchange,
		mapSSLLayer[Protocol::SSL_CHANGE_CIPHER_SPEC] includes one change cipher spec
		*/
		Protocol::SSLChangeCipherSpec* changeCipherSpec = new Protocol::SSLChangeCipherSpec(dwProtocol);
		if (!Behavior::CreateSSLMessageByRawdata(mapSSLLayer, (BYTE*)changeCipherSpec
			, htons(changeCipherSpec->m_recordLayer.length) + 5)) {
			bRet = FALSE;
			goto exit;
		}

		if (mapSSLLayer[pcpp::SSL_HANDSHAKE].find(pcpp::SSL_CLIENT_KEY_EXCHANGE) == mapSSLLayer[pcpp::SSL_HANDSHAKE].end()) {
			bRet = FALSE;
			goto exit;
		}
		lyrClientKeyExc = (pcpp::SSLHandshakeLayer*)mapSSLLayer[pcpp::SSL_HANDSHAKE][pcpp::SSL_CLIENT_KEY_EXCHANGE];
		msgClientKeyExc = (pcpp::SSLClientKeyExchangeMessage*)lyrClientKeyExc->getHandshakeMessageAt(0);

		if (mapSSLLayer.find(pcpp::SSL_CHANGE_CIPHER_SPEC) == mapSSLLayer.end()) {
			bRet = FALSE;
			goto exit;
		}
		lyrChangeCipherSpec = (pcpp::SSLChangeCipherSpecLayer*)mapSSLLayer[pcpp::SSL_CHANGE_CIPHER_SPEC][0];

		// Start to generate finiahed message
		/*
		First:
		We need to calculate handshake_messages.

		handshake_messages:
		All of the data from all messages in this handshake (not
		including any HelloRequest messages) up to, but not including,
		this message.

		Combine all of the ssl message so far to handshake_messages.
		*/

		DWORD dwHandshakeSize = msgClientHello->getMessageLength() + msgServerHello->getMessageLength() + msgCertificate->getMessageLength()
			+ msgServerDone->getMessageLength() + msgClientKeyExc->getMessageLength();

		BYTE * bhandShake = new BYTE[dwHandshakeSize];
		BYTE* pHandShake = bhandShake;
		/*
		Copy all of the data from all messages in this handshake into the bhandShake
		*/
		pcpp::SSLHandshakeMessage* msgHandShake = nullptr;
		for (auto mapLayer : mapSSLLayer[pcpp::SSL_HANDSHAKE]) {
			msgHandShake = ((pcpp::SSLHandshakeLayer*)mapLayer.second)->getHandshakeMessageAt(0);
			memcpy(pHandShake, msgHandShake->getData(), msgHandShake->getMessageLength());
			pHandShake += msgHandShake->getMessageLength();
		}

		BYTE finHandshake[12];

		ss = m_pfnTable->CreateHandshakeHash(m_hSslProvider, &phHandshakeHash, dwProtocol, cipherSuite->getID(), 0);

		if (!(SEC_SUCCESS(ss)))
		{
			_tprintf(_T("\noops when create handshakehash 0x%x\n"), ss);
			bRet = FALSE;
			goto exit;
		}

		/*
		Second:
		Calculate the hash of handshake_messages.
		Hash(handshake_messages)
		*/
		ss = m_pfnTable->HashHandshake(m_hSslProvider, phHandshakeHash, bhandShake, dwHandshakeSize, 0);

		if (!(SEC_SUCCESS(ss)))
		{
			_tprintf(_T("\noops when Hashhandshake 0x%x\n"), ss);
			bRet = FALSE;
			goto exit;
		}

		/*
		Third:
		Calculate the verify_data.
		verify_data:
		PRF(master_secret, finished_label, Hash(handshake_messages))
		*/
		ss = m_pfnTable->ComputeFinishedHash(m_hSslProvider, m_hClientMasterKey, phHandshakeHash, finHandshake, 12, NCRYPT_SSL_CLIENT_FLAG);

		if (!(SEC_SUCCESS(ss)))
		{
			_tprintf(_T("\noops when ComputeFinishedHash 0x%x\n"), ss);
			bRet = FALSE;
			goto exit;
		}

		//Generate session keys, m_hClientWriteKey used to encrypt data, m_hClientReadKey used to decrypt the data
		ss = m_pfnTable->GenerateSessionKeys(m_hSslProvider, m_hClientMasterKey, &m_hClientReadKey, &m_hClientWriteKey, &bufferDesc, 0);
		if (!(SEC_SUCCESS(ss)))
		{
			_tprintf(_T("\noops when generate session keys 0x%x\n"), ss);
			bRet = FALSE;
			goto exit;
		}

		/*
		Fourth:
		Encrypt the verify_data, after encrypted the verify_data, client hello finished has been created.
		Create client finished message, this packet is the first packet encryped
		*/
		pcpp::ssl_tls_handshake_layer lyrEncryptMsg;
		lyrEncryptMsg.handshakeType = pcpp::SSL_FINISHED;
		lyrEncryptMsg.length1 = 0x00;
		lyrEncryptMsg.length2 = htons(12);

		BYTE encryptMessage[16];
		memcpy(encryptMessage, (BYTE*)&lyrEncryptMsg, 4);
		memcpy(encryptMessage + 4, finHandshake, 12);

		BYTE* finMessage = new BYTE[1000];
		DWORD dwFinSize = 0;
		if (!Encrypt(encryptMessage, 16, finMessage, 1000, &dwFinSize, CT_HANDSHAKE)) {
			bRet = FALSE;
			goto exit;
		}

		/*
		So far 
		mapSSLLayer[Protocol::SSL_HANDSHAKE] inclueds client hello message, server hello, certificate, server hello done, client key exchange, client finished
		mapSSLLayer[Protocol::SSL_CHANGE_CIPHER_SPEC] includes one change cipher spec 
		*/
		if (!Behavior::CreateSSLMessageByRawdata(mapSSLLayer, finMessage, dwFinSize) ){
			bRet = FALSE;
			goto exit;
		}

		if (mapSSLLayer[pcpp::SSL_HANDSHAKE].find(pcpp::SSL_FINISHED) == mapSSLLayer[pcpp::SSL_HANDSHAKE].end()) {
			bRet = FALSE;
			goto exit;
		}
		lyrClientFinished = (pcpp::SSLHandshakeLayer*)mapSSLLayer[pcpp::SSL_HANDSHAKE][pcpp::SSL_FINISHED];
		
		DWORD dwSndSize = lyrClientKeyExc->getDataLen() + lyrChangeCipherSpec->getDataLen() + lyrClientFinished->getDataLen();

		BYTE* bSendData = new BYTE[dwSndSize];
		DWORD dwTotalLen = 0;

		memcpy(bSendData, lyrClientKeyExc->getData(), lyrClientKeyExc->getDataLen());
		dwTotalLen += lyrClientKeyExc->getDataLen();
		memcpy(bSendData + dwTotalLen, lyrChangeCipherSpec->getData(), lyrChangeCipherSpec->getDataLen());
		dwTotalLen += lyrChangeCipherSpec->getDataLen();
		memcpy(bSendData + dwTotalLen, lyrClientFinished->getData(), lyrClientFinished->getDataLen());

		Utility::FreeOBJ(&bBuffer);
		stRecSize = 0;
		//sendData includes three ssl message: client key exchange, change cipher spec, client hello finished
		if (m_socketIO->SendMsgToServer(bSendData, dwSndSize)) {
			if (!m_socketIO->ReceiveMsgFromServer(bBuffer, stRecSize)) {
				bRet = FALSE;
				goto exit;
			}
		}
		else {
			bRet = FALSE;
			goto exit;
		}

		/*
		So far 
		mapSSLLayer[Protocol::SSL_HANDSHAKE] inclueds client hello message, server hello, certificate, server hello done, client key exchange, client finished, server finished
		mapSSLLayer[Protocol::SSL_CHANGE_CIPHER_SPEC] includes two change cipher spec
		*/
		if (!Behavior::CreateSSLMessageByRawdata(mapSSLLayer, bBuffer, stRecSize)) {
			bRet = FALSE;
			goto exit;
		}

		BYTE bTmpBuffer[1000];
		DWORD dwtmpSize = 0;

		if (mapSSLLayer[pcpp::SSL_HANDSHAKE].find(pcpp::SSL_FINISHED) == mapSSLLayer[pcpp::SSL_HANDSHAKE].end()) {
			bRet = FALSE;
			goto exit;
		}

		//Sometimes the application data will follow the ssl message in the same packet, tyr to find the data and decrypt it.
		lyrServerFinished = (pcpp::SSLHandshakeLayer*)mapSSLLayer[pcpp::SSL_HANDSHAKE][pcpp::SSL_FINISHED];
		dwtmpSize = lyrServerFinished->getDataLen();
		if (!Decrypt(lyrServerFinished->getData(), lyrServerFinished->getDataLen(), bTmpBuffer, 1000, &dwtmpSize)) {
			bRet = FALSE;
			goto exit;
		}

		if (mapSSLLayer.find(pcpp::SSL_APPLICATION_DATA) != mapSSLLayer.end()) {
			for (int i = 0; i != mapSSLLayer[pcpp::SSL_APPLICATION_DATA].size(); ++i) {
				lyrData = mapSSLLayer[pcpp::SSL_APPLICATION_DATA][i];
				dwtmpSize = lyrData->getDataLen();
				if (!Decrypt(lyrData->getData(), lyrData->getDataLen(), bTmpBuffer, 1000, &dwtmpSize)) {
					bRet = FALSE;
					goto exit;
				}
			}
		}

		bRet = TRUE;
		printf("\n\nHandshake with server successfully, you can send request now\n");

	exit:
		if (phHandshakeHash)
		{
			m_pfnTable->FreeObject(phHandshakeHash, 0);
		}
		if (preMasterSecret)
		{
			Utility::FreeOBJ(&preMasterSecret);
			preMasterSecret = NULL;
		}

		if (publicKeyBlob)
		{
			Utility::FreeOBJ(&publicKeyBlob);
			publicKeyBlob = NULL;
		}

		for (auto iteSetLayer = mapSSLLayer.begin(); iteSetLayer != mapSSLLayer.end(); ++iteSetLayer) {
			for (auto iterLayer = iteSetLayer->second.begin(); iterLayer != iteSetLayer->second.end(); ++iterLayer) {
				Utility::FreeOBJ(&(iterLayer->second));
			}
		}

		return bRet;
	}

	BOOL CNcryptSSL::DeInit()
	{
		printf("\n\nDeInit called\n\n");
		BOOL bRet = TRUE;
		SECURITY_STATUS ss;
		m_SndCount = 0;
		m_RcvCount = 0;
		if (m_pfnTable->FreeObject &&
			m_hServerReadKey && m_hServerWriteKey && m_hClientReadKey && m_hClientWriteKey)
		{
			// We only use Client Write and Server Read, log 2 only but free all
			ss = m_pfnTable->FreeObject(m_hServerReadKey, 0);
			if (!(SEC_SUCCESS(ss))) bRet = FALSE;
			ss = m_pfnTable->FreeObject(m_hServerWriteKey, 0);
			if (!(SEC_SUCCESS(ss))) bRet = FALSE;
			ss = m_pfnTable->FreeObject(m_hClientReadKey, 0);
			if (!(SEC_SUCCESS(ss))) bRet = FALSE;
			ss = m_pfnTable->FreeObject(m_hClientWriteKey, 0);
			if (!(SEC_SUCCESS(ss))) bRet = FALSE;
			ss = m_pfnTable->FreeObject(m_hSslProvider, 0);
			if (!(SEC_SUCCESS(ss))) bRet = FALSE;
		}
		else
		{
			bRet = FALSE;
		}

		return bRet;
	}

	VOID PrintSecurityStatusMessage(_TCHAR *funcName, SECURITY_STATUS ss)
	{
		_TCHAR *pwszStatusDesc = NULL;

		switch (ss)
		{
		case SEC_E_INVALID_HANDLE:
			pwszStatusDesc = _T("SEC_E_INVALID_HANDLE");
			break;
		case NTE_PERM:
			pwszStatusDesc = _T("NTE_PERM");
			break;
		}

		_tprintf(_T("%s %s"), funcName, SEC_SUCCESS(ss) ? _T("success") : _T("failed"));
		if (pwszStatusDesc)
			_tprintf(_T(", status = %s"), pwszStatusDesc);
		else
			_tprintf(_T(", status = 0x%08x"), ss);

		_tprintf(_T("\n"));
	}

	BOOL CNcryptSSL::Encrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen, DWORD type)
	{
		SECURITY_STATUS ss;

		/*
		Before calling EncryptPacket function need to cauclate the size of data encrypted, 
		due to real edge the parameter outSize passed into SSLEncryptPacket  will equal the *dwWriteen
		*/

		if (inSize < 28) {
			if (inSize < 12) {
				outSize = 53;
			}
			else {
				outSize = 69;
			}
		}
		else {
			outSize = (inSize - 28) / 16 * 16 + 85;
		}
		ss = m_pfnTable->EncryptPacket(m_hSslProvider, m_hClientWriteKey, inBuffer, inSize, outBuffer, outSize, dwWriteen, m_SndCount, type, 0);
		
		if (!SEC_SUCCESS(ss))
		{
			PrintSecurityStatusMessage(_T("SslEncryptPacket"), ss);
			SetLastError(ss);
			Utility::WriteFile("rsp.txt", (BYTE*)"SSLEncryptPacket encrypt failed", strlen("SSLEncryptPacket encrypt failed"));
			return FALSE;
		}
		NCRYPT_SSL_CIPHER_SUITE aa;
		++m_SndCount;
		return TRUE;
	}

	BOOL CNcryptSSL::Decrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen)
	{
		SECURITY_STATUS ss;


		ss = m_pfnTable->DecryptPacket(m_hSslProvider, m_hClientReadKey, inBuffer, inSize, outBuffer, outSize, dwWriteen, m_RcvCount, 0);

		if (!SEC_SUCCESS(ss))
		{
			printf("\n\nMessage count: %d\n", m_RcvCount);
			PrintSecurityStatusMessage(_T("SslDecryptPacket"), ss);
			SetLastError(ss);
			*dwWriteen = -1; // a hack
			Utility::WriteFile("rsp.txt", (BYTE*)"SSLDecryptPacket decrypt failed", strlen("SSLDecryptPacket decrypt failed"));
			return FALSE;
		}
		++m_RcvCount;
		return TRUE;
	}

	CSSL* Behavior::CreateNCryptSSLInstance()
	{
		return new CNcryptSSL();
	}
}
