#include "stdafx.h"
#include <ws2tcpip.h>
#include <winsock2.h>
#include <algorithm>
#include <regex>

#include "SSLLibrary_nss3.h"
#include "Utility.h"

namespace Behavior {


	HMODULE CNSS3SSL::m_hModule = NULL;
	NSS3FunctionInterface CNSS3SSL::m_pfnTable = { NULL };

	int myAuthCertificate(void *arg, PRFileDesc *socket, BOOL checksig, BOOL isServer)
	{
		return 0;
	}

	CNSS3SSL::CNSS3SSL()
	{
		//cbClientToServerBuffer = 4096;
		//pClientToServerBuffer = new BYTE[cbClientToServerBuffer];
	}

	CNSS3SSL::~CNSS3SSL()
	{

	}

	BOOL CNSS3SSL::InitLibrary()
	{
		if (m_hModule == NULL)
		{
			m_hModule = LoadLibrary(_T("NSS3.DLL"));
			if (m_hModule == NULL) {
				printf("Init failed: Cannot find NSS3.DLL");
				return FALSE;
			}

			m_pfnTable.fpnPR_CreatePipe = (PR_CreatePipeT)GetProcAddress(m_hModule, "PR_CreatePipe");
			m_pfnTable.pfnPR_GetUniqueIdentity = (PR_GetUniqueIdentityT)GetProcAddress(m_hModule, "PR_GetUniqueIdentity");
			m_pfnTable.pfnPR_GetNameForIdentity = (PR_GetNameForIdentityT)GetProcAddress(m_hModule, "PR_GetNameForIdentity");
			m_pfnTable.pfnPR_Read = (PR_ReadT)GetProcAddress(m_hModule, "PR_Read");
			m_pfnTable.pfnPR_Write = (PR_WriteT)GetProcAddress(m_hModule, "PR_Write");
			m_pfnTable.pfnPR_GetError = (PR_GetErrorT)GetProcAddress(m_hModule, "PR_GetError");
			m_pfnTable.pfnPR_Close = (PR_CloseT)GetProcAddress(m_hModule, "PR_Close");
			m_pfnTable.pfnPR_AllocFileDesc = (PR_AllocFileDescT)GetProcAddress(m_hModule, "PR_AllocFileDesc");
			m_pfnTable.pfnSSL_ImportFD = (SSL_ImportFDT)GetProcAddress(m_hModule, "SSL_ImportFD");
			m_pfnTable.pfnPR_GetHostByName = (PR_GetHostByNameT)GetProcAddress(m_hModule, "PR_GetHostByName");
			m_pfnTable.pfnPR_EnumerateHostEnt = (PR_EnumerateHostEntT)GetProcAddress(m_hModule, "PR_EnumerateHostEnt");
			m_pfnTable.pfnPR_NewTCPSocket = (PR_NewTCPSocketT)GetProcAddress(m_hModule, "PR_NewTCPSocket");
			m_pfnTable.pfnPR_Connect = (PR_ConnectT)GetProcAddress(m_hModule, "PR_Connect");
			m_pfnTable.pfnSSL_ForceHandshake = (SSL_ForceHandshakeT)GetProcAddress(m_hModule, "SSL_ForceHandshake");
			m_pfnTable.pfnSSL_ResetHandshake = (SSL_ResetHandshakeT)GetProcAddress(m_hModule, "SSL_ResetHandshake");
			m_pfnTable.pfnSSL_OptionSet = (SSL_OptionSetT)GetProcAddress(m_hModule, "SSL_OptionSet");
			m_pfnTable.pfnSSL_SetURL = (SSL_SetURLT)GetProcAddress(m_hModule, "SSL_SetURL");
			m_pfnTable.pfnNSS_SetDomesticPolicy = (NSS_SetDomesticPolicyT)GetProcAddress(m_hModule, "NSS_SetDomesticPolicy");
			m_pfnTable.pfnSSL_CipherPrefSetDefault = (SSL_CipherPrefSetDefaultT)GetProcAddress(m_hModule, "SSL_CipherPrefSetDefault");
			m_pfnTable.pfnPR_Init = (PR_InitT)GetProcAddress(m_hModule, "PR_Init");
			m_pfnTable.pfnNSS_NoDB_Init = (NSS_NoDB_InitT)GetProcAddress(m_hModule, "NSS_NoDB_Init");
			m_pfnTable.pfnSSL_AuthCertificateHook = (SSL_AuthCertificateHookT)GetProcAddress(m_hModule, "SSL_AuthCertificateHook");
		}

		m_pfnTable.pfnPR_Init(1, 1, 1);
		int ss = m_pfnTable.pfnNSS_NoDB_Init(NULL);
		if (ss != 0) {
			printf("pfnNSS_NoDB_Init failed error: %d", m_pfnTable.pfnPR_GetError());
			return FALSE;
		}

		return TRUE;
	}

	BOOL CNSS3SSL::Init()
	{
		// loads ncrypt function pointer
		
		return InitLibrary();
	}

	BOOL CNSS3SSL::Connect()
	{
		BOOL bRet = TRUE;
		int ss = 0;

		PRHostEnt hostentry;
		char buf[1000];
		int bufsize = 1000;
		ss = m_pfnTable.pfnPR_GetHostByName(m_hostName.c_str(), buf, bufsize, &hostentry);
		printf("%s\n", hostentry.h_name);
		if (ss == -1) {
			printf("pfnPR_GetHostByName failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		PRNetAddr addr;
		ss = m_pfnTable.pfnPR_EnumerateHostEnt(0, &hostentry, std::stoi(m_port), &addr);
		if (ss == -1) {
			printf("pfnPR_EnumerateHostEnt failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		//if pfnPR_EnumerateHostEnt resolves IP address failed, use windows api to resolve IP address
		if (!addr.inet.ip) {
			struct addrinfo *result = NULL,
				*ptr = NULL,
				hints;

			ZeroMemory(&hints, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;

			// Resolve the server address and port
			int iResult = getaddrinfo(m_hostName.c_str(), m_port.c_str(), &hints, &result);
			if (iResult != 0) {
				printf("\n\ngetaddrinfo failed: %s\n", m_hostName.c_str());
				WSACleanup();
				return FALSE;
			}
			struct sockaddr_in  *sockaddr_ipv4 = nullptr;
			for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
				switch (ptr->ai_family)
				{
				case AF_INET:
					sockaddr_ipv4 = (struct sockaddr_in *) result->ai_addr;
					addr.inet.ip = static_cast<uint32_t>(sockaddr_ipv4->sin_addr.s_addr);
					addr.inet.port = static_cast<uint32_t>(sockaddr_ipv4->sin_port);
					break;
				default:
					break;
				}
			}
			if (!addr.inet.ip) {
				printf("Resolve IP address failed");
				return FALSE;
			}
		}

		ss = m_pfnTable.pfnPR_Connect(m_SSLSocket, &addr, PR_INTERVAL_NO_TIMEOUT);
		if (ss == -1) {
			printf("pfnPR_Connect failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

	exit:
		return bRet;
	}

	BOOL CNSS3SSL::Handshake()
	{
		printf("\n\nSSL handshake with %s", m_hostName.c_str());

		BOOL bRet = TRUE;
		PRFileDesc* pSocket = nullptr;
		int ss = 0;
		std::string strIpAddr = "";
		
		pSocket = m_pfnTable.pfnPR_NewTCPSocket();
		if (pSocket == NULL) {
			printf("pfnPR_NewTCPSocket failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		m_SSLSocket = m_pfnTable.pfnSSL_ImportFD(NULL, pSocket);
		if (m_SSLSocket == NULL) {
			printf("pfnSSL_ImportFD failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		ss = m_pfnTable.pfnSSL_OptionSet(m_SSLSocket, SSL_SECURITY, TRUE);
		if (ss == -1) {
			printf("pfnSSL_OptionSet failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		ss = m_pfnTable.pfnSSL_OptionSet(m_SSLSocket, SSL_HANDSHAKE_AS_CLIENT, TRUE);
		if (ss == -1) {
			printf("pfnSSL_OptionSet failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		ss = m_pfnTable.pfnSSL_AuthCertificateHook(m_SSLSocket,(SSLAuthCertificate)myAuthCertificate,NULL);
		if (ss == -1) {
			printf("pfnSSL_AuthCertificateHook failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		ss = m_pfnTable.pfnSSL_SetURL(m_SSLSocket, m_hostName.c_str());
		if (ss == -1) {
			printf("pfnSSL_SetURL failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		ss = m_pfnTable.pfnNSS_SetDomesticPolicy();
		if (ss != 0) {
			printf("pfnSSL_ForceHandshake failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		if (!Connect()) {
			bRet = FALSE;
			goto exit;
		}

		ss = m_pfnTable.pfnSSL_ForceHandshake(m_SSLSocket);
		if (ss != 0) {
			printf("pfnSSL_ForceHandshake failed error: %d", m_pfnTable.pfnPR_GetError());
			bRet = FALSE;
			goto exit;
		}

		printf("\n\nHandshake with server successfully, you can send request now\n");

	exit:
		if (!bRet) {
			if (m_SSLSocket) {
				m_pfnTable.pfnPR_Close(m_SSLSocket);
				m_SSLSocket = nullptr;
			}
			else {
				if (pSocket) {
					m_pfnTable.pfnPR_Close(pSocket);
					pSocket = nullptr;
				}
			}
		}

		return bRet;
	}

	BOOL CNSS3SSL::ReceiveAndDecrypt(BYTE* &response, size_t &recSize)
	{
		char recBuf[1000];
		int size = 1000;
		int iResult = 0;
		int countRead = 0;
		int bufferSize = 100000;
		int contentLen = 0;
		int times = 0;
		int headerSize = 0;
		BYTE *packet = new BYTE[bufferSize];
		BYTE *p = packet;
		BOOL isUnknownContentLenth = FALSE;

		BOOL isFirst = TRUE;
		while (TRUE) {
			iResult = m_pfnTable.pfnPR_Read(m_SSLSocket, recBuf, size);
			if (iResult == 0) {
				break; /* EOF */
			}

			if (iResult < 0) {
				printf("Got some error");
				DeInit();
				return FALSE;
			}

			if ((p + iResult) - packet > bufferSize) {
				while (bufferSize < ((p + iResult) - packet))
					bufferSize *= 2;
				BYTE* buffer2 = new BYTE[bufferSize];
				memcpy(buffer2, packet, p - packet);
				p = buffer2 + (p - packet);
				Utility::FreeOBJ(&packet);
				packet = buffer2;
			}

			memcpy(p, recBuf, iResult);
			if (isFirst) {
				std::regex txt_regex("^.*?Content-Length\:\\s(\\d+)");
				std::smatch base_match;
				std::string rspHeader = recBuf;
				std::regex_search(rspHeader, base_match, txt_regex);
				if (base_match.size()) {
					contentLen = std::stoi(base_match[1]);
				}
				else {
					printf("\n\nCannot find Content-Length from response header\n");
					isUnknownContentLenth = TRUE;
				}
				headerSize = rspHeader.find("\r\n\r\n") + 4;
			}

			p += iResult;
			if (!isUnknownContentLenth) {
				if (p - packet - headerSize == contentLen) {
					break;
				}
			}
			else {
				if (recBuf[iResult - 5] == 0x30 && recBuf[iResult - 4] == 0xd && recBuf[iResult - 3] == 0xa && recBuf[iResult - 2] == 0xd && recBuf[iResult - 1] == 0xa)
					break;
			}
			isFirst = FALSE;
			times++;
		}
		recSize = p - packet;
		response = new BYTE[recSize];
		memcpy(response, packet, recSize);
		Utility::FreeOBJ(&packet);
		return TRUE;
	}

	BOOL CNSS3SSL::get(std::string url, BYTE* &response, size_t &recSize)
	{
		if (!Init()) {
			return FALSE;
		}
		m_url = url;

		BOOL isSuccess = FALSE;
		BOOL isMoved = TRUE;
		std::string strUrl = url;

		int numBytes;

		int times = 0;
		do {
			if (!Utility::ParseURLInfo(strUrl, m_protocol, m_hostName, m_port, m_path)) {
				return FALSE;
			}

			if (m_protocol=="https") {
				if (!Handshake()) {
					DeInit();
					continue;
				}
			}
			else {
				m_SSLSocket = m_pfnTable.pfnPR_NewTCPSocket();
				if (m_SSLSocket == NULL) {
					printf("pfnPR_NewTCPSocket failed error: %d", m_pfnTable.pfnPR_GetError());
					continue;
				}

				if (!Connect()) {
					DeInit();
					continue;
				}
			}

			while (isMoved) {
				std::string hostName = m_hostName;
				if (m_port != "80" && m_port != "443") {
					hostName += ":" + m_port;
				}
				std::string request = "GET ";
				request += m_path;
				request += " HTTP/1.1\r\nHOST: ";
				request += hostName;
				request += "\r\n";
				request += "User-agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36\r\n\r\n";

				printf("\n\nSend request to server: %s\n", request.c_str());
				numBytes = m_pfnTable.pfnPR_Write(m_SSLSocket, (void*)request.c_str(), request.length());
				if (numBytes <= 0) {
					printf("pfnPR_Write failed error: %d", m_pfnTable.pfnPR_GetError());
					DeInit();
					continue;
				}
				if (ReceiveAndDecrypt(response,recSize)) {
					std::regex txt_regex("^.*?Location\:\\s([^\r]+)");
					std::smatch base_match;
					std::string rsp = (const char*)response;
					std::regex_search(rsp, base_match, txt_regex);

					if (base_match.size()) {
						std::string redirectUrl = base_match[1];
						std::string curProtocol = m_protocol;
						if (!Utility::ParseURLInfo(redirectUrl, m_protocol, m_hostName, m_port, m_path)) {
							redirectUrl = strUrl + redirectUrl;
							if (!Utility::ParseURLInfo(redirectUrl, m_protocol, m_hostName, m_port, m_path)) {
								return FALSE;
							}
						}

						if (response != nullptr) {
							Utility::FreeOBJ(&response);
							response = nullptr;
							recSize = 0;
						}
						//HSTS
						if (curProtocol != m_protocol) {
							isMoved = FALSE;
							isSuccess = FALSE;
							strUrl = redirectUrl;
						}

						printf("\n\nRedirect to %s\n", redirectUrl.c_str());

					}
					else {
						isMoved = FALSE;
						isSuccess = TRUE;
						break;
					}
				}
				
			}
			if (isSuccess)
				break;

			DeInit();

			printf("\n\nSleep one second\n");
			isMoved = TRUE;
			Sleep(1000);
		} while (times++ < 3);

		DeInit();

		return isSuccess;
	}

	BOOL CNSS3SSL::DeInit()
	{
		SECURITY_STATUS ss;
		BOOL bRet = TRUE;
		if (m_SSLSocket) {
			m_pfnTable.pfnPR_Close(m_SSLSocket);
			m_SSLSocket = nullptr;
		}
		else
		{
			bRet = FALSE;
		}

		return bRet;
	}

	CNSS3SSL *CreateNSS3SSLInstance()
	{
		return new CNSS3SSL();
	}
}