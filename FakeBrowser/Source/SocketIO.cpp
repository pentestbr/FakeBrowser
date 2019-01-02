#include "stdafx.h"
#include <ws2tcpip.h>
#include <vector>
#include <regex>
#include <WinSock2.h>

#include "SocketIO.h"
#include "SSLLibrary.h"
#include "Utility.h"

namespace Behavior
{
	//Connect to server
	BOOL SocketIO::ConnectToServer(std::string sUrl)
	{
		int iResult;
		
		// Initialize Winsock
		iResult = WSAStartup(MAKEWORD(2, 2), &m_wsaData);
		if (iResult != 0) {
			printf("WSAStartup failed: %d\n", iResult);
			return FALSE;
		}

		char *pCIpAdress = new char[INET_ADDRSTRLEN];
		struct addrinfo *result = NULL;
		if (!Utility::ResolveURL(sUrl, result, pCIpAdress)) {
			return FALSE;
		}

		printf("\nConnect to Server: %s\n", pCIpAdress);
		Utility::FreeOBJ(&pCIpAdress);
		// Create a SOCKET for connecting to server
		m_skSocket = socket(result->ai_family, result->ai_socktype,
			result->ai_protocol);

		if (m_skSocket == INVALID_SOCKET) {
			printf("Error at socket(): %ld\n", WSAGetLastError());
			freeaddrinfo(result);
			WSACleanup();
			return FALSE;
		}

		// Connect to server.
		iResult = connect(m_skSocket, result->ai_addr, (int)result->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(m_skSocket);
			m_skSocket = INVALID_SOCKET;
			printf("\n\nUnable to connect to server!\n");
			return FALSE;
		}

		// Should really try the next address returned by getaddrinfo
		// if the connect call failed
		// But for this simple example we just free the resources
		// returned by getaddrinfo and print an error message

		freeaddrinfo(result);

		if (m_skSocket == INVALID_SOCKET) {
			printf("\n\nUnable to connect to server!\n");
			WSACleanup();
			return FALSE;
		}

		return TRUE;
	}

	BOOL SocketIO::Send(BYTE* bData, size_t stSize)
	{
		BOOL ret = FALSE;
		if (m_pCSSL == nullptr) {
			ret = SendMsgToServer(bData, stSize);
		}
		else {
			ret = EncryptAndSend(bData, stSize);
		}

		return ret;
	}

	BOOL SocketIO::Receive(BYTE* &bResponse, size_t &stRecSize)
	{
		BOOL ret = FALSE;
		if (m_pCSSL == nullptr) {
			ret = ReceiveMsgFromServer(bResponse, stRecSize);
		}
		else {
			ret = ReceiveAndDecrypt(bResponse, stRecSize);
		}

		return ret;
	}

	//Send packet to server
	BOOL SocketIO::SendMsgToServer(BYTE* bData, size_t stSize)
	{
		int iResult;
		// Send an initial buffer
		iResult = send(m_skSocket, (char*)bData, stSize, 0);
		if (iResult == SOCKET_ERROR) {
			printf("\n\nsend failed: %d\n", WSAGetLastError());
			return FALSE;
		}
		//Sleep(500);
		return TRUE;
	}

	//Receive packet from server
	BOOL SocketIO::ReceiveMsgFromServer(BYTE* &bBuffer, size_t &stRecSize)
	{
#define DEFAULT_BUFLEN 1024
		int iResult;
		int recvbuflen = DEFAULT_BUFLEN;
		BYTE recvbuf[DEFAULT_BUFLEN];
		int bufferSize = 100000;
		BYTE *bPacket = new BYTE[bufferSize];
		BYTE* pPacket = bPacket;
		BOOL bRet = FALSE, isUnknownContentLenth = FALSE;

		// Receive data until the server closes the connection
		DWORD timeout = 300;
		setsockopt(m_skSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
		//printf("\n\nWait for server response...\n");

		BOOL isFirst = TRUE;
		do {
			iResult = recv(m_skSocket, (char*)recvbuf, recvbuflen, 0);
			if (iResult == SOCKET_ERROR || iResult == 0) {
				if (WSAGetLastError() == WSAETIMEDOUT || iResult == 0) {
					if (pPacket - bPacket == 0) {
						continue;
					}
					break;
				}
				else {
					printf("\n\nReceive from server failed\n");
					bRet = FALSE;
					goto exit;
				}
			}

			if ((pPacket + iResult) - bPacket > bufferSize) {
				while (bufferSize < ((pPacket + iResult) - bPacket))
					bufferSize *= 2;
				BYTE* buffer2 = new BYTE[bufferSize];
				memcpy(buffer2, bPacket, pPacket - bPacket);
				pPacket = buffer2 + (pPacket - bPacket);
				Utility::FreeOBJ(&bPacket);
				bPacket = buffer2;
			}

			memcpy(pPacket, recvbuf, iResult);

			//printf("%d,", iResult);
			pPacket += iResult;

			isFirst = FALSE;
		} while (TRUE);

		stRecSize = pPacket - bPacket;
		bBuffer = new BYTE[stRecSize];
		memcpy(bBuffer, bPacket, stRecSize);
		//printf("\n\nTotal Receive: %d bytes\n", stRecSize);
		bRet = TRUE;

	exit:
		Utility::FreeOBJ(&bPacket);
		return bRet;
	}

	//Before calling SendMsgToServer function to send packet to server, calling Encrypt function to encrypt the packet
	BOOL SocketIO::EncryptAndSend(BYTE* bData, size_t stSize)
	{
		if (m_pCSSL == nullptr) {
			printf("\nSSL library is NULL\n");
			return FALSE;
		}

		BYTE bBuffer[1000];
		DWORD dwOutSize = 0;
		if (!m_pCSSL->Encrypt(bData, stSize, bBuffer, 1000, &dwOutSize, CT_APPLICATIONDATA))
			return FALSE;
		SendMsgToServer(bBuffer, dwOutSize);
		return TRUE;
	}

	//Call Decrypt function to decrypt packet that receiving from ReceiveMsgFromServer function
	BOOL SocketIO::ReceiveAndDecrypt(BYTE* &bResponse, size_t &stRecSize)
	{
		if (m_pCSSL == nullptr) {
			printf("\nSSL library is NULL\n");
			return FALSE;
		}

		BYTE* bPacket;
		size_t stOutSize = 0;
		BOOL bRet = FALSE, isUnknownContentLenth = FALSE;;
		DWORD dwTotalSize = 0, dwContentLen = 0, dwHeaderSize = 0, dwBufferSize = 100000;
		BYTE* bBuffer = new BYTE[dwBufferSize];
		std::map<pcpp::SSLRecordType, std::map<size_t, pcpp::SSLLayer*>> mapSSLLayer;
		pcpp::SSLLayer* lyrData = nullptr;

		if (!ReceiveMsgFromServer(bPacket, stOutSize)) {
			bRet = FALSE;
			goto exit;
		}

		if (!Behavior::CreateSSLMessageByRawdata(mapSSLLayer, bPacket, stOutSize)) {
			bRet = FALSE;
			goto exit;
		}

		for (int i = 0; i != mapSSLLayer[pcpp::SSL_APPLICATION_DATA].size(); ++i) {
			lyrData = mapSSLLayer[pcpp::SSL_APPLICATION_DATA][i];
			//outSize should bigger or equal the data length encrypted, otherwise eyes will not send pre decrypt event on Edge
			stOutSize = lyrData->getDataLen();

			BYTE decrpytArr[100000];
			if (!m_pCSSL->Decrypt(lyrData->getData(), lyrData->getDataLen(), decrpytArr, 100000, (DWORD*)&stOutSize)) {
				printf("\n\nDecrypt packet failed\n");
				bRet = FALSE;
				goto exit;
			}

			if (dwTotalSize + stOutSize > dwBufferSize) {
				while (dwBufferSize < (dwTotalSize + stOutSize))
					dwBufferSize *= 2;

				BYTE* bBuffer2 = new BYTE[dwBufferSize];
				memcpy(bBuffer2, bBuffer, dwTotalSize);
				Utility::FreeOBJ(&bBuffer);
				bBuffer = bBuffer2;
			}

			/*if (i==0) {
				std::regex txt_regex("^.*?Content-Length\:\\s(\\d+)");
				std::smatch base_match;
				std::string rspHeader = (const char*)decrpytArr;
				std::regex_search(rspHeader, base_match, txt_regex);
	
				if (base_match.size()) {
					contentLen = std::stoi(base_match[1]);
				}
				else {
					printf("\n\nCannot find Content-Length from response header\n");
					isUnknownContentLenth = TRUE;
				}
				headerSize = rspHeader.find("\r\n\r\n") + 4;
			}*/

			memcpy(bBuffer + dwTotalSize, decrpytArr, stOutSize);
			dwTotalSize += stOutSize;
		}

		/*if (!isUnknownContentLenth) {
			if (totalSize - headerSize < contentLen) {
				printf("\n\nReceive bytes(%d) less than Content-Length(%d)\n", totalSize - headerSize, contentLen);
				bRet = FALSE;
				goto exit;
			}
		}
		else {
			if (buffer[totalSize - 5] == 0x30 && buffer[totalSize - 4] == 0xd && buffer[totalSize - 3] == 0xa && buffer[totalSize - 2] == 0xd && buffer[totalSize - 1] == 0xa) {
				printf("\n\nThe response is corrupt\n", totalSize - headerSize, contentLen);
				bRet = FALSE;
				goto exit;
			}
		}*/

		Utility::FreeOBJ(&bResponse);

		stRecSize = dwTotalSize;
		bResponse = new BYTE[stRecSize];
		memcpy(bResponse, bBuffer, stRecSize);
		bRet = TRUE;

	exit:
		for (auto iteSetLayer = mapSSLLayer.begin(); iteSetLayer != mapSSLLayer.end(); ++iteSetLayer) {
			for (auto iterLayer = iteSetLayer->second.begin(); iterLayer != iteSetLayer->second.end(); ++iterLayer) {
				Utility::FreeOBJ(&(iterLayer->second));
			}
		}

		if (!bRet)
			Utility::FreeOBJ(&bBuffer);

		return bRet;
	}

	void SocketIO::CloseConnection()
	{
		closesocket(m_skSocket);
		WSACleanup();
		m_pCSSL = nullptr;
	}
}