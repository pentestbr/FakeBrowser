// Performance.cpp : Defines the entry point for the console application.
#include "stdafx.h"
#include <time.h>
#include <string>
#include <fstream>
#include <codecvt>
#include <regex>
#include <bitset>
#include <thread> 

#include "SSLLibrary.h"
#include "SSLLibrary_ncrypt.h"
#include "SSLLibrary_Chrome.h"
#include "SSLLibrary_secur32.h"
#include "SSLLibrary_nss3.h"
#include "SocketIO.h"
#include "Utility.h"
#include "Protocol.h"

bool isEnd = false;

BOOL SendSocks(std::string sProxy, std::string sRemoteUrl, Behavior::SocketIO &skSocket, BYTE* &bResponse, size_t &stRecSize)
{
	std::string sProtocol, sHostName, sPort, sPath;
	if (!Utility::ParseURLInfo(sRemoteUrl, sProtocol, sHostName, sPort, sPath)) {
		return FALSE;
	}

	BYTE* bSocks = nullptr;
	int iSize;
	if (sProxy.find("socks4") != std::string::npos) {
		Protocol::Sock4 sksSocks;
		sksSocks.version = 4;
		sksSocks.command = 1;
		sksSocks.port = htons(atoi(sPort.c_str()));
		sksSocks.name = 0;

		bSocks = (BYTE*)&sksSocks;
		iSize = sizeof(sksSocks);
	}
	else if (sProxy.find("socks5") != std::string::npos) {
		BYTE bSocksAuth[] = { 0x05, 0x01, 0x00 };
		if (skSocket.Send(bSocksAuth, 3)) {
			if (!skSocket.Receive(bResponse, stRecSize)) {
				return FALSE;
			}
		}
		else {
			return FALSE;
		}

		Utility::FreeOBJ(&bResponse);

		Protocol::Sock5 sksSocks;
		sksSocks.version = 5;
		sksSocks.command = 1;
		sksSocks.reserved = 0;
		sksSocks.addressType = 1;
		sksSocks.port = htons(atoi(sPort.c_str()));

		bSocks = (BYTE*)&sksSocks;
		iSize = sizeof(sksSocks);
	}

	addrinfo *result = nullptr;
	char *pCIpAdress = new char[22];
	if (!Utility::ResolveURL(sRemoteUrl, result, pCIpAdress)) {
		return FALSE;
	}

	char delims[] = ".";
	char *strToken = nullptr;
	char *next_token = nullptr;

	strToken = strtok_s(pCIpAdress, delims, &next_token);

	int i = 4;
	while (strToken != NULL) {
		bSocks[i] = atoi(strToken);
		++i;
		strToken = strtok_s(nullptr, delims, &next_token);
	}

	printf("\n\nSend socks packet\n\n");
	if (skSocket.Send(bSocks, iSize)) {
		if (!skSocket.Receive(bResponse, stRecSize)) {
			return FALSE;
		}
	}
	else {
		return FALSE;
	}

	return TRUE;
}

BOOL SendHttp2(std::string sUrl, Behavior::SocketIO &skSocket, Behavior::CSSL* &pSSLLib, BYTE* &bResponse, size_t &stRecSize, BOOL isSndTogether)
{
	std::string sProtocol = "", sHostName, sPort, sPath;
	if (!Utility::ParseURLInfo(sUrl, sProtocol, sHostName, sPort, sPath)) {
		return FALSE;
	}

	BOOL isHttps = FALSE;

	BYTE magic[] = {
		0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
		0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x04, 0x00,
		0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0x00, 0x01,
	};

	printf("\nSend Magic, setting and window update frames\n");
	if (skSocket.Send(magic, 64)) {
		if (!skSocket.Receive(bResponse, stRecSize)) {
			return FALSE;
		}
	}
	else {
		return FALSE;
	}

	BYTE buffer[1000];
	DWORD outSize = 0;
	if (isSndTogether) {
		BYTE setting[] = {
			0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x04, 0x00, 0x60, 0x00, 0x00 };

		if (!pSSLLib->Encrypt(setting, 27, buffer, 1000, &outSize, CT_APPLICATIONDATA)) {
			return FALSE;
		}
	}

	nghttp2_nv nva1[] = {
		MAKE_NVT(":method", "GET"),
		MAKE_NVT(":authority", sHostName.c_str()),MAKE_NVT(":scheme", "https"),
		MAKE_NVT(":path", sPath.c_str()), MAKE_NVT("user-agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36"),
		MAKE_NVT("accept-encoding", "deflate") };

	/* Encode and decode 1st header set */
	uint8_t *buf;
	size_t outlen;
	size_t sum;
	Utility::Deflate(nva1, sizeof(nva1) / sizeof(nva1[0]), buf, outlen, sum);

	BYTE* sendData = new BYTE[outlen + 14]
	{
		0x00,0x00,BYTE(outlen + 5),0x01,0x25,0x00,0x00,0x00,0x01,0x80,0x00,0x00,0x00,0xff
	};

	memcpy(sendData + 14, buf, outlen);

	BYTE buffer2[1000];
	DWORD outSize2 = 0;

	if (!pSSLLib->Encrypt(sendData, outlen + 14, buffer2, 1000, &outSize2, CT_APPLICATIONDATA)) {
		return FALSE;
	}

	BYTE* sendData2 = nullptr;
	size_t sendSize = 0;

	if (isSndTogether) {
		sendSize = outSize + outSize2;
		sendData2 = new BYTE[sendSize];
		memcpy(sendData2, buffer, outSize);
		memcpy(sendData2 + outSize, buffer2, outSize2);
	}
	else {
		sendSize = outSize2;
		sendData2 = new BYTE[sendSize];
		memcpy(sendData2, buffer2, sendSize);
	}

	printf("\nSend setting and request header frames, size: %d\n", sendSize);
	if (skSocket.SendMsgToServer(sendData2, sendSize)) {
		if (!skSocket.Receive(bResponse, stRecSize)) {
			return FALSE;
		}
	}
	else {
		return FALSE;
	}

	return TRUE;
}

BOOL SendHttp11(std::string sProxy, BOOL isProxy, std::string sUrl, Behavior::SocketIO &skSocket, Behavior::CSSL* &pSSLLib, BYTE* &bResponse, size_t &stRecSize)
{
	std::string sProtocol = "", sHostName, sPort, sPath;
	if (!Utility::ParseURLInfo(sUrl, sProtocol, sHostName, sPort, sPath)) {
		return FALSE;
	}

	BOOL isMoved = TRUE;
	BOOL isHSTS = FALSE;
	BOOL isHttp2 = FALSE;
	std::string oriUrl = sUrl;
	while (isMoved) {
		/*
		Remove the last slash from oriUrl to avoid adding redirect path caused slash added twice
		e.g. oriUrl = https://mail.google.com/ redirect path = /mail/
		oriUrl + redirect path = https://mail.google.com//mail/
		*/
		if (oriUrl.back() == '/') {
			oriUrl.pop_back();
		}

		if (sPort != "80" && sPort != "443") {
			sHostName += ":" + sPort;
		}

		std::string request = "GET ";
		request += sPath;
		request += " HTTP/1.1\r\nHOST: ";
		request += sHostName;
		request += "\r\n";
		request += "User-agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36\r\n\r\n";
		printf("\n\nSend request to server: %s\n", request.c_str());
		if (skSocket.Send((BYTE*)request.c_str(), request.length())) {
			if (skSocket.Receive(bResponse, stRecSize)) {
				// if find the "Location: xxx" from the response header, we need to do the redirect
				std::regex txt_regex("^.*?Location\:\\s([^\r]+)");
				std::smatch base_match;
				std::string rsp = (const char*)bResponse;
				std::regex_search(rsp, base_match, txt_regex);

				if (base_match.size()) {
					std::string redirectUrl = base_match[1];
					std::string curProtocol = sProtocol;

					if (!Utility::ParseURLInfo(redirectUrl, sProtocol, sHostName, sPort, sPath)) {
						/*
						if the redirectUrl is only the path, combine the path with the original url
						e.g. Get https://mail.google.com, the redirectUrl will be /mail/
						so we should combine the path with the origina url like https://mail.google.com + /mail/
						and the redirectUrl will become https://mail.google.com/mail/
						*/
						redirectUrl = oriUrl + redirectUrl;
						if (!Utility::ParseURLInfo(redirectUrl, sProtocol, sHostName, sPort, sPath)) {
							return FALSE;
						}
					}

					Utility::FreeOBJ(&bResponse);

					//HSTS
					if (curProtocol != sProtocol) {
						if (sProtocol == "https") {
							skSocket.CloseConnection();
							Sleep(1000);
							if (!isProxy) {
								if (!skSocket.ConnectToServer(redirectUrl)) {
									return FALSE;
								}
							}
							else {
								if (!skSocket.ConnectToServer(sProxy)) {
									return FALSE;
								}

								if (!SendSocks(sProxy, redirectUrl, skSocket, bResponse, stRecSize)) {
									return FALSE;
								}
							}

							pSSLLib->SetSocket(&skSocket);

							if (!pSSLLib->Handshake(isHttp2)) {
								return FALSE;
							}
							skSocket.SetSSLLib(pSSLLib);
							oriUrl = redirectUrl;
							continue;
						}
					}

					printf("\n\nRedirect to %s\n", redirectUrl.c_str());
				}
				//Success
				else {
					break;
				}
			}
			//Failed
			else {
				return FALSE;
			}
		}
		//Failed
		else {
			return FALSE;
		}
	}

	return TRUE;
}

void ReceiveRromServer(Behavior::SocketIO &socket)
{
	BYTE* bResponse = nullptr;
	size_t stRecSize = 0;

	while (!isEnd) {
		if (socket.Receive(bResponse, stRecSize)) {
			std::regex txt_regex("^.*?\"message\"\:\"([^\"]+)");
			std::smatch base_match;
			std::string rsp = (const char*)bResponse;
			std::regex_search(rsp, base_match, txt_regex);

			if (base_match.size()) {
				std::string strServerMsg = base_match[1];
				printf("Server: %s\n\n", strServerMsg.c_str());
			}
		}
	}
}

BOOL SendWebSocket(std::string url, Behavior::SocketIO &socket, BYTE* &response, size_t &recSize)
{
	std::string sProtocol = "", sHostName, sPort, sPath;
	if (!Utility::ParseURLInfo(url, sProtocol, sHostName, sPort, sPath)) {
		return FALSE;
	}
	BOOL isMoved = TRUE;
	BOOL isHSTS = FALSE;
	BOOL isHttp2 = FALSE;
	std::string strOriUrl = url;

	if (sPort != "80" && sPort != "443") {
		sHostName += ":" + sPort;
	}

	std::string request = "GET ";
	request += sPath;
	request += " HTTP/1.1\r\nHOST: ";
	request += sHostName;
	request += "\r\n";
	request += "Connection: Upgrade\r\n";
	request += "Upgrade: websocket\r\n";
	request += "Sec-WebSocket-Version: 13\r\n";
	request += "User-agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36\r\n";
	request += "Sec-WebSocket-Key: /G4E8FcbWMqIteAA4mvP6g==\r\n\r\n";
	printf("\n\nSend request to server: %s\n", request.c_str());

	//Handshake
	if (socket.Send((BYTE*)request.c_str(), request.length())) {
		if (socket.Receive(response, recSize)) {
			printf("Handshake successful!!\nYou can send message now: ");
			//Utility::WriteFile("rsp.txt", response, recSize);
			std::thread thdReceive(ReceiveRromServer, socket);
			//send message
			while (true)
			{
				char caMsg[100];
				fgets(caMsg, 100, stdin);
				std::string strMsg(caMsg);
				
				printf("You: %s\n", strMsg.c_str());
				const int MAXMSGSIZE = 64;
				BYTE* bEnMsg = nullptr;
				char const maskkey[5] = "1234";
				std::string jsonmsg = "{\"message\":\"";
				jsonmsg += strMsg;
				jsonmsg += "\",\"color\":\"15E25F\"}";
				char encodemsg[MAXMSGSIZE];
				// encode message
				if (jsonmsg.length() > MAXMSGSIZE - 6)
				{
					printf("Message too long \n");
					return FALSE;
				}
				for (int i = 0; i < jsonmsg.length(); ++i)
					encodemsg[i] = (char)(jsonmsg[i] ^ maskkey[i % 4]);

				bEnMsg = (BYTE*)&encodemsg;
				BYTE bEnMsg2[MAXMSGSIZE];
				bEnMsg2[0] = { 0x81 }; // FIN+RSV+OPCODE
				bEnMsg2[1] = (BYTE)(jsonmsg.length() + 128); //add MASK flag
				bEnMsg2[2] = { 0x31 }; //add MASK key
				bEnMsg2[3] = { 0x32 }; //add MASK key
				bEnMsg2[4] = { 0x33 }; //add MASK key
				bEnMsg2[5] = { 0x34 }; //add MASK key

				//printf("[ ");
				for (int i = 0; i < jsonmsg.length() + 6; i++)
				{
					// //add FIN+RSV+OPCODE+PayloadLen+MaskKey in front of message
					if (i<jsonmsg.length())
					{
						bEnMsg2[i + 6] = bEnMsg[i];
					}
					//printf("%02x ", bEnMsg2[i]);
				}
				//printf("]\n");

				socket.Send(bEnMsg2, jsonmsg.length() + 6);

				if (caMsg[0] == '0') {
					printf("Connection disconnected!!\n");
					isEnd = true;
					thdReceive.join();
					break;
				}
			}
		}
		//Failed receive
		else {
			return FALSE;
		}
	}
	//Failed send
	else {
		return FALSE;
	}

	return TRUE;
}

int _tmain(int argc, _TCHAR *argv[])
{
	std::wstring wsType, wsUrlInfo, wsFilePath, wsProxy, wsSendMsg;
	std::string sUrlInfo = "", sProxy = "", sOutput = "";
	std::wstring wsOutput = L"rsp.txt";
	BOOL isProxy = FALSE;
	BOOL isSndTogether = FALSE;
	std::wstring* wsInfo = nullptr;
	Behavior::CSSL* pSSLLib = nullptr;
	for (int i = 1; i != argc; ++i) {
		_TCHAR* arg = argv[i];

		switch (arg[0]) {
			case L'-':
				switch (arg[1]) {
					case L't':
						wsInfo = &wsType;
						break;
					case L'u':
						wsInfo = &wsUrlInfo;
						break;
					case L'f':
						wsInfo = &wsFilePath;
						break;
					case L'o':
						wsInfo = &wsOutput;
						break;
					case L'p':
						wsInfo = &wsProxy;
						break;
					case L's':
						isSndTogether = TRUE;
						break;
					default:
						Utility::PrintUsage(argv);
						return 1;
				}
				break;
			default:
				*wsInfo = std::wstring(argv[i]);
				break;
		}
	}

	if (wsType == L"chrome") {
		pSSLLib = Behavior::CreateChromeSSLInstance();
	}
	else if (wsType == L"edge") {
		pSSLLib = Behavior::CreateNCryptSSLInstance();
	}
	else if (wsType == L"ie") {
		pSSLLib = Behavior::CreateSecur32SSLInstance();
	}
	else if (wsType == L"firefox") {
		//pFakeBrowser = Behavior::CreateNSS3SSLInstance();
		pSSLLib = Behavior::CreateChromeSSLInstance(TRUE);
	}
	else {
		if (std::wstring(argv[0]).find(L"chrome")!= std::string::npos)
		{
			pSSLLib = Behavior::CreateChromeSSLInstance();
		}
		else if (std::wstring(argv[0]).find(L"Edge") != std::string::npos) {
			pSSLLib = Behavior::CreateNCryptSSLInstance();
		}
		else if (std::wstring(argv[0]).find(L"iexplore") != std::string::npos) {
			pSSLLib = Behavior::CreateSecur32SSLInstance();
		}
		else if (std::wstring(argv[0]).find(L"firefox") != std::string::npos) {
			//pFakeBrowser = Behavior::CreateNSS3SSLInstance();
			pSSLLib = Behavior::CreateChromeSSLInstance(TRUE);
		}
		else {
			Utility::PrintUsage(argv);
			return 1;
		}
	}

	// if the tool cannot get url from -u command try to read the file to get the url if the file path existence from -f command 
	if (wsUrlInfo == L"") {
		if (wsFilePath != L"") {
			std::ifstream f(wsFilePath);
			std::wbuffer_convert<std::codecvt_utf8<wchar_t>> conv(f.rdbuf());
			std::wistream wf(&conv);
			getline(wf, wsUrlInfo);
		}
		else {
			Utility::PrintUsage(argv);
			return 1;
		}
	}
	
	if (pSSLLib == nullptr || wsUrlInfo == L"") {
		Utility::PrintUsage(argv);
		return 1;
	}

	//Convert wstring to string and do the puny code encoding.
	if (!Utility::ConvertURLFromWstring2String(wsUrlInfo, sUrlInfo)) {
		return 1;
	}

	if (!pSSLLib->Init()) {
		return 1;
	}

	BYTE* bResponse = nullptr;
	size_t stRecSize = 0;

	sProxy = std::string(wsProxy.begin(), wsProxy.end());
	Behavior::SocketIO skSocket;
	if (sProxy != "") {
		if (!skSocket.ConnectToServer(sProxy)) {
			return 1;
		}
		if (!SendSocks(sProxy, sUrlInfo, skSocket, bResponse, stRecSize)) {
			return 1;
		}
		isProxy = TRUE;
	}
	else {
		if (!skSocket.ConnectToServer(sUrlInfo)) {
			return 1;
		}
		isProxy = FALSE;
	}

	BOOL isHttp2 = FALSE;
	if (sUrlInfo.find("https") != std::string::npos 
		|| sUrlInfo.find("wss") != std::string::npos) {
		pSSLLib->SetSocket(&skSocket);
		if (!pSSLLib->Handshake(isHttp2, TRUE)) {
			return 1;
		}

		skSocket.SetSSLLib(pSSLLib);
	}

	if (isHttp2) {
		if (!SendHttp2(sUrlInfo, skSocket, pSSLLib, bResponse, stRecSize, isSndTogether)) {
			return 1;
		}
	}else {
		// Send WebSocket
		if (sUrlInfo.find("ws://") != std::string::npos 
			|| sUrlInfo.find("wss://") != std::string::npos) {
			if (!SendWebSocket(sUrlInfo, skSocket, bResponse, stRecSize)) {
				return 1;
			}
		}
		// Send Http11
		else if (!SendHttp11(sProxy, isProxy, sUrlInfo, skSocket, pSSLLib, bResponse, stRecSize)) {
			return 1;
		}
	}
	skSocket.CloseConnection();
	Utility::FreeOBJ(&pSSLLib);

	sOutput = std::string(wsOutput.begin(), wsOutput.end());
	Utility::WriteFile(sOutput, bResponse, stRecSize);

	return 0;
}