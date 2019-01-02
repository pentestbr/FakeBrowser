#pragma once
#include "stdafx.h"

namespace Behavior
{
	class CSSL;
	class SocketIO
	{
	public:
		BOOL ConnectToServer(std::string sUrl);
		BOOL SendMsgToServer(BYTE* bData, size_t stSize);
		BOOL ReceiveMsgFromServer(BYTE* &bBuffer, size_t &stRecSize);
		BOOL EncryptAndSend(BYTE* bData, size_t stSize);
		BOOL ReceiveAndDecrypt(BYTE* &bResponse, size_t &stRecSize);
		BOOL Send(BYTE* bData, size_t stSize);
		BOOL Receive(BYTE* &bResponse, size_t &stRecSize);
		void SetSSLLib(CSSL* pCSSL) { m_pCSSL = pCSSL; }
		void CloseConnection();

	private:
		std::string m_sUrl = "";
		SOCKET m_skSocket;
		WSADATA m_wsaData;
		CSSL* m_pCSSL = nullptr;
	};
}
