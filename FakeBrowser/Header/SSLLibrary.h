#pragma once
#include "stdafx.h"
#include <vector>

#include "SSLLayer.h"
#include "SocketIO.h"

namespace Behavior
{
#define SEC_SUCCESS(Status) ((Status) >= 0)
#define FAILED(hr) (((HRESULT)(hr)) < 0)
#define CT_HANDSHAKE 22
#define CT_APPLICATIONDATA 23
#define MAKE_NVT(K, V)                                                          \
  {                                                                            \
    (uint8_t *)K, (uint8_t *)V, strlen(K), strlen(V),                  \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

	class CSSL;
	class CNSS3SSL;
	BOOL CreateSSLMessageByRawdata(std::map<pcpp::SSLRecordType, std::map<size_t, pcpp::SSLLayer*>>& mapSSLLayer, uint8_t* data, size_t dataLen);

	CSSL * CreateNCryptSSLInstance();
	CSSL * CreateChromeSSLInstance(BOOL isFirefox = FALSE);
	CSSL * CreateSecur32SSLInstance();
	CNSS3SSL * CreateNSS3SSLInstance();

	class CSSL
	{
	public:
		virtual ~CSSL();
		virtual BOOL Handshake(BOOL& isHttp2, BOOL useALPN = FALSE) = 0;
		virtual BOOL Init() = 0;
		virtual BOOL DeInit() = 0;
		virtual BOOL Encrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen, DWORD type) { return FALSE; }
		virtual BOOL Decrypt(BYTE *inBuffer, DWORD inSize, BYTE *outBuffer, DWORD outSize, DWORD *dwWriteen) { return FALSE; }
		void SetSocket(SocketIO* socketIO) { m_socketIO = socketIO; }
	protected:
		SocketIO *m_socketIO = nullptr;
	};

}