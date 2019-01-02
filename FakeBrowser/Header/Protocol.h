#pragma once
#include "stdafx.h"
#include <sslprovider.h>

#include "SSLLayer.h"

namespace Protocol
{
#pragma pack(push, 1)
	struct SSLExtensionStruct
	{
		/** Extension type */
		uint16_t extensionType;
		/** Extension length */
		uint16_t extensionDataLength;
		/** Extension data as raw (byte array) */
		uint8_t extensionData[50];
	};
#pragma pack(pop)

#pragma pack(push, 1)
	struct SSLClientHello
	{
	public:
		SSLClientHello(BOOL useALPN = FALSE, DWORD version = TLS1_PROTOCOL_VERSION, uint16_t cipherSuite = TLS_RSA_WITH_AES_128_CBC_SHA);
		pcpp::ssl_tls_record_layer m_recordLayer;
		pcpp::ssl_tls_client_server_hello m_handshakeLayer;
		uint8_t m_sessionId = 0;
		uint16_t m_cipherSuiteLength = htons(2);
		uint16_t m_cipherSuite;
		uint8_t m_compressionMethodLength = 1;
		uint8_t m_compressionMethod = 0;
		uint16_t m_extensionsLength = 0;
		uint8_t m_extensions[500] = {
			0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02,
			0x01, 0x00, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x06, 0x01, 0x06, 0x03, 0x04, 0x01, 0x05, 0x01,
			0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x02, 0x03, 0x02, 0x02, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01,
			0x00, 0x01, 0x00
		};
	};
#pragma pack(pop)

#pragma pack(push, 1)
	struct SSLClientKeyExchange
	{
	public:
		SSLClientKeyExchange(uint8_t* preMasterSecret, uint16_t preMasterSecretLen, DWORD version = TLS1_PROTOCOL_VERSION);
		pcpp::ssl_tls_record_layer m_recordLayer;
		pcpp::ssl_tls_handshake_layer m_handshakeLayer;
		uint16_t m_preMasterSecretLen;
		uint8_t m_preMasterSecret[500];
	};
#pragma pack(pop)

#pragma pack(push, 1)
	struct SSLChangeCipherSpec
	{
	public:
		SSLChangeCipherSpec(DWORD version = TLS1_PROTOCOL_VERSION);
		pcpp::ssl_tls_record_layer m_recordLayer;
		uint8_t message = 1;
	};
#pragma pack(pop)

#pragma pack(push, 1)
	struct SSLFinishedMessage
	{
	public:
		SSLFinishedMessage(uint8_t* encryptedMessage, uint16_t encryptedMessageLen, DWORD version = TLS1_PROTOCOL_VERSION);
		pcpp::ssl_tls_record_layer m_recordLayer;
		uint8_t m_encryptedMessage[500];
	};
#pragma pack(pop)

#pragma pack(push, 1)
	struct Sock4
	{
	public:
		uint8_t version;
		uint8_t command;
		uint16_t port;
		BYTE address[4];
		uint8_t name;
	};
#pragma pack(pop)

#pragma pack(push, 1)
	struct Sock5
	{
	public:
		uint8_t version;
		uint8_t command;
		uint8_t reserved;
		uint8_t addressType;
		BYTE address[4];
		uint16_t port;
	};
#pragma pack(pop)

}
