#include "Protocol.h"
#include "Utility.h"

namespace Protocol
{
	SSLClientHello::SSLClientHello(BOOL useALPN, DWORD version, uint16_t cipherSuite)
	{
		int extenLen = 51;
		if (useALPN) {
			extenLen = 69;
		}

		//Init record layer part of SSL client hello message
		m_recordLayer.recordType = pcpp::SSL_HANDSHAKE;
		m_recordLayer.recordVersion = htons(version);
		m_recordLayer.length = htons(47 + extenLen);
		//Init handshake layer part of SSL client hello message
		m_handshakeLayer.handshakeType = pcpp::SSL_CLIENT_HELLO;
		m_handshakeLayer.length1 = 0x00;
		m_handshakeLayer.length2 = htons(47 + extenLen - 4);
		m_handshakeLayer.handshakeVersion = htons(version);
		Utility::GetRandomBytes(m_handshakeLayer.random);
		m_cipherSuite = htons(cipherSuite);

		m_extensionsLength = htons(extenLen);
		if (useALPN) {
			uint8_t extenALPN[] = {
				0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74,
				0x70, 0x2f, 0x31, 0x2e, 0x31
			};

			memcpy(m_extensions + 51, extenALPN, sizeof(extenALPN));
		}
	}

	SSLClientKeyExchange::SSLClientKeyExchange(uint8_t* preMasterSecret, uint16_t preMasterSecretLen, DWORD version)
	{
		//Init record layer part of SSL client key exchange
		m_recordLayer.recordType = pcpp::SSL_HANDSHAKE;
		m_recordLayer.recordVersion = htons(version);
		m_recordLayer.length = htons(6 + preMasterSecretLen);

		//Init handshake layer part of SSL client key exchange
		m_handshakeLayer.handshakeType = pcpp::SSL_CLIENT_KEY_EXCHANGE;
		m_handshakeLayer.length1 = 0x00;
		m_handshakeLayer.length2 = htons(2 + preMasterSecretLen);
		m_preMasterSecretLen = htons(preMasterSecretLen);
		memcpy(m_preMasterSecret, preMasterSecret, preMasterSecretLen);
	}

	SSLChangeCipherSpec::SSLChangeCipherSpec(DWORD version)
	{
		m_recordLayer.recordType = pcpp::SSL_CHANGE_CIPHER_SPEC;
		m_recordLayer.recordVersion = htons(version);
		m_recordLayer.length = htons(1);
	}

	SSLFinishedMessage::SSLFinishedMessage(uint8_t* encryptedMessage, uint16_t encryptedMessageLen, DWORD version)
	{
		m_recordLayer.recordType = pcpp::SSL_HANDSHAKE;
		m_recordLayer.recordVersion = htons(version);
		m_recordLayer.length = htons(encryptedMessageLen);
		memcpy(m_encryptedMessage, encryptedMessage, encryptedMessageLen);
	}
}