#include "stdafx.h"
#include <windows.h>

#include "SSLLibrary.h"
#include "Utility.h"

namespace Behavior
{
	BOOL CreateSSLMessageByRawdata(std::map<pcpp::SSLRecordType, std::map<size_t ,pcpp::SSLLayer*>>& mapSSLLayer, uint8_t* data, size_t dataLen)
	{
		pcpp::Packet* ptrPacket = nullptr;
		pcpp::Layer* prevLayer = nullptr;
		pcpp::SSLLayer* ptrLayer = nullptr;
		uint8_t* curPos = data;
		size_t totalLen = 0 , szDataKey = 0;

		while (totalLen != dataLen)
		{
			pcpp::ssl_tls_record_layer* recordLayer = (pcpp::ssl_tls_record_layer*)curPos;
			uint8_t type = recordLayer->recordType;
			if (type != pcpp::SSL_HANDSHAKE && type != pcpp::SSL_ALERT &&
				type != pcpp::SSL_CHANGE_CIPHER_SPEC && type != pcpp::SSL_APPLICATION_DATA) {
				printf("\n\nParse data error: unknown SSL type\n");
				return FALSE;
			}

			size_t size = htons(recordLayer->length) + 5;
			totalLen += size;

			if (totalLen > dataLen) {
				printf("\n\nParse data error: message size(%d) total size(%d)\n", totalLen, dataLen);
				return FALSE;
			}
			uint8_t* buffer = new uint8_t[size];
			memcpy(buffer, curPos, size);

			switch (type)
			{
				printf("%x,", recordLayer->recordType);
				case pcpp::SSL_HANDSHAKE:
				{
					ptrLayer = new pcpp::SSLHandshakeLayer(buffer, size, prevLayer, ptrPacket);
					if (mapSSLLayer[pcpp::SSL_CHANGE_CIPHER_SPEC].size() > 0) {
						szDataKey = pcpp::SSL_FINISHED;
					}
					else {
						szDataKey = (pcpp::SSLHandshakeType)(ptrLayer->getData()[5]);
					}
					break;
				}

				case pcpp::SSL_ALERT:
				{
					pcpp::SSLAlertLayer *ptrAltLayer = new pcpp::SSLAlertLayer(buffer, size, prevLayer, ptrPacket);
					//break;
					if (ptrAltLayer->getAlertLevel() == pcpp::SSL_ALERT_LEVEL_FATAL) {
						printf("\n\nGot fatal error from server: %d\n", ptrAltLayer->getAlertDescription());
						Utility::FreeOBJ(&ptrAltLayer);
						Utility::FreeOBJ(&data);
						return FALSE;
					}
					printf("\n\nGot alert from server: %d\n", ptrAltLayer->getAlertDescription());
					Utility::FreeOBJ(&ptrAltLayer);
					Utility::FreeOBJ(&data);
					continue;
				}

				case pcpp::SSL_CHANGE_CIPHER_SPEC:
				{
					ptrLayer = new pcpp::SSLChangeCipherSpecLayer(buffer, size, prevLayer, ptrPacket);
					szDataKey = 0;
					break;
				}

				case pcpp::SSL_APPLICATION_DATA:
				{
					ptrLayer = new pcpp::SSLApplicationDataLayer(buffer, size, prevLayer, ptrPacket);
					szDataKey = mapSSLLayer[(pcpp::SSLRecordType)type].size();
					break;
				}

				}
			curPos += size;
			mapSSLLayer[(pcpp::SSLRecordType)type][szDataKey] = ptrLayer;
		}

		return TRUE;
	}

	CSSL::~CSSL()
	{

	}
}
