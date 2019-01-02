#include "StdAfx.h"
#include <windows.h>

#include "SSLLibrary.h"
#include "SSLLibrary_Chrome.h"
#include "Markup.h"
#include "nghttp2.h"

namespace Behavior
{
	BOOL CChromeSSL::m_BIOWrapperDebug = 0;
	HMODULE CChromeSSL::m_hModule = NULL;
	HMODULE CChromeSSL::m_hModule2 = NULL;
	ChromeFunctionInterface CChromeSSL::m_pfnTable = {NULL};
	ChromeOffsetTable CChromeSSL::m_offsetTable = {NULL};
	DWORD CChromeSSL::ChromeMajorVersion = 52;
	uint8_t** CChromeSSL::ptr_alpn_client_proto_list = nullptr;

	const BIO_METHOD CChromeSSL::kBIOMethod = 
	{
		0,     // type (unused)
		NULL,  // name (unused)
		CChromeSSL::BIOWriteWrapper,
		CChromeSSL::BIOReadWrapper,
		NULL,
		NULL,
		CChromeSSL::BIOCtrlWrapper, // ctrl
		NULL, //create
		NULL, //destyroy
		NULL, //callback ctrl
	};

	BOOL GetChildHexValue(CMarkup *Config, _TCHAR *NodeName, DWORD *data)
	{
		CString csTemp;
		if(Config->FindElem(NodeName))
		{
			csTemp = Config->GetData();

			*data = _tcstoul(csTemp.GetBuffer(), NULL, 16);

			return TRUE;
		}
		else
		{
			_tprintf(_T("cannot find %s\n"), NodeName);
		}
		
		return FALSE;
	}

	BOOL
	CChromeSSL::LoadOffsetTable()
	{
		BOOL bRet = TRUE;
		BOOL bRet2;
		CMarkup *config = NULL;
		CString csTemp;
		_TCHAR TimestampAndSize[32];
		IMAGE_DOS_HEADER *pMZhdr;
		IMAGE_NT_HEADERS *pNtHdr;

		ChromeFunctionInterface offsetTable = {0}; 
		
		if(!GetFileAttributes(_T("offset.xml")))
			return FALSE;

		//Get PE Header
		pMZhdr = (IMAGE_DOS_HEADER*)m_hModule;

		pNtHdr = (IMAGE_NT_HEADERS*)Add2Ptr(m_hModule, pMZhdr->e_lfanew);

		_stprintf_s(TimestampAndSize, _T("%X%X"), 
			pNtHdr->FileHeader.TimeDateStamp,
			pNtHdr->OptionalHeader.SizeOfImage);

		_tprintf(_T("Build my signature %s\n"), TimestampAndSize);

		config = new CMarkup();
		if(config->Load(_T("offset.xml")) == false)
		{
			_tprintf(_T("failed to load XML\n"));
		}

		while(config->FindElem(_T("OffsetTable")))
		{
			//
			csTemp = config->GetAttrib(_T("TimestampAndSize"));

			_tprintf(_T("Get a offset, signature=%s\n"), csTemp);

			if(csTemp.CompareNoCase(TimestampAndSize))
				continue;

			csTemp = config->GetAttrib(_T("Version"));
			if(!csTemp.IsEmpty())
			{
				int pos = 0;
				CString csMajorVersion = csTemp.Tokenize(_T("."), pos);

				ChromeMajorVersion = _tcstoul(csMajorVersion.GetBuffer(), NULL, 0);
			}

			config->IntoElem();

			bRet = TRUE;
			bRet &= GetChildHexValue(config, _T("SSL_library_init"), (DWORD *)&offsetTable.SSL_library_init);
			bRet2 = GetChildHexValue(config, _T("SSLv23_client_method"), (DWORD *)&offsetTable.SSLv23_client_method);
			if(!bRet2)
			{
				//SSLv23_client_method_offset
				bRet &= GetChildHexValue(config, _T("SSLv23_client_method_offset"), (DWORD *)&offsetTable.SSLv23_client_method_offset);
			}

			bRet &= GetChildHexValue(config, _T("SSL_CTX_NEW"), (DWORD *)&offsetTable.SSL_CTX_NEW);
			if(ChromeMajorVersion >=59)
			{
				if(config->FindElem(_T("SSL_CTX_Struct_offset")))
				{
					config->IntoElem();
					if(ChromeMajorVersion>=61)
					{
						bRet &= GetChildHexValue(config, _T("verify_mode_offset"), (DWORD *)&m_offsetTable.ssl_verify_mode_offset);
						bRet &= GetChildHexValue(config, _T("custom_verify_callback_offset"), (DWORD *)&m_offsetTable.ssl_custom_verify_callback_offset);						
					}
					else // 59 60
					{
						bRet &= GetChildHexValue(config, _T("i_promise_to_verify_certs_after_the_handshake_offset"), (DWORD *)&m_offsetTable.ssl_i_promise_to_verify_certs_after_the_handshake_offset);
						bRet &= GetChildHexValue(config, _T("i_promise_to_verify_certs_after_the_handshake_bitfield"), (DWORD *)&m_offsetTable.ssl_i_promise_to_verify_certs_after_the_handshake_bitfield);
					}
					config->OutOfElem();
				}
				else
				{
					_tprintf(_T("Chrome >= 59 requires SSL_CTX_Struct_Offset"));
					return FALSE;
				}
			}

			bRet &= GetChildHexValue(config, _T("SSL_new"), (DWORD *)&offsetTable.SSL_new);
			if(ChromeMajorVersion < 56)
				bRet &= GetChildHexValue(config, _T("SSL_set_bio"), (DWORD *)&offsetTable.SSL_set_bio);
			bRet2 =  GetChildHexValue(config, _T("SSL_set_connect_state"), (DWORD *)&offsetTable.SSL_set_connect_state);
			if(!bRet2)
			{
				//chrome 53
				if(config->FindElem(_T("SSL_set_connect_state_offset")))
				{
					config->IntoElem();
					bRet &= GetChildHexValue(config, _T("ssl_server_offset"), (DWORD *)&m_offsetTable.ssl_server_offset);
					bRet &= GetChildHexValue(config, _T("ssl_server_bitfield"), (DWORD *)&m_offsetTable.ssl_server_bitfield);

					if(ChromeMajorVersion < 56)
					{
						bRet &= GetChildHexValue(config, _T("ssl_state_offset"), (DWORD *)&m_offsetTable.ssl_state_offset);
						bRet &= GetChildHexValue(config, _T("ssl_state_value"), (DWORD *)&m_offsetTable.ssl_state_value);
					}
					bRet &= GetChildHexValue(config, _T("ssl_handshake_func_offset"), (DWORD *)&m_offsetTable.ssl_handshake_func_offset);
					bRet &= GetChildHexValue(config, _T("ssl3_connect"), (DWORD *)&offsetTable.ssl3_connect);
					config->OutOfElem();
				}
				else
				{
					_tprintf(_T("failed to find SSL_set_connect_state_offset element\n"));
					bRet = FALSE;
				}
			}

			bRet &= GetChildHexValue(config, _T("SSL_do_handshake"), (DWORD *)&offsetTable.SSL_do_handshake);
			bRet &= GetChildHexValue(config, _T("SSL_get_error"), (DWORD *)&offsetTable.SSL_get_error);
			bRet2 = GetChildHexValue(config, _T("ERR_get_error"), (DWORD *)&offsetTable.ERR_get_error);
			if(!bRet2)
			{
				bRet2 = GetChildHexValue(config, _T("get_error_values"), (DWORD *)&offsetTable.get_error_values);
			}

			bRet2 = GetChildHexValue(config, _T("SSL_write"), (DWORD *)&offsetTable.SSL_write);
			if(!bRet2)
			{
				if(ChromeMajorVersion>=61)
				{
					bRet &= GetChildHexValue(config, _T("ssl3_write_app_data"), (DWORD *)&offsetTable.ssl3_write_app_data61);
					_tprintf(_T("> Chrome >= 61 %d\n"), bRet);
				}
				else
				{
					bRet &= GetChildHexValue(config, _T("ssl3_write_app_data"), (DWORD *)&offsetTable.ssl3_write_app_data);
					_tprintf(_T("> Chrome <= 60 %d\n"), bRet);
				}
			}

			bRet2 = GetChildHexValue(config, _T("SSL_read"), (DWORD *)&offsetTable.SSL_read);
			if(!bRet2)
			{
				if(ChromeMajorVersion>=54)
					bRet &= GetChildHexValue(config, _T("ssl3_read_app_data"), (DWORD *)&offsetTable.ssl3_read_app_data54);
				else
					bRet &= GetChildHexValue(config, _T("ssl3_read_app_data"), (DWORD *)&offsetTable.ssl3_read_app_data);
			}

			bRet &= GetChildHexValue(config, _T("BIO_new"), (DWORD *)&offsetTable.BIO_new);
			bRet2 &= GetChildHexValue(config, _T("BIO_read"), (DWORD *)&offsetTable.BIO_read);
			bRet2 &= GetChildHexValue(config, _T("BIO_write"), (DWORD *)&offsetTable.BIO_write);

			if(ChromeMajorVersion<=55)
			{
				bRet &= GetChildHexValue(config, _T("bio_make_pair"), (DWORD *)&offsetTable.bio_make_pair);
				bRet &= GetChildHexValue(config, _T("methods_biop"), (DWORD *)&offsetTable.biop_table);
			}
			else // >= 56
			{
				if(config->FindElem(_T("SSL_BIO_Struct_Offset")))
				{
					config->IntoElem();
					bRet &= GetChildHexValue(config, _T("ssl_wbio_offset"), (DWORD *)&m_offsetTable.ssl_wbio_offset);
					bRet &= GetChildHexValue(config, _T("ssl_rbio_offset"), (DWORD *)&m_offsetTable.ssl_rbio_offset);
					bRet &= GetChildHexValue(config, _T("bio_init_offset"), (DWORD *)&m_offsetTable.bio_init_offset);
					bRet &= GetChildHexValue(config, _T("bio_flags_offset"), (DWORD *)&m_offsetTable.bio_flags_offset);
					bRet &= GetChildHexValue(config, _T("bio_reference_offset"), (DWORD *)&m_offsetTable.bio_reference_offset);
					bRet &= GetChildHexValue(config, _T("bio_ptr_offset"), (DWORD *)&m_offsetTable.bio_ptr_offset);
					config->OutOfElem();
				}
				else
				{
					_tprintf(_T("Chrome >= 56 requires SSL_BIO_Struct_Offset"));
					return FALSE;
				}
			}
			//bio_io
			bRet2 &= GetChildHexValue(config, _T("bio_io"), (DWORD *)&offsetTable.bio_io);
			bRet2 &= GetChildHexValue(config, _T("CRYPTO_refcount_inc"), (DWORD *)&offsetTable.CRYPTO_refcount_inc);

			if((offsetTable.BIO_read == NULL || offsetTable.BIO_write == NULL) && offsetTable.bio_io == NULL)
			{
				_tprintf(_T("Must have BIO_read/BIO_write or bio_io\n"));
				return FALSE;
			}

			bRet2 &= GetChildHexValue(config, _T("SSL_free"), (DWORD *)&offsetTable.SSL_free54);

			config->OutOfElem();

			if(!bRet)
				continue;

			/* found, add the offset */
			PVOID *addr = (PVOID*)&m_pfnTable;
			DWORD offset;

			for(offset = 0; offset < sizeof(ChromeFunctionInterface); offset+= sizeof(PVOID))
			{
				if(*(PVOID *)Add2Ptr(&offsetTable, offset) != NULL)
				{
					*(PVOID *)Add2Ptr(addr, offset) = Add2Ptr(m_hModule, *(DWORD *)Add2Ptr(&offsetTable, offset) );
				}
			}

			break;
		}

cleanup:
		_tprintf(_T("%hs: bRet = %d\n"), __FUNCTION__, bRet);

		delete config;

		return bRet;
	}

	BOOL
	CChromeSSL::LoadOpenSSL()
	{
		m_pfnTable.SSL_library_init = (SSL_library_initT)GetProcAddress(m_hModule, "SSL_library_init");
		m_pfnTable.SSLv23_client_method = (SSLv23_client_methodT)GetProcAddress(m_hModule, "SSLv23_client_method");
		m_pfnTable.SSL_CTX_NEW = (SSL_CTX_NEWT)GetProcAddress(m_hModule, "SSL_CTX_new");
		m_pfnTable.SSL_new = (SSL_newT)GetProcAddress(m_hModule, "SSL_new");
		m_pfnTable.SSL_set_bio = (SSL_set_bioT)GetProcAddress(m_hModule, "SSL_set_bio");
		m_pfnTable.SSL_set_connect_state = (SSL_set_connect_stateT)GetProcAddress(m_hModule, "SSL_set_connect_state");
		m_pfnTable.SSL_do_handshake = (SSL_do_handshakeT)GetProcAddress(m_hModule, "SSL_do_handshake");
		m_pfnTable.SSL_get_error = (SSL_get_errorT)GetProcAddress(m_hModule, "SSL_get_error");
		m_pfnTable.ERR_get_error = (ERR_get_errorT)GetProcAddress(m_hModule2, "ERR_get_error");
		m_pfnTable.SSL_write = (SSL_writeT)GetProcAddress(m_hModule, "SSL_write");
		m_pfnTable.SSL_read = (SSL_readT)GetProcAddress(m_hModule, "SSL_read");
		m_pfnTable.BIO_new = (BIO_newT)GetProcAddress(m_hModule2, "BIO_new");
		m_pfnTable.BIO_read = (BIO_readT)GetProcAddress(m_hModule2, "BIO_read");
		m_pfnTable.BIO_write = (BIO_writeT)GetProcAddress(m_hModule2, "BIO_write");
		m_pfnTable.BIO_new_bio_pair = (BIO_new_bio_pairT)GetProcAddress(m_hModule2, "BIO_new_bio_pair");
		//m_pfnTable.biop_table = (PVOID)GetProcAddress(m_hModule2, "biop_table");

		return TRUE;
	}

	SSL_METHOD CChromeSSL::SSLv23_client_method(void)
	{
		if(m_pfnTable.SSLv23_client_method)
			return m_pfnTable.SSLv23_client_method();
		else
			return (SSL_METHOD)m_pfnTable.SSLv23_client_method_offset;		
	}

	SSL_CTX* CChromeSSL::SSL_CTX_NEW(SSL_METHOD method)
	{
#ifndef _WIN64 /* win32 */
		if(ChromeMajorVersion>=54)
			return m_pfnTable.SSL_CTX_NEW54(method);
		else
			return m_pfnTable.SSL_CTX_NEW(method);
#else
		return m_pfnTable.SSL_CTX_NEW(method);
#endif		
	}

	SSL* CChromeSSL::SSL_new(SSL_CTX *ctx)
	{
#ifndef _WIN64 /* win32 */
		if(ChromeMajorVersion>=54)
			return m_pfnTable.SSL_new54(ctx);
		else
			return m_pfnTable.SSL_new(ctx);
#else
		return m_pfnTable.SSL_new(ctx);
#endif
	}

	BIO* CChromeSSL::BIO_new(PVOID bio_method_st)
	{
#ifndef _WIN64 /* win32 */
		if(ChromeMajorVersion>=54)
			return m_pfnTable.BIO_new54(bio_method_st);
		else
			return m_pfnTable.BIO_new(bio_method_st);
#else
		return m_pfnTable.BIO_new(bio_method_st);
#endif
	}

	int CChromeSSL::bio_make_pair(BIO* bio1, BIO* bio2, DWORD writebuf1_len, BYTE *ext_writebuf1, DWORD writebuf2_len, BYTE* ext_writebuf2)
	{
#ifndef _WIN64 /* win32 */
		if(ChromeMajorVersion>=54)
		{
			// Chrome 54 use special calling convension
			__asm
			{
				push ext_writebuf2
				push writebuf2_len
				push ext_writebuf1
				push writebuf1_len
				mov ecx, bio1
				mov edx, bio2
				call m_pfnTable.bio_make_pair
				add esp, 0x10
			}
		}
		else
			return m_pfnTable.bio_make_pair(bio1, bio2, writebuf1_len, ext_writebuf1, writebuf2_len, ext_writebuf2);
#else
		return m_pfnTable.bio_make_pair(bio1, bio2, writebuf1_len, ext_writebuf1, writebuf2_len, ext_writebuf2);
#endif
	}

	void CChromeSSL::SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio)
	{
		if(ChromeMajorVersion>=56)
		{
			//add ref count
			m_pfnTable.CRYPTO_refcount_inc((DWORD *)Add2Ptr(rbio, m_offsetTable.bio_reference_offset));
			m_pfnTable.CRYPTO_refcount_inc((DWORD *)Add2Ptr(wbio, m_offsetTable.bio_reference_offset));

			*(PVOID*)Add2Ptr(ssl, m_offsetTable.ssl_rbio_offset) = rbio;
			*(PVOID*)Add2Ptr(ssl, m_offsetTable.ssl_wbio_offset) = wbio;
			return;
		}
#ifndef _WIN64 /* win32 */
		if(ChromeMajorVersion>=54)
		{
			__asm
			{
				push wbio
				mov edx, rbio
				mov ecx, ssl
				call m_pfnTable.SSL_set_bio
				pop ecx
			}
		}
		else
			return m_pfnTable.SSL_set_bio(ssl, rbio, wbio);
#else
		return m_pfnTable.SSL_set_bio(ssl, rbio, wbio);
#endif
	}

	int CChromeSSL::SSL_do_handshake(SSL * ssl)
	{
#ifndef _WIN64 /* win32 */
		if(ChromeMajorVersion>=54)
		{
			return m_pfnTable.SSL_do_handshake54(ssl);
		}
		else
			return m_pfnTable.SSL_do_handshake(ssl);
#else
		return m_pfnTable.SSL_do_handshake(ssl);
#endif		
	}

	int CChromeSSL::SSL_get_error(const SSL *ssl, int ret)
	{
#ifndef _WIN64 /* win32 */
		if(ChromeMajorVersion>=54)
		{
			return m_pfnTable.SSL_get_error54(ssl, ret);
		}
		else
			return m_pfnTable.SSL_get_error(ssl, ret);
#else
		return m_pfnTable.SSL_get_error(ssl, ret);
#endif				
	}

	int CChromeSSL::SSL_write(SSL *ssl, BYTE *buf, DWORD num)
	{
		if(m_pfnTable.SSL_write)
			return m_pfnTable.SSL_write(ssl, buf, num);
		else if(m_pfnTable.ssl3_write_app_data)
			return m_pfnTable.ssl3_write_app_data(ssl, buf, num);	
		else
		{
			int needs_handshake;
			int ret;

			ret = m_pfnTable.ssl3_write_app_data61(ssl, &needs_handshake, buf, num);
			_tprintf(_T(">> ret %d handshake %d\n"), ret, needs_handshake);

			return ret;
		}
	}

	int CChromeSSL::SSL_read(SSL *ssl, BYTE *buf, DWORD num)
	{
		int ret = -1;
		if(m_pfnTable.SSL_read)
			ret = m_pfnTable.SSL_read(ssl, buf, num);
		else if(m_pfnTable.ssl3_read_app_data)
			ret = m_pfnTable.ssl3_read_app_data(ssl, buf, num, 0);
		else if(m_pfnTable.ssl3_read_app_data54)
		{
			int got_handshake;
			ret = m_pfnTable.ssl3_read_app_data54(ssl, &got_handshake, buf, num, 0);
			if(got_handshake)
				ret = -1;
		}
		return ret;
	}

	void CChromeSSL::SSL_free(SSL *ssl)
	{
		if(m_pfnTable.SSL_free54)
			m_pfnTable.SSL_free54(ssl);
	}

	int CChromeSSL::BIO_read(BIO *b, void *buf, int len)
	{
#ifndef _WIN64 /* win32 */
		if(ChromeMajorVersion>=54)
		{
			__asm
			{
				push len
				mov edx, buf
				mov ecx, b
				call m_pfnTable.BIO_read
				pop ecx
			}
		}
		else
			return m_pfnTable.BIO_read(b, buf, len);
#else
		if(m_pfnTable.BIO_read)
		{
			return m_pfnTable.BIO_read(b, buf, len);
		}
		else if(m_pfnTable.bio_io) // build bio_io ourselves
		{
			size_t n = 0;
			return m_pfnTable.bio_io(b, buf, len, offsetof(BIO_METHOD, bread), 0x2, &n);
		}
#endif		
	}

	int CChromeSSL::BIO_write(BIO *b, void *buf, int len)
	{

		/*for (int i = 0; i != len; ++i) {
			printf("%x,", ((BYTE*)buf)[i]);
		}
		system("pause");*/
#ifndef _WIN64 /* win32 */
		if(ChromeMajorVersion>=54)
		{
			int ret;
			__asm
			{
				push len
				mov edx, buf
				mov ecx, b
				call m_pfnTable.BIO_write
				pop ecx
				mov ret, eax
			}
		}
		else
			return m_pfnTable.BIO_write(b, buf, len);
#else
		if(m_pfnTable.BIO_write)
			return m_pfnTable.BIO_write(b, buf, len);
		else if(m_pfnTable.bio_io) // build bio_io ourselves
		{
			size_t n = 0;
			return m_pfnTable.bio_io(b, buf, len, offsetof(BIO_METHOD, bwrite), 0x3, &n);
		}
#endif		
	}
	
	unsigned int CChromeSSL::ERR_get_error(void)
	{
		if(m_pfnTable.ERR_get_error)
			return m_pfnTable.ERR_get_error();

		// ref: boringssl crypto/err/err.c
		return m_pfnTable.get_error_values (1 /* inc */, 0 /* bottom*/, NULL, NULL, NULL, NULL);
	}

	// ref: boringssl ssl/ssl_lib.c
	void CChromeSSL::SSL_set_connect_state(SSL *ssl)
	{
		if(m_pfnTable.SSL_set_connect_state)
		{
			m_pfnTable.SSL_set_connect_state(ssl);
		}
		else
		{
			DWORD *pFlag = (DWORD *)Add2Ptr(ssl, m_offsetTable.ssl_server_offset /* flag offset */);
			DWORD *State = (DWORD *)Add2Ptr(ssl, m_offsetTable.ssl_state_offset /* state offset */);
			PVOID *pHandshake_func = (PVOID *)Add2Ptr(ssl, m_offsetTable.ssl_handshake_func_offset);


			*pFlag &= ~(1<<m_offsetTable.ssl_server_bitfield);
			*pHandshake_func = m_pfnTable.ssl3_connect;
			if(m_offsetTable.ssl_state_offset)
				*State = m_offsetTable.ssl_state_value;
		}
	}

	// ref: boringssl ssl_lib.c
	void CChromeSSL::SSL_CTX_i_promise_to_verify_certs_after_the_handshake(SSL_CTX *ctx)
	{
		BYTE *pFlag = (BYTE *)Add2Ptr(ctx, m_offsetTable.ssl_i_promise_to_verify_certs_after_the_handshake_offset);

		*pFlag |= 1<< m_offsetTable.ssl_i_promise_to_verify_certs_after_the_handshake_bitfield;
	}

	void CChromeSSL::SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode, custom_verify_callbackT callback)
	{
		//SSL_CTX_set_custom_verify

		*(int *)Add2Ptr(ctx, m_offsetTable.ssl_verify_mode_offset) = mode;
		*(custom_verify_callbackT *)Add2Ptr(ctx, m_offsetTable.ssl_custom_verify_callback_offset) = callback;
	}

	int CChromeSSL::my_BIO_new_bio_pair(BIO **pbio1, BIO **pbio2, DWORD Buffer1Size, BYTE *Buffer1, DWORD Buffer2Size, BYTE *Buffer2)
	{
		int ret = 1;

		BIO *bio1 = NULL, *bio2 = NULL;
		BUFFER_CTX *buffer1Ctx = NULL;
		BUFFER_CTX *buffer2Ctx = NULL;
		MY_BIO_CTX *bio1_ctx = NULL;
		MY_BIO_CTX *bio2_ctx = NULL;

		if(m_offsetTable.bio_init_offset == 0 ||
			m_offsetTable.bio_ptr_offset == 0)
		{
			return 0;
		}

		bio1 = BIO_new((PVOID)&kBIOMethod);
		bio2 = BIO_new((PVOID)&kBIOMethod);

		if(!bio1 || !bio2)
		{
			ret = 0;
			goto cleanup;
		}

		buffer1Ctx = new BUFFER_CTX;
		buffer2Ctx = new BUFFER_CTX;

		buffer1Ctx->Buffer = Buffer1;
		buffer1Ctx->BufferSize = Buffer1Size;
		buffer1Ctx->DataSize = buffer1Ctx->DataOffset = 0;
		buffer2Ctx->Buffer = Buffer2;
		buffer2Ctx->BufferSize = Buffer2Size;
		buffer2Ctx->DataSize = buffer2Ctx->DataOffset = 0;

		bio1_ctx = new MY_BIO_CTX;
		bio2_ctx = new MY_BIO_CTX;

		bio1_ctx->WriteBuffer = bio2_ctx->ReadBuffer = buffer1Ctx;
		bio2_ctx->WriteBuffer = bio1_ctx->ReadBuffer = buffer2Ctx;

		if(m_BIOWrapperDebug)
		{
			_tprintf(_T("bio1 %p, ctx %p\n"), bio1, bio1_ctx);
			_tprintf(_T("bio2 %p, ctx %p\n"), bio2, bio2_ctx);

			_tprintf(_T("SSL to Socket buffer = %p\n"), buffer1Ctx);
			_tprintf(_T("Socket to SSL buffer = %p\n"), buffer2Ctx);
		}

		// bio->ptr = ctx;
		*(PVOID *)Add2Ptr(bio1, m_offsetTable.bio_ptr_offset) = bio1_ctx;
		*(PVOID *)Add2Ptr(bio2, m_offsetTable.bio_ptr_offset) = bio2_ctx;
		// bio->init = 1;
		*(DWORD *)Add2Ptr(bio1, m_offsetTable.bio_init_offset) =1;
		*(DWORD *)Add2Ptr(bio2, m_offsetTable.bio_init_offset) =1;	

		*pbio1 = bio1;
		*pbio2 = bio2;
cleanup:
		return ret;
	}

	int CChromeSSL::BIOWriteWrapper(BIO *bio, const char *buf, int len)
	{
		if(m_BIOWrapperDebug)
			_tprintf(_T("%p write %d bytes\n"), bio, len);

		if(m_BIOWrapperDebug > 1)
		{
			//CSSL::DumpTlsPacket((const BYTE *)buf, len);

			int i;

			for(i=0;i<len;i++)
			{
				_tprintf(_T("%02x "), (unsigned char)buf[i]);
				if(i % 16 == 15) _tprintf(_T("\n"));
				else if(i % 8 == 7) _tprintf(_T("\t"));
			}

			if(i%16 != 0) _tprintf(_T("\n"));
		}

		MY_BIO_CTX *ctx = *(MY_BIO_CTX**)Add2Ptr(bio, m_offsetTable.bio_ptr_offset);

		if(ctx == NULL) return -1;

		int remainingSize = ctx->WriteBuffer->BufferSize - ctx->WriteBuffer->DataSize;
		int bytesToWrite = len > remainingSize ? remainingSize : len;

		if(ctx->WriteBuffer->DataOffset + ctx->WriteBuffer->DataSize + bytesToWrite <= ctx->WriteBuffer->BufferSize) // case 1, not cross end
		{
			RtlCopyMemory(ctx->WriteBuffer->Buffer + ctx->WriteBuffer->DataSize + ctx->WriteBuffer->DataOffset, buf,  bytesToWrite);
			ctx->WriteBuffer->DataSize += bytesToWrite;
		}
		else
		{
			int bytesToWrite1 = ctx->WriteBuffer->BufferSize - (ctx->WriteBuffer->DataOffset + ctx->WriteBuffer->DataSize);
			RtlCopyMemory(ctx->WriteBuffer->Buffer + ctx->WriteBuffer->DataSize + ctx->WriteBuffer->DataOffset, buf,  bytesToWrite1);				
			RtlCopyMemory(ctx->WriteBuffer->Buffer, buf+bytesToWrite1, bytesToWrite - bytesToWrite1);

			_tprintf(_T("QQ write case 2\n"));
			ctx->WriteBuffer->DataSize += bytesToWrite;
		}

		return bytesToWrite;
	}

	int CChromeSSL::BIOReadWrapper(BIO *bio, char *buf, int len)
	{
		if(m_BIOWrapperDebug)
			_tprintf(_T("%p read %d bytes\n"), bio, len);
		MY_BIO_CTX *ctx = *(MY_BIO_CTX**)Add2Ptr(bio, m_offsetTable.bio_ptr_offset);
		int bytesToCopy = 0;

		if(ctx == NULL) return -1;

		if(ctx->ReadBuffer->DataSize== 0)
		{
			// nothing to read, set retry read flag
			*(DWORD*)Add2Ptr(bio, m_offsetTable.bio_flags_offset) |= (0x1 | 0x8);
			return -1;
		}

		bytesToCopy = (len > ctx->ReadBuffer->DataSize) ? ctx->ReadBuffer->DataSize : len;

		if(ctx->ReadBuffer->DataOffset + bytesToCopy <= ctx->ReadBuffer->BufferSize) //case 1, not cross end
		{
			RtlCopyMemory(buf, ctx->ReadBuffer->Buffer + ctx->ReadBuffer->DataOffset, bytesToCopy);
			ctx->ReadBuffer->DataSize -= bytesToCopy;
			ctx->ReadBuffer->DataOffset += bytesToCopy;
		}
		else
		{
			_tprintf(_T("QQ read case 2\n"));

			int bytesToCopy1 = ctx->ReadBuffer->BufferSize - ctx->ReadBuffer->DataOffset;
			_tprintf(_T("    copy %d bytes from offset %d\n"), bytesToCopy1, ctx->ReadBuffer->DataOffset);
			RtlCopyMemory(buf, ctx->ReadBuffer->Buffer + ctx->ReadBuffer->DataOffset, bytesToCopy1);
			_tprintf(_T("    copy %d bytes from offset 0\n"), bytesToCopy - bytesToCopy1);
			RtlCopyMemory(buf+bytesToCopy1, ctx->ReadBuffer->Buffer, bytesToCopy - bytesToCopy1); // copy the remaining part

			//if(m_BIOWrapperDebug)
			//	_tprintf(_T("read case 2 not supported !!\n"));

			ctx->ReadBuffer->DataSize -= bytesToCopy;
			ctx->ReadBuffer->DataOffset = bytesToCopy - bytesToCopy1;
		}

		if(m_BIOWrapperDebug)
			_tprintf(_T("  Read: copy %d data, %d remaining\n"), bytesToCopy, ctx->ReadBuffer->DataSize);

		return bytesToCopy;
	}

	long CChromeSSL::BIOCtrlWrapper(BIO *bio, int cmd, long larg, void *parg)
	{
		if(m_BIOWrapperDebug)
			_tprintf(_T("%p control with cmd %x\n"), bio, cmd);
		return 1;
	}


	void CChromeSSL::OPENSSL_free(void *orig_ptr)
	{
		if (orig_ptr == NULL) {
			return;
		}

		void *ptr = ((uint8_t *)orig_ptr) - OPENSSL_MALLOC_PREFIX;

		size_t size = *(size_t *)ptr;
		SecureZeroMemory(ptr, size + OPENSSL_MALLOC_PREFIX);
		free(ptr);
	}

	//Replace copying SSLConnection structure from chrome source code with caculating the offset of two members(alpn_client_proto_list,alpn_client_proto_list_len) of SSLConnection
	//int CChromeSSL::SSL_set_alpn_protos(SSL *ssl, const uint8_t *protos, unsigned protos_len)
	//{
	//	OPENSSL_free(ssl->alpn_client_proto_list);

	//	void* ret = malloc(protos_len + OPENSSL_MALLOC_PREFIX);
	//	*(size_t *)ret = protos_len;
	//	memcpy(((uint8_t*)ret) + OPENSSL_MALLOC_PREFIX, (uint8_t*)protos, protos_len);

	//	ssl->alpn_client_proto_list = ((uint8_t*)ret) + OPENSSL_MALLOC_PREFIX;
	//	ssl->alpn_client_proto_list_len = (unsigned)protos_len;

	//	if (!ssl->alpn_client_proto_list) {
	//		return 1;
	//	}

	//	return 0;
	//}

	//Refer from Chrome source code https://cs.chromium.org/chromium/src/third_party/boringssl/src/ssl/ssl_lib.cc?type=cs&q=SSL_set_alpn_protos&sq=package:chromium&l=2028
	int CChromeSSL::SSL_set_alpn_protos(SSL *ssl, const uint8_t *protos, unsigned protos_len)
	{
		size_t alpnListOffset = 0;
		size_t alpnLenOffset = 0;
		size_t size = protos_len;
		//Find from windbg attached to Chrome.dll
		if (ChromeMajorVersion == 58)
		{
#ifdef _WIN64
			alpnListOffset = 0x118;
			alpnLenOffset = 0x120;
#else
			alpnListOffset = 0x98;
			alpnLenOffset = 0x9c;
#endif	
		}
		else if (ChromeMajorVersion == 59)
		{
#ifdef _WIN64
			alpnListOffset = 0x120;
			alpnLenOffset = 0x128;
#else
			alpnListOffset = 0x9c;
			alpnLenOffset = 0xa0;
#endif	
		}
		else if (ChromeMajorVersion == 61)
		{
#ifdef _WIN64
			alpnListOffset = 0x128;
			alpnLenOffset = 0x130;
#else
			alpnListOffset = 0xa4;
			alpnLenOffset = 0xa8;
#endif	
		}
		else {
			printf("Dose not support version %d", ChromeMajorVersion);
			return 1;
		}

	    ptr_alpn_client_proto_list = (uint8_t**)((char*)ssl + alpnListOffset);
		unsigned* ptr_alpn_client_proto_list_len = (unsigned*)((char*)ssl + alpnLenOffset);

		OPENSSL_free(*ptr_alpn_client_proto_list);

		void* ptr = malloc(size + OPENSSL_MALLOC_PREFIX);
		*(size_t *)ptr = size;

		memcpy((uint8_t*)ptr + OPENSSL_MALLOC_PREFIX, (uint8_t*)protos, size);
		*ptr_alpn_client_proto_list = (uint8_t*)ptr + OPENSSL_MALLOC_PREFIX;

		if (!*ptr_alpn_client_proto_list) {
			return 1;
		}
		*ptr_alpn_client_proto_list_len = protos_len;

		return 0;
	}
}