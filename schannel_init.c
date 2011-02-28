#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h> /* for UNISP_NAME */

#pragma comment(lib, "secur32.lib")

enum {
	TCP_SSL_REQUEST_CONTEXT_FLAGS =
		ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR |
		ISC_REQ_REPLAY_DETECT |
		ISC_REQ_SEQUENCE_DETECT |
		ISC_REQ_STREAM
};

int main(int argc, TCHAR** argv) {
	TCHAR *hostname = _T("localhost");
	SECURITY_STATUS s;
	CredHandle handle;
	TimeStamp tsExpiry;
	CtxtHandle ctxtHandle;
	ULONG outFlags = 0;
	SecBuffer sendBuffer;
	SecBufferDesc outBufferDesc;
	
	s = AcquireCredentialsHandle(
		NULL, /* should be NULL for Schannel. */
		UNISP_NAME, /* specify it for Schannel. */
		SECPKG_CRED_OUTBOUND, /* for server, specify SECPKG_CRED_INBOUND */
		NULL, /* should be NULL for Schannel. */
		NULL, /* can specify PSCHANNEL_CRED. */
		NULL, /* should be NULL for Schannel. */
		NULL, /* should be NULL for Schannel. */
		&handle,
		&tsExpiry);
	if (s != SEC_E_OK) {
		_tprintf(_T("AcquireCredentialsHandle() failed(0x%08x)."), s);
		return -1;
	} else {
		sendBuffer.cbBuffer = 0;
		sendBuffer.pvBuffer = NULL;
		sendBuffer.BufferType = SECBUFFER_TOKEN;
		
		outBufferDesc.cBuffers = 1;
		outBufferDesc.pBuffers = &sendBuffer;
		outBufferDesc.ulVersion = SECBUFFER_VERSION;
		
		s = InitializeSecurityContext(
			&handle,
			NULL, /* must be NULL on first call. */
			hostname,
			TCP_SSL_REQUEST_CONTEXT_FLAGS,
			0, /* must be 0. */
			SECURITY_NATIVE_DREP, /* must be 0 on msdn, but ... */
			NULL, /* must be NULL on first call. */
			0, /* must be 0. */
			&ctxtHandle,
			&outBufferDesc,
			&outFlags,
			&tsExpiry);
		if (s != SEC_I_CONTINUE_NEEDED) {
			_tprintf(_T("InitializeSecurityContext() failed(0x%08x)."), s);
			FreeCredentialHandle(&handle);
			return -2;
		} else {
			/* You will get request buffer for sending. */
			
			if (sendBuffer.pvBuffer) {
				FreeContextBuffer(sendBuffer.pvBuffer);
			}
			if (handle.dwLower != 0 || handle.dwUpper != 0) {
				DeleteSecurityContext(&handle);
			}
		}
		FreeCredentialHandle(&handle);
	}
	
	return 0;
}
