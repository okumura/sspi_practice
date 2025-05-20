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

void print_client_hello(unsigned char *pbuf) {
  unsigned int handshake_length;
  unsigned char *pclient_hello;
  unsigned short i;
  unsigned short num_ciphers;
  unsigned char num_comp_methods;
  unsigned short num_extentions;
  unsigned short extention_length;

  /* TLSPlainText */
  _tprintf(_T("TLSPlainText\n"));
  _tprintf(_T("  ContentType: %d\n"), pbuf[0]); pbuf++;
  _tprintf(_T("  Version: 0x%02x%02x\n"), pbuf[0], pbuf[1]); pbuf += 2;
  _tprintf(_T("  Length: %d\n"), (pbuf[0] << 8) | (pbuf[1])); pbuf += 2;
  _tprintf(_T("\n"));

  /* Handshake */
  _tprintf(_T("Handshake\n"));
  _tprintf(_T("  Type: %d\n"), pbuf[0]); pbuf++;
  handshake_length = (pbuf[0] << 16) | (pbuf[1] << 8) | (pbuf[2]); pbuf += 3;
  _tprintf(_T("  Length: %d\n"), handshake_length);
  _tprintf(_T("\n"));

  /* ClientHello */
  pclient_hello = pbuf;
  _tprintf(_T("ClientHello\n"));
  _tprintf(_T("  Version: 0x%02x%02x\n"), pbuf[0], pbuf[1]); pbuf += 2;
  _tprintf(_T("  GMT: 0x%02x%02x%02x%02x\n"), pbuf[0], pbuf[1], pbuf[2], pbuf[3]); pbuf += 4;
  /* skip random bytes. */
  pbuf += 28;
  _tprintf(_T("  SessionID Length: %d\n"), pbuf[0]); pbuf += 1 + pbuf[0];
  num_ciphers = ((pbuf[0] << 8) | (pbuf[1])) / 2; pbuf += 2;
  _tprintf(_T("  CipherSuite Count: %d\n"), num_ciphers);
  for (i = 0; i < num_ciphers; i++) {
    _tprintf(_T("    CipherSuite: 0x%02x%02x\n"), pbuf[0], pbuf[1]); pbuf += 2;
  }

  num_comp_methods = pbuf[0]; pbuf++;
  _tprintf(_T("  CompressionMethod Count: %d\n"), num_comp_methods);
  for (i = 0; i < num_comp_methods; i++) {
    _tprintf(_T("    CompressionMethod: 0x%02x\n"), pbuf[0]); pbuf++;
  }

  if (pbuf - pclient_hello < handshake_length) {
    num_extentions = ((pbuf[0] << 8) | (pbuf[1])); pbuf += 2;
    _tprintf(_T("  Extension Length: %d\n"), num_extentions);
    while (pbuf - pclient_hello < handshake_length) {
      _tprintf(_T("    ExtensionType: 0x%04x\n"), (pbuf[0] << 8) | (pbuf[1])); pbuf += 2;
      extention_length = ((pbuf[0] << 8) | (pbuf[1])); pbuf += 2 + extention_length;
      _tprintf(_T("    Length: %d\n"), extention_length);
    }
  }
}

int main(int argc, TCHAR** argv) {
  TCHAR *hostname = _T("localhost");
  SECURITY_STATUS s;
  SCHANNEL_CRED cred;
  CredHandle handle;
  TimeStamp tsExpiry;
  CtxtHandle ctxtHandle;
  ULONG outFlags = 0;
  SecBuffer sendBuffer;
  SecBufferDesc outBufferDesc;

  ZeroMemory(&cred, sizeof(cred));
  cred.dwVersion = SCHANNEL_CRED_VERSION;
  cred.grbitEnabledProtocols = SP_PROT_TLS1_CLIENT;
  cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_USE_DEFAULT_CREDS;

  s = AcquireCredentialsHandle(
    NULL,                 /* should be NULL for Schannel. */
    UNISP_NAME,           /* specify it for Schannel. */
    SECPKG_CRED_OUTBOUND, /* for server, specify SECPKG_CRED_INBOUND */
    NULL,                 /* should be NULL for Schannel. */
    &cred,                /* can specify PSCHANNEL_CRED. */
    NULL,                 /* should be NULL for Schannel. */
    NULL,                 /* should be NULL for Schannel. */
    &handle,
    &tsExpiry);
  if (s != SEC_E_OK) {
    _tprintf(_T("AcquireCredentialsHandle() failed(0x%08x)."), s);
    return -1;
  }

  sendBuffer.cbBuffer = 0;
  sendBuffer.pvBuffer = NULL;
  sendBuffer.BufferType = SECBUFFER_TOKEN;

  outBufferDesc.cBuffers = 1;
  outBufferDesc.pBuffers = &sendBuffer;
  outBufferDesc.ulVersion = SECBUFFER_VERSION;

  s = InitializeSecurityContext(
    &handle,
    NULL,                 /* must be NULL on first call. */
    hostname,
    TCP_SSL_REQUEST_CONTEXT_FLAGS,
    0,                    /* must be 0. */
    SECURITY_NATIVE_DREP, /* must be 0 on msdn, but ... */
    NULL,                 /* must be NULL on first call. */
    0,                    /* must be 0. */
    &ctxtHandle,
    &outBufferDesc,
    &outFlags,
    &tsExpiry);
  if (s != SEC_I_CONTINUE_NEEDED) {
    _tprintf(_T("InitializeSecurityContext() failed(0x%08x)."), s);
    FreeCredentialHandle(&handle);
    return -2;
  }

  /* You will get request buffer for sending. */
  print_client_hello((unsigned char *) sendBuffer.pvBuffer);

  if (sendBuffer.pvBuffer) {
    FreeContextBuffer(sendBuffer.pvBuffer);
  }
  if (handle.dwLower || handle.dwUpper) {
    DeleteSecurityContext(&handle);
  }

  FreeCredentialHandle(&handle);

  return 0;
}
