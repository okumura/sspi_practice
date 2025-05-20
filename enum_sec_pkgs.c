#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h> /* for UNISP_NAME */

#pragma comment(lib, "secur32.lib")

int main(int argc, TCHAR** argv) {
  ULONG i;
  ULONG pcPackages = 0;
  PSecPkgInfo pSecPkgInfo = NULL;
  SECURITY_STATUS s;

  _tprintf(_T("EnumerateSecurityPackages() demo\n\n"));

  _tprintf(_T("UNISP_NAME = %s\n\n"), UNISP_NAME);

  s = EnumerateSecurityPackages(&pcPackages, &pSecPkgInfo);
  if (s == SEC_E_OK) {
    for (i = 0; i < pcPackages; i++) {
      _tprintf(_T("%s: %s\n"), pSecPkgInfo[i].Name, pSecPkgInfo[i].Comment);
    }
    if (pSecPkgInfo) {
      FreeContextBuffer(pSecPkgInfo);
    }
  }

  return 0;
}

