#include <windows.h>
#include "beacon.h"


typedef struct _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
  union {
    DWORD Flags;
    struct {
      DWORD MicrosoftSignedOnly : 1;
      DWORD StoreSignedOnly : 1;
      DWORD MitigationOptIn : 1;
      DWORD AuditMicrosoftSignedOnly : 1;
      DWORD AuditStoreSignedOnly : 1;
      DWORD ReservedFlags : 27;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
} PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, *PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY;

PROCESS_MITIGATION_POLICY ProcessSignaturePolicy = 8;


WINBASEAPI HANDLE WINAPI KERNEL32$SetProcessMitigationPolicy(PROCESS_MITIGATION_POLICY MitigationPolicy,PVOID           lpBuffer,SIZE_T  dwLength);

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessMitigationPolicy(HANDLE hProcess, PROCESS_MITIGATION_POLICY MitigationPolicy, PVOID lpBuffer, SIZE_T  dwLength);


void AddACG(){

	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature = { 0 };
	KERNEL32$GetProcessMitigationPolicy((HANDLE)(-1), (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));

	signature.MicrosoftSignedOnly = 1;


	KERNEL32$SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Add ACG!");

}

void go(char* args, int length)
{
    AddACG();
}
