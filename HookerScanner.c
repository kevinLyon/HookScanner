#include <Windows.h>
#include <stdio.h>
#include <wchar.h>

//##############################################################//
//#                         DLLs                               #//
//##############################################################//

PCHAR ntdll_lst[] = {

    "EtwpCreateEtwThread",
    "NtQueryInformationProcess",
    "NtQueueApcThreadEx",
    "RtlCreateProcessParameters",
    "NtCreateProcessEx"
};


PCHAR kernel32_lst[] = {

    "CloseHandle",
    "CloseHandle",
    "VirtualAlloc",
    "CreateRemoteThreadEx",

};

//##############################################################//
//#                         DLLs                               #//
//##############################################################//

VOID checkHook(PCHAR pcList[], SIZE_T sLength, LPCWSTR pcModuleName) {
   
    // bytes to read
    SIZE_T sBytesToRead = 9;
    SIZE_T sController = 0;

    HANDLE kernalbase_handle = GetModuleHandleW(pcModuleName);
    
    printf(" -> %p", kernalbase_handle);
  
    printf("\n{\n");
    for (INT i = 0; i < sLength; i++) {

        PCHAR pcCurrentFunction = pcList[i];
        if (kernalbase_handle != NULL) {
            LPVOID CRT_address = GetProcAddress(kernalbase_handle, pcCurrentFunction); 

            if (CRT_address != NULL) {

                // pointer buffer 
                unsigned char* bytePointer = (unsigned char*)CRT_address;

                //HOOKED ( some EDRs can put the jump after SSN )
                if ((unsigned char*)bytePointer[0] == (unsigned char*)0xe9 || (unsigned char*)bytePointer[8] == (unsigned char*)0xe9) {
                    for (INT q = 0; q <= sBytesToRead; q++) {
                        printf(" %02x", (INT)bytePointer[q]); 
                    }
                    printf(" %s", pcCurrentFunction);
                    printf(" at %p ", CRT_address);
                    printf("[!] HOOKED!\n");

                    if (sController == 0) {

                        printf("    [ + ] Test unHook...");
                        WriteProcessMemory(GetCurrentProcess(), CRT_address, "\xff", 1, NULL);

                        if ((unsigned char*)bytePointer[0] == (unsigned char*)0xff) {
                            for (INT q = 0; q < sBytesToRead; q++) {
                                printf(" %02x", (INT)bytePointer[q]); 
                            }
                            printf(" [+] SUCESS!\n\n");
                        }
                        else {
                            printf(" [!] ERROR!\n\n");
                        }
                        sController++;
                    }


                }
                else {

                    for (INT q = 0; q < sBytesToRead; q++) {
                        printf(" %02x", (INT)bytePointer[q]); 
                    }
                    printf(" %s\n", pcCurrentFunction);

                }
            }
            //i++;
        }
    }
    printf("}\n");
}


INT main() { 


    INT result = 0;

    PCHAR* pcLoot[] = { ntdll_lst, kernel32_lst };
    
    // PCHAR Buffer[2] sizeof( 8 byte + 8 byte ) the calc = ( 16 / 8 = 2 ) bufferLenght=2
    SIZE_T  sSizeLists[] = {
        sizeof(ntdll_lst) / sizeof(ntdll_lst[0]),
        sizeof(kernel32_lst) / sizeof(kernel32_lst[0])
    };

    // folow same order in all variables... 'ntdll', 'kernel32', '...'...
    PWCHAR pcOrderList[] = { L"ntdll.dll", L"kernel32.dll" };
    

    for (INT q = 0; q <= sizeof(sSizeLists) / sizeof(sSizeLists); q++) {

        printf("\n[+] ( functions: %d ) Test hooking '%ls'", (INT)sSizeLists[q], pcOrderList[q]);
        checkHook(pcLoot[q], sSizeLists[q], pcOrderList[q]);
    }

    printf("\n<Finish program>");
    result = getchar(); 
	return 0;
}