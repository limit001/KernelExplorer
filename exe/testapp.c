/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    testapp.c

Abstract:

Environment:

    Win32 console multi-threaded application

--*/
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <sys\sioctl.h>
#include <conio.h>

BOOLEAN
ManageDriver(
    _In_ LPCTSTR  DriverName,
    _In_ LPCTSTR  ServiceName,
    _In_ USHORT   Function
    );

BOOLEAN
SetupDriverName(
    _Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
    _In_ ULONG BufferLength
    );

char OutputBuffer[100];
char InputBuffer[100];

VOID __cdecl
main(
    _In_ ULONG argc,
    _In_reads_(argc) PCHAR argv[]
    )
{
    HANDLE hDevice;
    BOOL bRc;
    ULONG bytesReturned;
    DWORD errNum = 0;
    TCHAR driverLocation[MAX_PATH];

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    printf("CreateFile(\"\\\\.\\IoctlTest\")\n");
    //
    // open the device
    //

    if ((hDevice = CreateFile( "\\\\.\\IoctlTest",
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            NULL,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL)) == INVALID_HANDLE_VALUE) {

        errNum = GetLastError();

        if (errNum != ERROR_FILE_NOT_FOUND) {

            printf("CreateFile failed : %d\n", errNum);

            return ;
        }

        //
        // The driver is not started yet so let us the install the driver.
        // First setup full path to driver name.
        //

        if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {
            printf("SetupDriverName : %s\n", driverLocation);
            return ;
        }

        if (!ManageDriver(DRIVER_NAME,
                          driverLocation,
                          DRIVER_FUNC_INSTALL
                          )) {

            printf("Unable to install driver.\n");

            //
            // Error - remove driver.
            //

            ManageDriver(DRIVER_NAME,
                         driverLocation,
                         DRIVER_FUNC_REMOVE
                         );

            return;
        }

        hDevice = CreateFile( "\\\\.\\IoctlTest",
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            NULL,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);

        if ( hDevice == INVALID_HANDLE_VALUE ){
            printf ( "Error: CreatFile Failed : %d\n", GetLastError());
            return;
        }

    }

    //
    // Printing Input & Output buffer pointers and size
    //

    printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
                        sizeof(InputBuffer));
    printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
                                sizeof(OutputBuffer));
    //
    // Performing METHOD_BUFFERED
    //

    StringCbCopy(InputBuffer, sizeof(InputBuffer),
        "This String is from User Application; using METHOD_BUFFERED");

    printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

    memset(OutputBuffer, 0, sizeof(OutputBuffer));

    bRc = DeviceIoControl ( hDevice,
                            (DWORD) IOCTL_SIOCTL_METHOD_BUFFERED,
                            &InputBuffer,
                            (DWORD) strlen ( InputBuffer )+1,
                            &OutputBuffer,
                            sizeof( OutputBuffer),
                            &bytesReturned,
                            NULL
                            );

    if ( !bRc )
    {
        printf ( "Error in DeviceIoControl : %d", GetLastError());
        return;

    }
    printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);

    //
    // Performing METHOD_NEITHER
    //

    printf("\nCalling DeviceIoControl METHOD_NEITHER\n");

    StringCbCopy(InputBuffer, sizeof(InputBuffer),
               "This String is from User Application; using METHOD_NEITHER");
    memset(OutputBuffer, 0, sizeof(OutputBuffer));

    bRc = DeviceIoControl ( hDevice,
                            (DWORD) IOCTL_SIOCTL_METHOD_NEITHER,
                            &InputBuffer,
                            (DWORD) strlen ( InputBuffer )+1,
                            &OutputBuffer,
                            sizeof( OutputBuffer),
                            &bytesReturned,
                            NULL
                            );

    if ( !bRc )
    {
        printf ( "Error in DeviceIoControl : %d\n", GetLastError());
        return;

    }

    printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);

    //
    // Performing METHOD_IN_DIRECT
    //

    printf("\nCalling DeviceIoControl METHOD_IN_DIRECT\n");

    StringCbCopy(InputBuffer, sizeof(InputBuffer),
               "This String is from User Application; using METHOD_IN_DIRECT");
    StringCbCopy(OutputBuffer, sizeof(OutputBuffer),
               "This String is from User Application in OutBuffer; using METHOD_IN_DIRECT");

    bRc = DeviceIoControl ( hDevice,
                            (DWORD) IOCTL_SIOCTL_METHOD_IN_DIRECT,
                            &InputBuffer,
                            (DWORD) strlen ( InputBuffer )+1,
                            &OutputBuffer,
                            sizeof( OutputBuffer),
                            &bytesReturned,
                            NULL
                            );

    if ( !bRc )
    {
        printf ( "Error in DeviceIoControl : %d", GetLastError());
        return;
    }

    printf("    Number of bytes transfered from OutBuffer: %d\n",
                                    bytesReturned);

    //
    // Performing METHOD_OUT_DIRECT
    //

    printf("\nCalling DeviceIoControl METHOD_OUT_DIRECT\n");
    StringCbCopy(InputBuffer, sizeof(InputBuffer),
               "This String is from User Application; using METHOD_OUT_DIRECT");
    memset(OutputBuffer, 0, sizeof(OutputBuffer));
    bRc = DeviceIoControl ( hDevice,
                            (DWORD) IOCTL_SIOCTL_METHOD_OUT_DIRECT,
                            &InputBuffer,
                            (DWORD) strlen ( InputBuffer )+1,
                            &OutputBuffer,
                            sizeof( OutputBuffer),
                            &bytesReturned,
                            NULL
                            );

    if ( !bRc )
    {
        printf ( "Error in DeviceIoControl : %d", GetLastError());
        return;
    }

    printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);

    BOOL bExit = FALSE;
    char cInput = L' ';

    while (1)
    {
        printf("Input command(1,2,3,4,0):");
        cInput = getchar();
        memset(InputBuffer, 0, sizeof(InputBuffer));
        memset(OutputBuffer, 0, sizeof(OutputBuffer));
        switch (cInput)
        {
        case '1':
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_TEST_001,
                    &InputBuffer,
                    (DWORD)strlen(InputBuffer) + 1,
                    &OutputBuffer,
                    sizeof(OutputBuffer),
                    &bytesReturned,
                    NULL);
            break;
        case '2':
            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_TEST_002,
                &InputBuffer,
                (DWORD)strlen(InputBuffer) + 1,
                &OutputBuffer,
                sizeof(OutputBuffer),
                &bytesReturned,
                NULL );
            break;
        case '3':
            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_TEST_003,
                &InputBuffer,
                (DWORD)strlen(InputBuffer) + 1,
                &OutputBuffer,
                sizeof(OutputBuffer),
                &bytesReturned,
                NULL);
            break;
        case '4':
            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_TEST_004,
                &InputBuffer,
                (DWORD)strlen(InputBuffer) + 1,
                &OutputBuffer,
                sizeof(OutputBuffer),
                &bytesReturned,
                NULL);
            break;
        case '5':
            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_TEST_005,
                &InputBuffer,
                (DWORD)strlen(InputBuffer) + 1,
                &OutputBuffer,
                sizeof(OutputBuffer),
                &bytesReturned,
                NULL);
            break;

        case '6':
        {
            unsigned int unPid;
            printf("insert pid : ");
            scanf("%u", &unPid);
            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_TEST_006,
                &unPid,
                (DWORD)sizeof(unPid),
                &OutputBuffer,
                sizeof(OutputBuffer),
                &bytesReturned,
                NULL);
            break;

        }

        case '0':
            bExit = TRUE;
            break;
        }
        if (bExit)
            break;
    }


    CloseHandle ( hDevice );

    //
    // Unload the driver.  Ignore any errors.
    //

    ManageDriver(DRIVER_NAME,
                 driverLocation,
                 DRIVER_FUNC_REMOVE
                 );


    //
    // close the handle to the device.
    //

}


