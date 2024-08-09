#include <Windows.h>
#include <stdio.h>

#define DENEME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) //kontrol kodu yapilanmasi

typedef struct readmemoryPacket {
    int pid;
    ULONG address;
} rmPacket, * _rmPacket;

ULONG readmemory(HANDLE driver, rmPacket packet) {
    ULONG value;
    DWORD bytesReturned;

    BOOL success = DeviceIoControl( //device io kontrol ile kernelle konusuruz
        driver,
        DENEME,           //kontrol kod
        &packet,               //gonderdigimiz veri, eger bos ise NULL
        sizeof(packet),
        &value,         //driverdan aldigimiz veri
        sizeof(value),
        &bytesReturned,     //toplam donen byte
        NULL
    );

    if (success) {
        return value;
    }
    return -31; //ERROR
}

int main() {

    HANDLE hDevice = CreateFileA("\\\\.\\kernelhop",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("No driver found at the specific path! %ld\n", GetLastError());
        return 1;
    }

    rmPacket packet;
    packet.pid = 3192;
    packet.address = 0x008CBADC;

    ULONG ammo = readmemory(hDevice, packet);
    printf("%ld\n", ammo);
    CloseHandle(hDevice);
    return 0;
}
