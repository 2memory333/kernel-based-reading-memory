#define DENEME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#include <ntddk.h>
#include "ntos.h"
PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING DriverName, DriverSymbol;

typedef struct readmemoryPacket {
	int pid;
	ULONG address;
} rmPacket, * _rmPacket;

NTSTATUS ReadMemoryFromProcess(PEPROCESS SourceProcess, PVOID SourceAddress, PVOID DestinationBuffer, SIZE_T BufferSize, PSIZE_T BytesRead)
{
	return MmCopyVirtualMemory(SourceProcess, 
		SourceAddress, PsGetCurrentProcess(), 
		DestinationBuffer, 
		BufferSize, 
		KernelMode, 
		BytesRead);
}

ULONG oku(int procId,ULONG address) {
	HANDLE processHandle = NULL;
	PEPROCESS targetProcess = NULL;
	CLIENT_ID clientId;
	OBJECT_ATTRIBUTES objectAttributes;
	NTSTATUS status;
	SIZE_T bytesRead;

	clientId.UniqueProcess = (HANDLE)procId;
	clientId.UniqueThread = NULL;
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = PsLookupProcessByProcessId(clientId.UniqueProcess, &targetProcess);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "fucuk");
		return status;
	}

	PVOID addressToRead = (PVOID)(address);
	ULONG save = 0;
	status = ReadMemoryFromProcess(targetProcess, addressToRead, &save, sizeof(save), &bytesRead);

	if (targetProcess) {
		ObDereferenceObject(targetProcess);
	}

	return save;
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode; 

	if (ControlCode == DENEME)
	{
		_rmPacket readedpacket = (_rmPacket)Irp->AssociatedIrp.SystemBuffer; //kontrol kodu METHOD_BUFFERED oldugu icin AssociatedIrp.SystemBuffer kullandik.
		//readedpacket deðiþkeninin pointerine verdik.
		ULONG value = oku(readedpacket->pid, readedpacket->address);
		RtlCopyMemory(readedpacket, &value, sizeof(value));  //gelen veri üzerine yaziyoruz
		BytesIO = sizeof(value);
		DbgPrintEx(0, 0, "gonderildi\n");
	}
	Status = STATUS_SUCCESS;
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	DbgPrintEx(0, 0, "Unload routine called.\n");
	IoDeleteSymbolicLink(&DriverSymbol);
	IoDeleteDevice(pDriverObject->DeviceObject);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrintEx(0, 0, "Driver Loaded\n");

	RtlInitUnicodeString(&DriverName, L"\\Device\\kernelhop");
	RtlInitUnicodeString(&DriverSymbol, L"\\DosDevices\\kernelhop");

	IoCreateDevice(pDriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&DriverSymbol, &DriverName);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	pDriverObject->DriverUnload = UnloadDriver;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}