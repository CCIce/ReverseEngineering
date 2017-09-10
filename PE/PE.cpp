#include<stdio.h>
#include<windows.h>
#include<tchar.h>

PIMAGE_DOS_HEADER m_pDosHdr=NULL; //Dos pointer
PIMAGE_NT_HEADERS m_pNtHdr=NULL; //PE pointer
PIMAGE_SECTION_HEADER m_pSecHdr=NULL; //section pointer

LPVOID m_lpBase=NULL; //base address of image
HANDLE m_hMap=NULL; //handle of image
HANDLE m_hFile=NULL; //handle of file

BOOL FileCreate(const char *szFileName)
{
        m_hFile = CreateFile(szFileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (m_hFile == INVALID_HANDLE_VALUE)
	{

	        printf("error open file...\r\n");
		return FALSE;
	}

	m_hMap = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, 0);

	if (m_hMap == NULL)
	{
		CloseHandle(m_hFile);
		return FALSE;
	}

	m_lpBase = MapViewOfFile(m_hMap, FILE_MAP_READ, 0, 0, 0);
	if (m_lpBase == NULL)
	{
	    printf("ipBase is NULL");
		CloseHandle(m_hMap);
		CloseHandle(m_hFile);
		return FALSE;
	}
	return TRUE;
}

BOOL IsPeFileAndGetPePoint()
{
	m_pDosHdr = (PIMAGE_DOS_HEADER)m_lpBase;

	if (m_pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
	    printf("Not MZ header\n");
		return FALSE;
	}

	m_pNtHdr = (PIMAGE_NT_HEADERS)((DWORD)m_lpBase + m_pDosHdr->e_lfanew);

	if (m_pNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
	    printf("Open False");
		return FALSE;
	}

	m_pSecHdr = (PIMAGE_SECTION_HEADER)((DWORD)&(m_pNtHdr->OptionalHeader) + m_pNtHdr->FileHeader.SizeOfOptionalHeader);
	return TRUE;
}

//print information of PE
VOID CPeParseDig()
{
	printf("address of EntryPoint:");
	printf("%08X\n", m_pNtHdr->OptionalHeader.AddressOfEntryPoint);

	printf("Base Address:");
	printf("%08X\n", m_pNtHdr->OptionalHeader.ImageBase);

	printf("linker version:");
	printf("%d.%d\n", m_pNtHdr->OptionalHeader.MajorLinkerVersion, m_pNtHdr->OptionalHeader.MinorLinkerVersion);

	printf("Number of Sections:");
	printf("%02X\n", m_pNtHdr->FileHeader.NumberOfSections);

	printf("size of code:");
	printf ("%08x\n", m_pNtHdr->OptionalHeader.SizeOfCode);

}

//Print information of sections
VOID EnumSections()
{
	int nSecNum = m_pNtHdr->FileHeader.NumberOfSections;

	for (int i = 0; i < nSecNum; i++)
	{
	    printf("Section:%d\n", i+1);
		printf("%08X\n", m_pSecHdr[i].VirtualAddress);
		printf("%08X\n", m_pSecHdr[i].Misc.VirtualSize);
		printf("%08X\n", m_pSecHdr[i].PointerToRawData);
		printf("%08X\n", m_pSecHdr[i].SizeOfRawData);
		printf("%08X\n", m_pSecHdr[i].Characteristics);
		printf("\n");
	}
}


VOID FreePoint()
{
	CloseHandle(m_hMap);
	CloseHandle(m_hFile);
}

int main()
{
	const char* szFileName = "c:\\windows\\system32\\cmd.exe";
	if (FileCreate(szFileName))
	{

		if (IsPeFileAndGetPePoint())
		{
			CPeParseDig();
			EnumSections();
			FreePoint();
		}
	}

    FreePoint();
	return 0;
}
