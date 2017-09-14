#include<stdio.h>
#include<windows.h>
#include<tchar.h>
#include<iostream>
#include<string.h>


using namespace std;


PIMAGE_DOS_HEADER m_pDosHdr = NULL;
PIMAGE_NT_HEADERS m_pNtHdr = NULL;
PIMAGE_SECTION_HEADER m_pSecHdr = NULL;

LPVOID m_pbImage = NULL;
HANDLE m_hMap = NULL;
HANDLE m_hFile = NULL;

BOOL FileCreate(const char *szFileName)
{
	cout << szFileName << endl;
	HANDLE m_hFile = CreateFile(szFileName,
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

	m_pbImage = MapViewOfFile(m_hMap, FILE_MAP_READ, 0, 0, 0);
	if (m_pbImage == NULL)
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

	//	LPVOID m_lpBase;
	//	PIMAGE_SECTION_HEADER m_pSecHdr;
	m_pDosHdr = (PIMAGE_DOS_HEADER)m_pbImage;

	if (m_pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Not MZ header\n");
		return FALSE;
	}

	m_pNtHdr = (PIMAGE_NT_HEADERS)((DWORD)m_pbImage + m_pDosHdr->e_lfanew);

	if (m_pNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	m_pSecHdr = (PIMAGE_SECTION_HEADER)((DWORD)&(m_pNtHdr->OptionalHeader) + m_pNtHdr->FileHeader.SizeOfOptionalHeader);
	return TRUE;
}

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
	printf("%08x\n", m_pNtHdr->OptionalHeader.SizeOfCode);

}

VOID EnumSections()
{
	int nSecNum = m_pNtHdr->FileHeader.NumberOfSections;

	for (int i = 0; i < nSecNum; i++)
	{
		printf("Section:%d\n", i + 1);
		printf("%08X\n", m_pSecHdr[i].VirtualAddress);
		printf("%08X\n", m_pSecHdr[i].Misc.VirtualSize);
		printf("%08X\n", m_pSecHdr[i].PointerToRawData);
		printf("%08X\n", m_pSecHdr[i].SizeOfRawData);
		printf("%08X\n", m_pSecHdr[i].Characteristics);
		printf("\n");
	}
}

DWORD OffsetToRva(DWORD dwOffset, LPVOID m_pbImage)
{
    DWORD dwSecBorder = -1;

    PIMAGE_NT_HEADERS m_pNtHdr = PIMAGE_NT_HEADERS((DWORD)m_pbImage + (DWORD)PIMAGE_DOS_HEADER(m_pbImage)->e_lfanew);
    PIMAGE_SECTION_HEADER m_pSecHdr = PIMAGE_SECTION_HEADER(PBYTE(m_pNtHdr) + sizeof(IMAGE_NT_HEADERS));

    for(DWORD i = 0; i < m_pNtHdr->FileHeader.NumberOfSections; i++)
    {
        if(dwOffset >= m_pSecHdr[i].PointerToRawData && dwOffset < m_pSecHdr[i].PointerToRawData + m_pSecHdr[i].SizeOfRawData)
            return  dwOffset - m_pSecHdr[i].PointerToRawData + m_pSecHdr[i].VirtualAddress;

        if(m_pSecHdr[i].PointerToRawData && m_pSecHdr[i].PointerToRawData < dwSecBorder)
            dwSecBorder = m_pSecHdr[i].PointerToRawData;
    }

    if(dwOffset < dwSecBorder)
        return dwOffset;
    else
        return NULL;


}

LPVOID RvaToPointer(DWORD dwRva, LPVOID m_pbImage)
{
    DWORD dwSecBorder = -1;
    PIMAGE_NT_HEADERS m_pNtHdr = PIMAGE_NT_HEADERS((DWORD)m_pbImage + PIMAGE_DOS_HEADER(m_pbImage)->e_lfanew);
    PIMAGE_SECTION_HEADER m_pSecHdr = PIMAGE_SECTION_HEADER((PBYTE)m_pNtHdr + sizeof(PIMAGE_NT_HEADERS));

    for(int i = 0; i < m_pNtHdr->FileHeader.NumberOfSections; i++)
    {
        if(dwRva >= m_pSecHdr[i].VirtualAddress && dwRva < m_pSecHdr[i].VirtualAddress + m_pSecHdr[i].Misc.VirtualSize)
        {
            return (m_pbImage + (dwRva - m_pSecHdr[i].VirtualAddress + m_pSecHdr[i].PointerToRawData));
        }

        if(m_pSecHdr[i].PointerToRawData && m_pSecHdr[i].PointerToRawData < dwSecBorder)
            dwSecBorder = m_pSecHdr[i].PointerToRawData;
    }

    if(dwRva < dwSecBorder)
        return m_pbImage + dwRva;
    else
        return NULL;
}



VOID FreePoint()
{
	CloseHandle(m_hMap);
	CloseHandle(m_hFile);
	CloseHandle(m_pbImage);

	free(m_pDosHdr);
	free(m_pNtHdr);
	free(m_pSecHdr);
}

int main()
{
	//    "D:\\The Sims 4\\Game\\Bin\\TS4_x64.exe";
	const char* szFileName = "C:\\Users\\Administrator\\Desktop\\add.exe";
//	if (FileCreate(szFileName))
//	{
//
//		if (IsPeFileAndGetPePoint())
//		{
//			CPeParseDig();
//			EnumSections();
//			FreePoint();
//		}
//	}

    FileCreate(szFileName);
//    LPVOID a = RvaToPointer((DWORD)0x002288, m_pbImage);
    DWORD a = OffsetToRva((DWORD)0x0011, m_pbImage);
    cout << a << endl;

	return 0;
}
