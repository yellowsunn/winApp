#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#pragma comment(lib, "ws2_32.lib")
#include <WinSock2.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <WS2tcpip.h>
#include <time.h>
#include <Windows.h>
#include "resource.h"
#define BUFSIZE		512

HWND hHandle;		// ���̾� �α� �ڵ鰪
SOCKET recieveSock, senderSock;
HANDLE sendEvent;	// ������ ��ư�� ���� ��� ��ȣ���·� �����(Sender ������ blocked ���� ����)

char multiAddr[30];
int port;
char userName[30];
char buf[BUFSIZE + 1];

BOOL CALLBACK DlgProc(HWND hdlg, UINT iMsg, WPARAM wParam, LPARAM lParam);
BOOL isClassD(const char * addr);
DWORD WINAPI Receiver(LPVOID arg);
DWORD WINAPI Sender(LPVOID arg);
DWORD WINAPI CheckSame(LPVOID arg);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	WSADATA wsaData;
	WSAStartup(WINSOCK_VERSION, &wsaData);
	sendEvent = CreateEvent(NULL, FALSE, FALSE, NULL);	//���ȣ ����

	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DlgProc);

	CloseHandle(sendEvent);
	closesocket(recieveSock);
	closesocket(senderSock);
	WSACleanup();
	return 0;
}

BOOL CALLBACK DlgProc(HWND hdlg, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	HWND hMsg;
	char temp[10];
	
	switch (iMsg)
	{
	case WM_INITDIALOG:
		hHandle = hdlg;
		hMsg = GetDlgItem(hdlg, ID_SEND_MESSAGE);
		EnableWindow(hMsg, FALSE);			// �ʱ� ���¿��� ������ ���� ������ �޼����� ���� �� ����.
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDCANCEL:
			EndDialog(hdlg, 0);
			return TRUE;

		case ID_REGISTER:
			GetDlgItemText(hdlg, ID_MULTICAST_ADDR, multiAddr, 30);
			if (strlen(multiAddr) == 0 || !isClassD(multiAddr))
			{
				MessageBox(NULL, "��Ƽ ĳ��Ʈ �ּҸ� �Է��ϼ���. (224.0.0.0 ~ 239.255.255.255)", "��Ƽĳ��Ʈ �ּ� ����", MB_ICONERROR);
				SetDlgItemText(hdlg, ID_MULTICAST_ADDR, "");
				SetFocus(GetDlgItem(hdlg, ID_MULTICAST_ADDR));
				break;
			}

			GetDlgItemText(hdlg, ID_PORT_NUM, temp, 10);
			port = atoi(temp);
			if (port == 0 || !(port > 0 && port <= USHRT_MAX))
			{
				MessageBox(NULL, "�߸��� ��Ʈ ��ȣ �Դϴ�.", "��Ʈ ��ȣ ����", MB_ICONERROR);
				SetDlgItemText(hdlg, ID_PORT_NUM, "");
				SetFocus(GetDlgItem(hdlg, ID_PORT_NUM));
				break;
			}

			GetDlgItemText(hdlg, ID_USER_NAME, userName, 30);
			if (strlen(userName) == 0)
			{
				MessageBox(NULL, "��ȭ���� �Է��ϼ���.", "��ȭ�� ����", MB_ICONERROR);
				SetFocus(GetDlgItem(hdlg, ID_USER_NAME));
				break;
			}
			hMsg = GetDlgItem(hdlg, ID_SEND_MESSAGE);
			EnableWindow(hMsg, TRUE);
			CreateThread(NULL, 0, Receiver, NULL, 0, NULL);
			CreateThread(NULL, 0, Sender, NULL, 0, NULL);

			EnableWindow(GetDlgItem(hdlg, ID_REGISTER), FALSE);	//���� ���ϰ�(���� ���ڰ� ���߿� ��������)
			////
			char t[30];
			sprintf(t, "%d", GetWindowThreadProcessId(hdlg, NULL));
			MessageBox(NULL, t, "��Ƽĳ��Ʈ �ּ� ����", MB_ICONERROR);
			///
			return TRUE;
		case ID_CHANGE_NAME:
			if(recieveSock == NULL || senderSock == NULL)
				MessageBox(NULL, "������ �Ŀ� ���� �����մϴ�.", "��ȭ�� ���� ����", MB_ICONERROR);
			else
			{
				char temp[30];
				GetDlgItemText(hdlg, ID_USER_NAME, temp, 30);
				if (strlen(temp) != 0)
				{
					strcpy(userName, temp);
				}
			}
			break;
		case ID_SEND_MESSAGE:
			SetEvent(sendEvent);
			break;
		}
	}
	return FALSE;
}

DWORD WINAPI Receiver(LPVOID arg)
{
	// socket()
	recieveSock = socket(PF_INET, SOCK_DGRAM, 0);
	if (recieveSock == INVALID_SOCKET) exit(-1);

	// SO_REUSEADDR �ɼ� ����
	BOOL optval = TRUE;
	if (setsockopt(recieveSock, SOL_SOCKET,
		SO_REUSEADDR, (char *)&optval, sizeof(optval)) == SOCKET_ERROR)
		exit(-1);

	// bind()
	SOCKADDR_IN localaddr;
	ZeroMemory(&localaddr, sizeof(localaddr));
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localaddr.sin_port = htons(port);
	if (bind(recieveSock, (SOCKADDR *)&localaddr, sizeof(localaddr)) == SOCKET_ERROR)
		exit(-1);

	// ��Ƽĳ��Ʈ �׷� ����
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr(multiAddr);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(recieveSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR)
		exit(-1);
	
	SOCKADDR_IN senderAddr;
	int senderAddr_sz = sizeof(senderAddr);
	while (1)
	{
		char senderName[30];
		recvfrom(recieveSock, senderName, 30, 0, (SOCKADDR*)&senderAddr, &senderAddr_sz);
		recvfrom(recieveSock, buf, BUFSIZE, 0, (SOCKADDR *)&senderAddr, &senderAddr_sz);

		char cMsg[BUFSIZE + 100];
		//����ð�
		time_t t = time(NULL);
		struct tm *tm = localtime(&t);

		sprintf(cMsg, "%s[%s:%d](%d-%d-%d %d:%d:%d) : %s\r\n", senderName, inet_ntoa(senderAddr.sin_addr), ntohs(senderAddr.sin_port),
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec, buf);

		HWND hmessage = GetDlgItem(hHandle, ID_MESSAGE_BOX);
		int nLength = GetWindowTextLength(hmessage);
		SendMessage(hmessage, EM_SETSEL, nLength, nLength);
		SendMessage(hmessage, EM_REPLACESEL, FALSE, (LPARAM)cMsg);
	}
}

DWORD WINAPI Sender(LPVOID arg)
{
	// socket()
	senderSock = socket(PF_INET, SOCK_DGRAM, 0);
	if (senderSock == INVALID_SOCKET) exit(-1);

	SOCKADDR_IN mulAdr;
	ZeroMemory(&mulAdr, sizeof(mulAdr));
	mulAdr.sin_family = AF_INET;
	mulAdr.sin_addr.s_addr = inet_addr(multiAddr);
	mulAdr.sin_port = htons(port);

	// ��Ƽĳ��Ʈ TTL ����
	int ttl = 2;
	if (setsockopt(senderSock, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl)) == SOCKET_ERROR)
		exit(-1);

	while (1)
	{
		WaitForSingleObject(sendEvent, INFINITE);
		sendto(senderSock, userName, 30, 0, (SOCKADDR *)&mulAdr, sizeof(mulAdr));
		GetDlgItemText(hHandle, ID_INPUT_MESSAGE, buf, 512);
		sendto(senderSock, buf, BUFSIZE, 0, (SOCKADDR *)&mulAdr, sizeof(mulAdr));
		SetDlgItemText(hHandle, ID_INPUT_MESSAGE, "");
	}
}

DWORD WINAPI CheckSame(LPVOID arg)
{
	return 0;
}
BOOL isClassD(const char * addr)
{
	ULONG uAddr;
	if ((uAddr = inet_addr(addr)) == INADDR_NONE) return FALSE;	// �ּ� ��ȯ�� ������ ���
	uAddr %= 256;
	if (uAddr >= 224 && uAddr <= 239)
		return TRUE;
	else
		return FALSE;
}