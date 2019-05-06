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
#define BUFSIZE			512
#define USERNAME_SIZE	50
#define PID_SIZE		sizeof(DWORD)


HWND gDlgHandle;						// ���̾� �α� �ڵ鰪
SOCKET recieveSock, senderSock;		// ���� ���ϰ� �۽� ����
HANDLE sendEvent;					// �޼��� ���� ��ư�� ���� ��� set�Ǵ� �̺�Ʈ (Sender ������ blocked ���� ����)
HANDLE sameEvent;					// ���� ��ȭ�� �����ϴ��� Ȯ���Ҷ� set�Ǵ� �̺�Ʈ
HANDLE changeNameEvent;				// ��ȭ���� �����ϴ� ��� set �Ǵ� �̺�Ʈ
HANDLE initRcvSockEvent, initSndSockEvent;	// ����, �۽� ������ ����,�ʱ�ȭ ������ ��� ������ ��� �̺�Ʈ �߻�

BOOL gAlreadySame = FALSE;			// ���� ��ȭ���� �̹� ������ ��� TRUE �� �����

char gMultiAddr[30];					// ��Ƽĳ��Ʈ �ּ�
int gPort;							// ��Ʈ
char gUserName[USERNAME_SIZE];					// ��ȭ��
SOCKADDR_IN gMulAdr;					// ��Ƽĳ��Ʈ ������ �ּ�
const DWORD currentPID = GetCurrentProcessId();	// ���� ���μ��� ID


BOOL CALLBACK DlgProc(HWND hdlg, UINT iMsg, WPARAM wParam, LPARAM lParam);	// ���̾�α�
DWORD WINAPI Receiver(LPVOID arg);	// ������ �������� ���̿� ���� �����͸� ó���ϴ� ������
DWORD WINAPI Sender(LPVOID arg);	// �޼����� ������ ������(�޼��� ���� ��ư�� ���� ���)
DWORD WINAPI CheckSame(LPVOID arg);	// ����, ��ȭ���� �����ϸ� ������ ���� ��ȭ���� �ִ��� üũ�ϴ� ������
DWORD WINAPI ChangeUserName(LPVOID arg);	// ��ȭ���� ������ ���

BOOL isClassD(const char * addr);
BOOL getMulticastAddr(HWND hdlg);
BOOL getPortNum(HWND hdlg);
BOOL getUserName(HWND hdlg);
void error_message(const char * msg);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	WSADATA wsaData;
	WSAStartup(WINSOCK_VERSION, &wsaData);
	sendEvent = CreateEvent(NULL, FALSE, FALSE, NULL);		// �޼��� ���� ��ư�� ���� ��� set(�ʱ����: reset)
	sameEvent = CreateEvent(NULL, FALSE, FALSE, NULL);		// ���� ��ȭ�� �����ϴ��� Ȯ���Ҷ� set(�ʱ����: reset)
	changeNameEvent = CreateEvent(NULL, FALSE, FALSE, NULL);	// ��ȭ���� �����ϴ� ��� set (�ʱ����: reset)
	initRcvSockEvent = CreateEvent(NULL, TRUE, FALSE, NULL);	// ���� ������ ���������� ������ ��� set(�ʱ����: reset)
	initSndSockEvent = CreateEvent(NULL, TRUE, FALSE, NULL);	// �۽� ������ ���������� ������ ��� set(�ʱ����: reset)

	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DlgProc);	//���̾�α� �ڽ� ����

	CloseHandle(sendEvent);
	CloseHandle(sameEvent);
	CloseHandle(changeNameEvent);
	CloseHandle(initRcvSockEvent);
	CloseHandle(initSndSockEvent);
	closesocket(recieveSock);
	closesocket(senderSock);
	WSACleanup();
	return 0;
}

BOOL CALLBACK DlgProc(HWND hdlg, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	switch (iMsg)
	{
	// �ʱ� ����
	case WM_INITDIALOG:
		gDlgHandle = hdlg;		// ���̾�α� �ڵ� �� ���� ������ ����
		EnableWindow(GetDlgItem(hdlg, ID_SEND_MESSAGE), FALSE);			// �ʱ� ���¿��� ������ ���� ������ �޼����� ���� �� ����.
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		// ���� ��ư�� ���� ���
		case IDCANCEL:
			EndDialog(hdlg, 0);
			return TRUE;
		// ���� ��ư�� ���� ���
		case ID_REGISTER:
			if (!getMulticastAddr(hdlg)) break;	// ��Ƽ ĳ��Ʈ �ּҸ� �Է� �ް� Ȯ���Ѵ�.
			if (!getPortNum(hdlg)) break;		// ��Ʈ ��ȣ�� �Է� �ް� Ȯ���Ѵ�.
			if (!getUserName(hdlg)) break;		// ��ȭ���� �Է� �ް� Ȯ���Ѵ�.

			// ��Ƽĳ��Ʈ �ּ�, ��Ʈ, ��ȭ���� ���� ���� ���
			EnableWindow(GetDlgItem(hdlg, ID_SEND_MESSAGE), TRUE);	// �޼��� ���� ��ư Ȱ��ȭ
			// ������ ����
			CreateThread(NULL, 0, Receiver, NULL, 0, NULL);			
			CreateThread(NULL, 0, Sender, NULL, 0, NULL);
			CreateThread(NULL, 0, ChangeUserName, NULL, 0, NULL);
			CreateThread(NULL, 0, CheckSame, NULL, 0, NULL);

			EnableWindow(GetDlgItem(hdlg, ID_REGISTER), FALSE);	// ������ �Ϸ�Ǹ� ���� ��ư ��Ȱ��ȭ
			SetEvent(sameEvent); // ���� ���̵� �����ϴ� �� üũ�ϴ� �̺�Ʈ set
			return TRUE;
		// ��ȭ�� ���� ��ư�� ���� ���
		case ID_CHANGE_NAME:
			if (recieveSock == NULL && senderSock == NULL)
			{
				MessageBox(NULL, "������ �Ŀ� ���� �����մϴ�.", "��ȭ�� ���� ����", MB_ICONERROR);
				break;
			}
			SetEvent(changeNameEvent);
			return TRUE;
		// �޼��� ���� ��ư�� ���� ���
		case ID_SEND_MESSAGE:
			SetEvent(sendEvent);
			return TRUE;
		}
	}
	return FALSE;
}

DWORD WINAPI Receiver(LPVOID arg)
{
	// socket()
	recieveSock = socket(PF_INET, SOCK_DGRAM, 0);
	if (recieveSock == INVALID_SOCKET) error_message("socket() error!");

	// SO_REUSEADDR �ɼ� ����
	BOOL optval = TRUE;
	if (setsockopt(recieveSock, SOL_SOCKET,
		SO_REUSEADDR, (char *)&optval, sizeof(optval)) == SOCKET_ERROR)
		error_message("setsockopt() error!");

	// bind()
	SOCKADDR_IN localaddr;
	ZeroMemory(&localaddr, sizeof(localaddr));
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localaddr.sin_port = htons(gPort);
	if (bind(recieveSock, (SOCKADDR *)&localaddr, sizeof(localaddr)) == SOCKET_ERROR)
		error_message("bind() error!");

	// ��Ƽĳ��Ʈ �׷� ����
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr(gMultiAddr);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(recieveSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR)
		error_message("setsockopt() error!");
	
	SetEvent(initRcvSockEvent);	// ���� ���� ����, �ʱ�ȭ �Ϸ� �̺�Ʈ set

	SOCKADDR_IN senderAddr;
	int senderAddr_sz = sizeof(senderAddr);
	while (1)
	{
		char rcvBuf[PID_SIZE + sizeof(BOOL) + USERNAME_SIZE + BUFSIZE];

		// ���� ���� �������� ���̿� ���� �ٸ��� ó���ϵ��� �����ߴ�.
		int recvSize = recvfrom(recieveSock, rcvBuf, sizeof(rcvBuf), 0, (SOCKADDR *)&senderAddr, &senderAddr_sz);

		// ���� ��ȭ���� ���� ������ �ִ� ���μ����� �ִ� �� �˻�
		// (������ : PID, ��ȭ��) 
		if (recvSize == PID_SIZE + USERNAME_SIZE)
		{
			DWORD getPID;	// ���޹��� ���μ����� PID
			memcpy((void *)&getPID, rcvBuf, PID_SIZE);
			char getName[USERNAME_SIZE];	// ���޹��� ��ȭ��
			memcpy(getName, rcvBuf + PID_SIZE, USERNAME_SIZE);
			// �ٸ� ���μ���, ���� ��ȭ���� ���
			if (currentPID != getPID && !strcmp(gUserName, getName))
			{
				// ���� ��ȭ���� ���� ������ �ִ� ���μ�����
				// ���� ��ȭ���� ���� �ٸ� ���μ����� PID ���� �����ͷ� �����Ѵ�.
				sendto(senderSock, (char *)&getPID, PID_SIZE, 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr));
			}
		}

		// �ٸ� ���μ����� ���� ���� ��ȭ���� ����ϰ� �ִٸ�
		// �ڽ��� ���μ����� gAlreadySame������ TRUE�� �����Ѵ�.(�ߺ��� ��ȭ�� ��������� ��Ÿ���� ����)
		// (������ : PID)
		else if (recvSize == PID_SIZE)
		{
			DWORD getPID;	// ���޹��� ���μ����� PID
			memcpy((void *)&getPID, rcvBuf, PID_SIZE);
			if (currentPID == getPID)
			{
				gAlreadySame = TRUE;
			}
		}

		// �޼��� ���� ��ư�� ���� ���޹��� �����͸� �޼��� �ڽ��� ����Ѵ�.
		// (������ : PID, gAlreadySame ����, ��ȭ��, ������ �޼���) 
		//		- gAlreadySame ���� : �ߺ��� ��ȭ���� ������̸� TRUE
		else if(recvSize == PID_SIZE + sizeof(BOOL) + USERNAME_SIZE + BUFSIZE)
		{
			DWORD getPID;	// ���� ���� PID
			memcpy((void *)&getPID, rcvBuf, PID_SIZE);
			BOOL getAlreadySame; // ���� ���� ���μ����� �ߺ��� ��ȭ���� ���������
			memcpy((void *)&getAlreadySame, rcvBuf + PID_SIZE, sizeof(BOOL));
			char getName[USERNAME_SIZE]; // ���� ���� ��ȭ��
			memcpy(getName, rcvBuf + PID_SIZE + sizeof(BOOL), USERNAME_SIZE);
			char buf[BUFSIZE];	// ���� ���� �޼���
			memcpy(buf, rcvBuf + PID_SIZE + sizeof(BOOL) + USERNAME_SIZE, BUFSIZE);

			//����ð�
			time_t t = time(NULL);
			struct tm *tm = localtime(&t);
			char totalMsg[PID_SIZE + sizeof(BOOL) + USERNAME_SIZE + BUFSIZE + 128];	// ������ �޼���
			sprintf(totalMsg, "%s(PID : %d)[%s](%d-%02d-%02d %02d:%02d:%02d) : \r\n->%s\r\n", getName, getPID, inet_ntoa(senderAddr.sin_addr),
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec, buf);

			// �޼����� �޼��� ���ڿ� ����.
			HWND hmessage = GetDlgItem(gDlgHandle, ID_MESSAGE_BOX);
			int nLength = GetWindowTextLength(hmessage);
			SendMessage(hmessage, EM_SETSEL, nLength, nLength);
			SendMessage(hmessage, EM_REPLACESEL, FALSE, (LPARAM)totalMsg);

			// ��ȭ���� ���� ����ϴ� ���μ�����
			// �ߺ��� ��ȭ���� ����ϴ� �ٸ� ���μ������� ���� �����͸� ����
			if (GetCurrentProcessId() != getPID && !strcmp(gUserName, getName) && getAlreadySame)
			{
				char buf[PID_SIZE + 1];
				memcpy(buf, (void *)&getPID, PID_SIZE);
				sendto(senderSock, buf, sizeof(buf), 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr));
			}
		}

		// ���޹��� ���� ������
		// (������: PID, �ǹ̾��� 1byte)
		else if (recvSize == PID_SIZE + 1)
		{
			DWORD getPID;	// ���� ���� PID
			memcpy((void*)&getPID, rcvBuf, PID_SIZE);
			
			// �ߺ��� ��ȭ���� ����ϴ� ���μ����� ���� ���
			if (getPID == currentPID)
			{
				char buf[100];
				sprintf(buf, "�ٸ� ������ �̹� ����ϰ� �ִ� ��ȭ�� �Դϴ�.\n(������ �߻��� Process ID : %d)", currentPID);
				MessageBox(NULL, buf, "������ ��ȭ�� ���", MB_ICONERROR);
			}
		}

		// ��ȭ���� ����� ���, ����� ����� �޼��� �ڽ��� ���
		// (������ : ����� ��ȭ��, ������ ��ȭ��, PID)
		else if (recvSize == (USERNAME_SIZE*2 + PID_SIZE))
		{
			char changedName[USERNAME_SIZE];	// ����� ��ȭ��
			memcpy(changedName, rcvBuf, USERNAME_SIZE);
			char prevName[USERNAME_SIZE];		// ������ ��ȭ��
			memcpy(prevName, rcvBuf + USERNAME_SIZE, USERNAME_SIZE);
			DWORD getPID;
			memcpy((void *)&getPID, rcvBuf + USERNAME_SIZE*2, PID_SIZE);

			// ���� �ð�
			time_t t = time(NULL);
			struct tm *tm = localtime(&t);

			char buf[250];
			sprintf(buf, "%s(��)(PID : %d)�� ��ȭ���� %s(��)�� ���� �Ǿ����ϴ�.(%d-%02d-%02d %02d:%02d:%02d)\r\n", prevName, getPID,changedName,
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);

			// ��ȭ�� ���� ����� �޼��� �ڽ��� ���
			HWND hmessage = GetDlgItem(gDlgHandle, ID_MESSAGE_BOX);
			int nLength = GetWindowTextLength(hmessage);
			SendMessage(hmessage, EM_SETSEL, nLength, nLength);
			SendMessage(hmessage, EM_REPLACESEL, FALSE, (LPARAM)buf);
		}
	}
}

DWORD WINAPI Sender(LPVOID arg)
{
	// socket()
	senderSock = socket(PF_INET, SOCK_DGRAM, 0);
	if (senderSock == INVALID_SOCKET) error_message("socket() error!");

	ZeroMemory(&gMulAdr, sizeof(gMulAdr));
	gMulAdr.sin_family = AF_INET;
	gMulAdr.sin_addr.s_addr = inet_addr(gMultiAddr);
	gMulAdr.sin_port = htons(gPort);

	// ��Ƽĳ��Ʈ TTL ����
	int ttl = 2;
	if (setsockopt(senderSock, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl)) == SOCKET_ERROR)
		error_message("setsockopt() error!");

	SetEvent(initSndSockEvent);	// �۽� ���� ����, �ʱ�ȭ �Ϸ� �̺�Ʈ set

	char sendBuf[PID_SIZE + sizeof(BOOL) + USERNAME_SIZE + BUFSIZE];
	while (1)
	{
		// �޼��� ���� ��ư�� ������ blocked ���� ����
		WaitForSingleObject(sendEvent, INFINITE);
		char buf[BUFSIZE];
		GetDlgItemText(gDlgHandle, ID_INPUT_MESSAGE, buf, BUFSIZE);
		memcpy(sendBuf, (void*)&currentPID, PID_SIZE);							// ���ۿ� PID ����
		memcpy(sendBuf + PID_SIZE, (void *)&gAlreadySame, sizeof(BOOL));		// ���ۿ� gAlreadySame ���� (gAlreadySame : �ߺ��� ��ȭ���� ����ϴ� �� ����)
		memcpy(sendBuf + PID_SIZE + sizeof(BOOL), gUserName, USERNAME_SIZE);	// ���ۿ� ��ȭ�� ����
		memcpy(sendBuf + PID_SIZE + sizeof(BOOL) + USERNAME_SIZE, buf, BUFSIZE);			// ���ۿ� ������ �޼��� ����

		// ������(pid, gAlreadySame ������ , ��ȭ��, ������ �޼���) ����
		sendto(senderSock, sendBuf, sizeof(sendBuf), 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr));
		SetDlgItemText(gDlgHandle, ID_INPUT_MESSAGE, "");
	}
}

DWORD WINAPI ChangeUserName(LPVOID arg)
{
	HANDLE events[3] = { changeNameEvent, initRcvSockEvent, initSndSockEvent};
	while (1)
	{
		// ����, ���� ������ ����, �ʱ�ȭ �ǰ�
		// ��ȭ�� ���� ��ư�� ���� ���
		WaitForMultipleObjects(3, events, TRUE, INFINITE);
		char temp[USERNAME_SIZE*2 + PID_SIZE];	
		GetDlgItemText(gDlgHandle, ID_USER_NAME, temp, USERNAME_SIZE); //temp�� ������ ��ȭ�� ����

		// ������ �ƴϰ�, ������ ��ȭ��� �ٸ� ���
		if (strlen(temp) != 0 && strncmp(gUserName, temp, USERNAME_SIZE) != 0)
		{
			memcpy(temp + USERNAME_SIZE, gUserName, USERNAME_SIZE);	// temp�� ������ ��ȭ�� ����
			memcpy(temp + USERNAME_SIZE*2, (void *)&currentPID, PID_SIZE);	// temp�� PID ����
			strncpy(gUserName, temp, USERNAME_SIZE);		// ��ȭ�� ����
			// ������(����� ��ȭ��, ������ ��ȭ��, PID) ����
			sendto(senderSock, temp, sizeof(temp), 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr));
			SetEvent(sameEvent);	// ���� ���̵� �����ϴ� �� üũ�ϴ� �̺�Ʈ set
		}
	}
}

 DWORD WINAPI CheckSame(LPVOID arg)
{
	HANDLE events[3] = { sameEvent, initRcvSockEvent, initSndSockEvent };
	while (1)
	{
		// ����, �۽� ������ ����, �ʱ�ȭ�� �Ϸ�ǰ�
		// ����, ��ȭ�� ���� �� ���� ���̵� �����ϴ� �� �˻��ϰ��� �ϴ� ���
		WaitForMultipleObjects(3, events, TRUE ,INFINITE);
		char buf[PID_SIZE + USERNAME_SIZE];
		memcpy(buf, (void*)&currentPID, sizeof(DWORD));	// ���ۿ� PID ����
		memcpy(buf + sizeof(DWORD), gUserName, USERNAME_SIZE);	// ���ۿ� ��ȭ�� ����
		// ������(PID, ��ȭ��) ����
		sendto(senderSock, buf, sizeof(buf), 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr)); 
	}
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

BOOL getMulticastAddr(HWND hdlg)
{
	GetDlgItemText(hdlg, ID_MULTICAST_ADDR, gMultiAddr, 30);
	if (strlen(gMultiAddr) == 0 || !isClassD(gMultiAddr))
	{
		MessageBox(NULL, "��Ƽ ĳ��Ʈ �ּҸ� �Է��ϼ���. (224.0.0.0 ~ 239.255.255.255)", "��Ƽĳ��Ʈ �ּ� ����", MB_ICONERROR);
		SetDlgItemText(hdlg, ID_MULTICAST_ADDR, "");
		SetFocus(GetDlgItem(hdlg, ID_MULTICAST_ADDR));
		return FALSE;
	}
	return TRUE;
}

BOOL getPortNum(HWND hdlg)
{
	char temp[10];
	GetDlgItemText(hdlg, ID_PORT_NUM, temp, 10);
	gPort = atoi(temp);
	if (gPort == 0 || !(gPort > 0 && gPort <= USHRT_MAX))
	{
		MessageBox(NULL, "�߸��� ��Ʈ ��ȣ �Դϴ�.", "��Ʈ ��ȣ ����", MB_ICONERROR);
		SetDlgItemText(hdlg, ID_PORT_NUM, "");
		SetFocus(GetDlgItem(hdlg, ID_PORT_NUM));
		return FALSE;
	}
	return TRUE;
}

BOOL getUserName(HWND hdlg)
{
	GetDlgItemText(hdlg, ID_USER_NAME, gUserName, USERNAME_SIZE);
	if (strlen(gUserName) == 0)
	{
		MessageBox(NULL, "��ȭ���� �Է��ϼ���.", "��ȭ�� ����", MB_ICONERROR);
		SetFocus(GetDlgItem(hdlg, ID_USER_NAME));
		return FALSE;
	}
	return TRUE;
}

void error_message(const char * msg)
{
	MessageBox(NULL, msg, NULL, MB_ICONERROR);
	exit(-1);
}