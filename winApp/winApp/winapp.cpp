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

HWND hHandle;		// 다이얼 로그 핸들값
SOCKET recieveSock, senderSock;
HANDLE sendEvent;	// 보내기 버튼을 누를 경우 신호상태로 만든다(Sender 스레드 blocked 상태 해제)
HANDLE sameEvent;
BOOL alreadySame = FALSE;	//같은 아이디가 이미 존재하면 TRUE

char multiAddr[30];
int port;
char userName[30];
char buf[BUFSIZE + 1];
const DWORD pid = GetCurrentProcessId();	// 프로세스 ID
DWORD getPid;

SOCKADDR_IN mulAdr;

BOOL CALLBACK DlgProc(HWND hdlg, UINT iMsg, WPARAM wParam, LPARAM lParam);
BOOL isClassD(const char * addr);
DWORD WINAPI Receiver(LPVOID arg);
DWORD WINAPI Sender(LPVOID arg);
DWORD WINAPI CheckSame(LPVOID arg);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	WSADATA wsaData;
	WSAStartup(WINSOCK_VERSION, &wsaData);
	sendEvent = CreateEvent(NULL, FALSE, FALSE, NULL);	//비신호 상태
	sameEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DlgProc);

	CloseHandle(sendEvent);
	CloseHandle(sameEvent);
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
		EnableWindow(hMsg, FALSE);			// 초기 상태에서 가입을 하지 않으면 메세지를 보낼 수 없다.
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
				MessageBox(NULL, "멀티 캐스트 주소를 입력하세요. (224.0.0.0 ~ 239.255.255.255)", "멀티캐스트 주소 에러", MB_ICONERROR);
				SetDlgItemText(hdlg, ID_MULTICAST_ADDR, "");
				SetFocus(GetDlgItem(hdlg, ID_MULTICAST_ADDR));
				break;
			}

			GetDlgItemText(hdlg, ID_PORT_NUM, temp, 10);
			port = atoi(temp);
			if (port == 0 || !(port > 0 && port <= USHRT_MAX))
			{
				MessageBox(NULL, "잘못된 포트 번호 입니다.", "포트 번호 에러", MB_ICONERROR);
				SetDlgItemText(hdlg, ID_PORT_NUM, "");
				SetFocus(GetDlgItem(hdlg, ID_PORT_NUM));
				break;
			}

			GetDlgItemText(hdlg, ID_USER_NAME, userName, 30);
			if (strlen(userName) == 0)
			{
				MessageBox(NULL, "대화명을 입력하세요.", "대화명 에러", MB_ICONERROR);
				SetFocus(GetDlgItem(hdlg, ID_USER_NAME));
				break;
			}
			hMsg = GetDlgItem(hdlg, ID_SEND_MESSAGE);
			EnableWindow(hMsg, TRUE);
			CreateThread(NULL, 0, Receiver, NULL, 0, NULL);
			CreateThread(NULL, 0, Sender, NULL, 0, NULL);
			CreateThread(NULL, 0, CheckSame, NULL, 0, NULL);

			EnableWindow(GetDlgItem(hdlg, ID_REGISTER), FALSE);	//가입 못하게(좀더 예쁘게 나중에 수정하자)
			return TRUE;
		case ID_CHANGE_NAME:
			if(recieveSock == NULL || senderSock == NULL)
				MessageBox(NULL, "가입한 후에 변경 가능합니다.", "대화명 변경 에러", MB_ICONERROR);
			else
			{
				char temp[30+30 + sizeof(DWORD)];
				GetDlgItemText(hdlg, ID_USER_NAME, temp, 30);
				if (strlen(temp) != 0 && strncmp(userName, temp, 30) != 0)
				{
					memcpy(temp + 30, userName, 30);
					memcpy(temp + 60, (void *)&pid, sizeof(DWORD));
					strncpy(userName, temp, 30);
					sendto(senderSock, temp, 30 + 30 + sizeof(DWORD), 0, (SOCKADDR *)&mulAdr, sizeof(mulAdr));	//변경된 아이디를 전달
					SetEvent(sameEvent);	// 같은 아이디가 존재하는 지 체크하는 스레드 Block 해제
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

	// SO_REUSEADDR 옵션 설정
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

	// 멀티캐스트 그룹 가입
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr(multiAddr);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(recieveSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR)
		exit(-1);
	
	SOCKADDR_IN senderAddr;
	int senderAddr_sz = sizeof(senderAddr);
	while (1)
	{
		char rcvBuf[sizeof(DWORD) + sizeof(BOOL) + 30 + BUFSIZE];
		int recvSize = recvfrom(recieveSock, rcvBuf, sizeof(rcvBuf), 0, (SOCKADDR *)&senderAddr, &senderAddr_sz);

		if (recvSize == sizeof(DWORD) + 30)	// 대화명과 PID 전달해서 같은 대화명이 있는 프로세스가 있는 지 검사
		{
			DWORD tempPid;
			memcpy((void *)&tempPid, rcvBuf, sizeof(DWORD));
			char tempName[30];
			memcpy(tempName, rcvBuf + sizeof(DWORD), 30);
			if (GetCurrentProcessId() != tempPid && !strcmp(userName, tempName))
			{
				sendto(senderSock, (char *)&tempPid, sizeof(DWORD), 0, (SOCKADDR *)&mulAdr, sizeof(mulAdr));
			}
		}
		else if (recvSize == sizeof(DWORD))	// 같은 대화명이 이미 존재하는 프로세스를 찾는 
		{
			DWORD tempPid;
			memcpy((void *)&tempPid, rcvBuf, sizeof(DWORD));
			if (GetCurrentProcessId() == tempPid) // 같은 대화명을 가진 프로세스 
			{
				alreadySame = TRUE;
			}
		}
		else if(recvSize == sizeof(DWORD) + sizeof(BOOL) + 30 + BUFSIZE)
		{
			char cMsg[BUFSIZE + 256];
			//현재시간
			time_t t = time(NULL);
			struct tm *tm = localtime(&t);

			memcpy((void *)&getPid, rcvBuf, sizeof(DWORD));	//pid
			BOOL getAlreadySame;
			memcpy((void *)&getAlreadySame, rcvBuf + sizeof(DWORD), sizeof(BOOL));	// 보낸 곳의 alreaySame
			char senderName[30];
			memcpy(senderName, rcvBuf + sizeof(DWORD) + sizeof(BOOL), 30);
			memcpy(buf, rcvBuf + sizeof(DWORD) + sizeof(BOOL)+ 30, BUFSIZE);	// 굳이 전역변수 buf 로 둔 이유?

			sprintf(cMsg, "%s[%s](%d-%d-%d %d:%d:%d)(PID : %d) : \r\n->%s\r\n", senderName, inet_ntoa(senderAddr.sin_addr), 
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec, getPid, buf);

			HWND hmessage = GetDlgItem(hHandle, ID_MESSAGE_BOX);
			int nLength = GetWindowTextLength(hmessage);
			SendMessage(hmessage, EM_SETSEL, nLength, nLength);
			SendMessage(hmessage, EM_REPLACESEL, FALSE, (LPARAM)cMsg);

			if (GetCurrentProcessId() != getPid && !strcmp(userName, senderName) && getAlreadySame)
			{
				char buf[sizeof(DWORD) + 1];
				memcpy(buf, (void *)&getPid, sizeof(DWORD));
				sendto(senderSock, buf, sizeof(buf), 0, (SOCKADDR *)&mulAdr, sizeof(mulAdr));
			}
		}
		else if (recvSize == sizeof(DWORD) + 1)
		{
			DWORD tempPid;
			memcpy((void*)&tempPid, rcvBuf, sizeof(DWORD));
			if (tempPid == GetCurrentProcessId())
			{
				char buf[40];
				sprintf(buf, "다른 유저가 사용하고 있는 대화명 입니다.\n(오류가 발생한 Process ID : %d)", GetCurrentProcessId());
				MessageBox(NULL, buf, "동일한 대화명 사용", MB_ICONERROR);
			}
		}
		else if (recvSize == (30 + 30 + sizeof(DWORD)))
		{
			char changedName[30];
			strncpy(changedName, rcvBuf, 30);
			char prevName[30];
			strncpy(prevName, rcvBuf + 30, 30);
			DWORD tempPid;
			memcpy((void *)&tempPid, rcvBuf + 60, sizeof(DWORD));

			time_t t = time(NULL);
			struct tm *tm = localtime(&t);

			char buf[100];
			sprintf(buf, "%s(님)(PID : %d)의 대화명이 %s(으)로 변경 되었습니다.(%d-%d-%d %d:%d:%d)\r\n", prevName, tempPid ,changedName, 
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);
			HWND hmessage = GetDlgItem(hHandle, ID_MESSAGE_BOX);
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
	if (senderSock == INVALID_SOCKET) exit(-1);

	ZeroMemory(&mulAdr, sizeof(mulAdr));
	mulAdr.sin_family = AF_INET;
	mulAdr.sin_addr.s_addr = inet_addr(multiAddr);
	mulAdr.sin_port = htons(port);

	// 멀티캐스트 TTL 설정
	int ttl = 2;
	if (setsockopt(senderSock, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl)) == SOCKET_ERROR)
		exit(-1);

	SetEvent(sameEvent);	// 같은 아이디가 존재하는 지 체크하는 스레드 Block 해제
	char sendBuf[sizeof(DWORD) + sizeof(BOOL) + 30 + BUFSIZE];
	while (1)
	{
		WaitForSingleObject(sendEvent, INFINITE);
		GetDlgItemText(hHandle, ID_INPUT_MESSAGE, buf, 512);
		memcpy(sendBuf, (void*)&pid, sizeof(DWORD));			// PID
		memcpy(sendBuf + sizeof(DWORD), (void *)&alreadySame, sizeof(BOOL));	// alreaySame
		memcpy(sendBuf + sizeof(DWORD) + sizeof(BOOL), userName, 30);			// userName
		memcpy(sendBuf + sizeof(DWORD) + sizeof(BOOL) + 30, buf, BUFSIZE);		// BUF

		sendto(senderSock, sendBuf, sizeof(sendBuf), 0, (SOCKADDR *)&mulAdr, sizeof(mulAdr));
		SetDlgItemText(hHandle, ID_INPUT_MESSAGE, "");
	}
}

 DWORD WINAPI CheckSame(LPVOID arg)
{
	while (1)
	{
		WaitForSingleObject(sameEvent, INFINITE);
		char buf[sizeof(DWORD) + 30];
		memcpy(buf, (void*)&pid, sizeof(DWORD));
		memcpy(buf + sizeof(DWORD), userName, 30);
		sendto(senderSock, buf, sizeof(DWORD) + 30, 0, (SOCKADDR *)&mulAdr, sizeof(mulAdr));	// 같은 아이디가 존재하는지 체크
	}
}
BOOL isClassD(const char * addr)
{
	ULONG uAddr;
	if ((uAddr = inet_addr(addr)) == INADDR_NONE) return FALSE;	// 주소 변환에 실패한 경우
	uAddr %= 256;
	if (uAddr >= 224 && uAddr <= 239)
		return TRUE;
	else
		return FALSE;
}