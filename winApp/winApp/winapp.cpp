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


HWND gDlgHandle;						// 다이얼 로그 핸들값
SOCKET recieveSock, senderSock;		// 수신 소켓과 송신 소켓
HANDLE sendEvent;					// 메세지 전송 버튼을 누를 경우 set되는 이벤트 (Sender 스레드 blocked 상태 해제)
HANDLE sameEvent;					// 같은 대화명 존재하는지 확인할때 set되는 이벤트
HANDLE changeNameEvent;				// 대화명을 변경하는 경우 set 되는 이벤트
HANDLE initRcvSockEvent, initSndSockEvent;	// 수신, 송신 소켓이 생성,초기화 과정을 모두 마쳤을 경우 이벤트 발생

BOOL gAlreadySame = FALSE;			// 같은 대화명이 이미 존재할 경우 TRUE 로 변경됨

char gMultiAddr[30];					// 멀티캐스트 주소
int gPort;							// 포트
char gUserName[USERNAME_SIZE];					// 대화명
SOCKADDR_IN gMulAdr;					// 멀티캐스트 목적지 주소
const DWORD currentPID = GetCurrentProcessId();	// 현재 프로세스 ID


BOOL CALLBACK DlgProc(HWND hdlg, UINT iMsg, WPARAM wParam, LPARAM lParam);	// 다이얼로그
DWORD WINAPI Receiver(LPVOID arg);	// 수신한 데이터의 길이에 따라 데이터를 처리하는 스레드
DWORD WINAPI Sender(LPVOID arg);	// 메세지를 보내는 스레드(메세지 전송 버튼을 누를 경우)
DWORD WINAPI CheckSame(LPVOID arg);	// 가입, 대화명을 변경하면 기존에 같은 대화명이 있는지 체크하는 스레드
DWORD WINAPI ChangeUserName(LPVOID arg);	// 대화명을 변경할 경우

BOOL isClassD(const char * addr);
BOOL getMulticastAddr(HWND hdlg);
BOOL getPortNum(HWND hdlg);
BOOL getUserName(HWND hdlg);
void error_message(const char * msg);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	WSADATA wsaData;
	WSAStartup(WINSOCK_VERSION, &wsaData);
	sendEvent = CreateEvent(NULL, FALSE, FALSE, NULL);		// 메세지 전송 버튼을 누를 경우 set(초기상태: reset)
	sameEvent = CreateEvent(NULL, FALSE, FALSE, NULL);		// 같은 대화명 존재하는지 확인할때 set(초기상태: reset)
	changeNameEvent = CreateEvent(NULL, FALSE, FALSE, NULL);	// 대화명을 변경하는 경우 set (초기상태: reset)
	initRcvSockEvent = CreateEvent(NULL, TRUE, FALSE, NULL);	// 수신 소켓이 생성과정을 마쳤을 경우 set(초기상태: reset)
	initSndSockEvent = CreateEvent(NULL, TRUE, FALSE, NULL);	// 송신 소켓이 생성과정을 마쳤을 경우 set(초기상태: reset)

	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DlgProc);	//다이얼로그 박스 생성

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
	// 초기 상태
	case WM_INITDIALOG:
		gDlgHandle = hdlg;		// 다이얼로그 핸들 값 전역 변수에 저장
		EnableWindow(GetDlgItem(hdlg, ID_SEND_MESSAGE), FALSE);			// 초기 상태에서 가입을 하지 않으면 메세지를 보낼 수 없다.
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		// 종료 버튼을 누른 경우
		case IDCANCEL:
			EndDialog(hdlg, 0);
			return TRUE;
		// 가입 버튼을 누른 경우
		case ID_REGISTER:
			if (!getMulticastAddr(hdlg)) break;	// 멀티 캐스트 주소를 입력 받고 확인한다.
			if (!getPortNum(hdlg)) break;		// 포트 번호를 입력 받고 확인한다.
			if (!getUserName(hdlg)) break;		// 대화명을 입력 받고 확인한다.

			// 멀티캐스트 주소, 포트, 대화명이 문제 없는 경우
			EnableWindow(GetDlgItem(hdlg, ID_SEND_MESSAGE), TRUE);	// 메세지 전송 버튼 활성화
			// 스레드 생성
			CreateThread(NULL, 0, Receiver, NULL, 0, NULL);			
			CreateThread(NULL, 0, Sender, NULL, 0, NULL);
			CreateThread(NULL, 0, ChangeUserName, NULL, 0, NULL);
			CreateThread(NULL, 0, CheckSame, NULL, 0, NULL);

			EnableWindow(GetDlgItem(hdlg, ID_REGISTER), FALSE);	// 가입이 완료되면 가입 버튼 비활성화
			SetEvent(sameEvent); // 같은 아이디가 존재하는 지 체크하는 이벤트 set
			return TRUE;
		// 대화명 변경 버튼을 누른 경우
		case ID_CHANGE_NAME:
			if (recieveSock == NULL && senderSock == NULL)
			{
				MessageBox(NULL, "가입한 후에 변경 가능합니다.", "대화명 변경 에러", MB_ICONERROR);
				break;
			}
			SetEvent(changeNameEvent);
			return TRUE;
		// 메세지 전송 버튼을 누른 경우
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

	// SO_REUSEADDR 옵션 설정
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

	// 멀티캐스트 그룹 가입
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr(gMultiAddr);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(recieveSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR)
		error_message("setsockopt() error!");
	
	SetEvent(initRcvSockEvent);	// 수신 소켓 생성, 초기화 완료 이벤트 set

	SOCKADDR_IN senderAddr;
	int senderAddr_sz = sizeof(senderAddr);
	while (1)
	{
		char rcvBuf[PID_SIZE + sizeof(BOOL) + USERNAME_SIZE + BUFSIZE];

		// 전달 받은 데이터의 길이에 따라 다르게 처리하도록 구현했다.
		int recvSize = recvfrom(recieveSock, rcvBuf, sizeof(rcvBuf), 0, (SOCKADDR *)&senderAddr, &senderAddr_sz);

		// 같은 대화명을 먼저 가지고 있는 프로세스가 있는 지 검사
		// (데이터 : PID, 대화명) 
		if (recvSize == PID_SIZE + USERNAME_SIZE)
		{
			DWORD getPID;	// 전달받은 프로세스의 PID
			memcpy((void *)&getPID, rcvBuf, PID_SIZE);
			char getName[USERNAME_SIZE];	// 전달받은 대화명
			memcpy(getName, rcvBuf + PID_SIZE, USERNAME_SIZE);
			// 다른 프로세스, 같은 대화명인 경우
			if (currentPID != getPID && !strcmp(gUserName, getName))
			{
				// 같은 대화명을 먼저 가지고 있는 프로세스는
				// 같은 대화명을 가진 다른 프로세스의 PID 값을 데이터로 전달한다.
				sendto(senderSock, (char *)&getPID, PID_SIZE, 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr));
			}
		}

		// 다른 프로세스가 먼저 같은 대화명을 사용하고 있다면
		// 자신의 프로세스의 gAlreadySame변수를 TRUE로 설정한다.(중복된 대화명 사용중임을 나타내기 위해)
		// (데이터 : PID)
		else if (recvSize == PID_SIZE)
		{
			DWORD getPID;	// 전달받은 프로세스의 PID
			memcpy((void *)&getPID, rcvBuf, PID_SIZE);
			if (currentPID == getPID)
			{
				gAlreadySame = TRUE;
			}
		}

		// 메세지 전송 버튼을 눌러 전달받은 데이터를 메세지 박스에 출력한다.
		// (데이터 : PID, gAlreadySame 변수, 대화명, 전송할 메세지) 
		//		- gAlreadySame 변수 : 중복된 대화명을 사용중이면 TRUE
		else if(recvSize == PID_SIZE + sizeof(BOOL) + USERNAME_SIZE + BUFSIZE)
		{
			DWORD getPID;	// 전달 받은 PID
			memcpy((void *)&getPID, rcvBuf, PID_SIZE);
			BOOL getAlreadySame; // 전달 받은 프로세스가 중복된 대화명을 사용중인지
			memcpy((void *)&getAlreadySame, rcvBuf + PID_SIZE, sizeof(BOOL));
			char getName[USERNAME_SIZE]; // 전달 받은 대화명
			memcpy(getName, rcvBuf + PID_SIZE + sizeof(BOOL), USERNAME_SIZE);
			char buf[BUFSIZE];	// 전달 받은 메세지
			memcpy(buf, rcvBuf + PID_SIZE + sizeof(BOOL) + USERNAME_SIZE, BUFSIZE);

			//현재시간
			time_t t = time(NULL);
			struct tm *tm = localtime(&t);
			char totalMsg[PID_SIZE + sizeof(BOOL) + USERNAME_SIZE + BUFSIZE + 128];	// 통합한 메세지
			sprintf(totalMsg, "%s(PID : %d)[%s](%d-%02d-%02d %02d:%02d:%02d) : \r\n->%s\r\n", getName, getPID, inet_ntoa(senderAddr.sin_addr),
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec, buf);

			// 메세지를 메세지 상자에 띄운다.
			HWND hmessage = GetDlgItem(gDlgHandle, ID_MESSAGE_BOX);
			int nLength = GetWindowTextLength(hmessage);
			SendMessage(hmessage, EM_SETSEL, nLength, nLength);
			SendMessage(hmessage, EM_REPLACESEL, FALSE, (LPARAM)totalMsg);

			// 대화명을 먼저 사용하는 프로세스가
			// 중복된 대화명을 사용하는 다른 프로세스에게 오류 데이터를 전달
			if (GetCurrentProcessId() != getPID && !strcmp(gUserName, getName) && getAlreadySame)
			{
				char buf[PID_SIZE + 1];
				memcpy(buf, (void *)&getPID, PID_SIZE);
				sendto(senderSock, buf, sizeof(buf), 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr));
			}
		}

		// 전달받은 오류 데이터
		// (데이터: PID, 의미없는 1byte)
		else if (recvSize == PID_SIZE + 1)
		{
			DWORD getPID;	// 전달 받은 PID
			memcpy((void*)&getPID, rcvBuf, PID_SIZE);
			
			// 중복된 대화명을 사용하는 프로세스만 오류 출력
			if (getPID == currentPID)
			{
				char buf[100];
				sprintf(buf, "다른 유저가 이미 사용하고 있는 대화명 입니다.\n(오류가 발생한 Process ID : %d)", currentPID);
				MessageBox(NULL, buf, "동일한 대화명 사용", MB_ICONERROR);
			}
		}

		// 대화명이 변경된 경우, 변경된 결과를 메세지 박스에 출력
		// (데이터 : 변경된 대화명, 변경전 대화명, PID)
		else if (recvSize == (USERNAME_SIZE*2 + PID_SIZE))
		{
			char changedName[USERNAME_SIZE];	// 변경된 대화명
			memcpy(changedName, rcvBuf, USERNAME_SIZE);
			char prevName[USERNAME_SIZE];		// 변경전 대화명
			memcpy(prevName, rcvBuf + USERNAME_SIZE, USERNAME_SIZE);
			DWORD getPID;
			memcpy((void *)&getPID, rcvBuf + USERNAME_SIZE*2, PID_SIZE);

			// 현재 시간
			time_t t = time(NULL);
			struct tm *tm = localtime(&t);

			char buf[250];
			sprintf(buf, "%s(님)(PID : %d)의 대화명이 %s(으)로 변경 되었습니다.(%d-%02d-%02d %02d:%02d:%02d)\r\n", prevName, getPID,changedName,
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);

			// 대화명 변경 결과를 메세지 박스에 출력
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

	// 멀티캐스트 TTL 설정
	int ttl = 2;
	if (setsockopt(senderSock, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl)) == SOCKET_ERROR)
		error_message("setsockopt() error!");

	SetEvent(initSndSockEvent);	// 송신 소켓 생성, 초기화 완료 이벤트 set

	char sendBuf[PID_SIZE + sizeof(BOOL) + USERNAME_SIZE + BUFSIZE];
	while (1)
	{
		// 메세지 전송 버튼을 누르면 blocked 상태 해제
		WaitForSingleObject(sendEvent, INFINITE);
		char buf[BUFSIZE];
		GetDlgItemText(gDlgHandle, ID_INPUT_MESSAGE, buf, BUFSIZE);
		memcpy(sendBuf, (void*)&currentPID, PID_SIZE);							// 버퍼에 PID 저장
		memcpy(sendBuf + PID_SIZE, (void *)&gAlreadySame, sizeof(BOOL));		// 버퍼에 gAlreadySame 저장 (gAlreadySame : 중복된 대화명을 사용하는 지 여부)
		memcpy(sendBuf + PID_SIZE + sizeof(BOOL), gUserName, USERNAME_SIZE);	// 버퍼에 대화명 저장
		memcpy(sendBuf + PID_SIZE + sizeof(BOOL) + USERNAME_SIZE, buf, BUFSIZE);			// 버퍼에 전송할 메세지 저장

		// 데이터(pid, gAlreadySame 변수값 , 대화명, 전송할 메세지) 전달
		sendto(senderSock, sendBuf, sizeof(sendBuf), 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr));
		SetDlgItemText(gDlgHandle, ID_INPUT_MESSAGE, "");
	}
}

DWORD WINAPI ChangeUserName(LPVOID arg)
{
	HANDLE events[3] = { changeNameEvent, initRcvSockEvent, initSndSockEvent};
	while (1)
	{
		// 수신, 생성 소켓이 생성, 초기화 되고
		// 대화명 변경 버튼을 누른 경우
		WaitForMultipleObjects(3, events, TRUE, INFINITE);
		char temp[USERNAME_SIZE*2 + PID_SIZE];	
		GetDlgItemText(gDlgHandle, ID_USER_NAME, temp, USERNAME_SIZE); //temp에 변경후 대화명 저장

		// 공백이 아니고, 기존의 대화명과 다른 경우
		if (strlen(temp) != 0 && strncmp(gUserName, temp, USERNAME_SIZE) != 0)
		{
			memcpy(temp + USERNAME_SIZE, gUserName, USERNAME_SIZE);	// temp에 변경전 대화명 저장
			memcpy(temp + USERNAME_SIZE*2, (void *)&currentPID, PID_SIZE);	// temp에 PID 저장
			strncpy(gUserName, temp, USERNAME_SIZE);		// 대화명 변경
			// 데이터(변경된 대화명, 변경전 대화명, PID) 전달
			sendto(senderSock, temp, sizeof(temp), 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr));
			SetEvent(sameEvent);	// 같은 아이디가 존재하는 지 체크하는 이벤트 set
		}
	}
}

 DWORD WINAPI CheckSame(LPVOID arg)
{
	HANDLE events[3] = { sameEvent, initRcvSockEvent, initSndSockEvent };
	while (1)
	{
		// 수신, 송신 소켓이 생성, 초기화가 완료되고
		// 가입, 대화명 변경 시 같은 아이디가 존재하는 지 검사하고자 하는 경우
		WaitForMultipleObjects(3, events, TRUE ,INFINITE);
		char buf[PID_SIZE + USERNAME_SIZE];
		memcpy(buf, (void*)&currentPID, sizeof(DWORD));	// 버퍼에 PID 저장
		memcpy(buf + sizeof(DWORD), gUserName, USERNAME_SIZE);	// 버퍼에 대화명 저장
		// 데이터(PID, 대화명) 전달
		sendto(senderSock, buf, sizeof(buf), 0, (SOCKADDR *)&gMulAdr, sizeof(gMulAdr)); 
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

BOOL getMulticastAddr(HWND hdlg)
{
	GetDlgItemText(hdlg, ID_MULTICAST_ADDR, gMultiAddr, 30);
	if (strlen(gMultiAddr) == 0 || !isClassD(gMultiAddr))
	{
		MessageBox(NULL, "멀티 캐스트 주소를 입력하세요. (224.0.0.0 ~ 239.255.255.255)", "멀티캐스트 주소 에러", MB_ICONERROR);
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
		MessageBox(NULL, "잘못된 포트 번호 입니다.", "포트 번호 에러", MB_ICONERROR);
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
		MessageBox(NULL, "대화명을 입력하세요.", "대화명 에러", MB_ICONERROR);
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