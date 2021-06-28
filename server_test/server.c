#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
 
 
/* socket
 * bind
 * listen
 * accept
 * send/recv
 */
 
#define SERVER_PORT 8888
#define BACKLOG     10
 
int main(int argc, char **argv)
{
	int iSocketServer;
	int iSocketClient;
	struct sockaddr_in tSocketServerAddr; //指定服务器绑定地址
	struct sockaddr_in tSocketClientAddr; //保存客户端地址
	int iRet;
	int iAddrLen;
 
	int iRecvLen;
	unsigned char ucRecvBuf[1000];
 
	int iClientNum = -1;
 	printf(" begin \n");
	signal(SIGCHLD,SIG_IGN); //此函数用于处理僵尸进程
	
	iSocketServer = socket(AF_INET, SOCK_STREAM, 0);//AF_INET IPV4连接 SOCK_STREAM启动TCP连接
	if (-1 == iSocketServer)
	{
		printf("socket error!\n");
		return -1;
	}
 
	tSocketServerAddr.sin_family      = AF_INET; //一般设置为
	tSocketServerAddr.sin_port        = htons(SERVER_PORT); //将SERVER_PORT转化为网络字节序 host to net, short
 	tSocketServerAddr.sin_addr.s_addr = INADDR_ANY; //INADDR_ANY表示本机上所有IP
	memset(tSocketServerAddr.sin_zero, 0, 8);
	printf("%d",SERVER_PORT);
 
	int opt = 1;  
    //使用setsockopt函数可以保证端口可被重复绑定
    iRet = setsockopt(iSocketServer, SOL_SOCKET,SO_REUSEADDR,   
    				(const void *)&opt, sizeof(opt) );	
	if (-1 == iRet)
	{
		printf("set sock option error!\n");
		close(iSocketServer);
		return -1;
	}
	
	printf(" iRet:%d \n",iRet);
	iRet = bind(iSocketServer, (const struct sockaddr *)&tSocketServerAddr, sizeof(struct sockaddr)); //绑定端口
	if (-1 == iRet)
	{
		printf("bind error!\n");
		close(iSocketServer);
		return -1;
	}
 	
	iRet = listen(iSocketServer, BACKLOG); //设置监听 BACKLOG代表同时监听10路连接
	if (-1 == iRet)
	{
		printf("listen error!\n");
		return -1;
	}
	 printf(" listen iRet:%d \n",iRet);
	while (1)
	{
		iAddrLen = sizeof(struct sockaddr);
		printf("1:%d",iSocketClient);
		iSocketClient = accept(iSocketServer, (struct sockaddr *)&tSocketClientAddr, &iAddrLen); //等待连接 如果建立连接
		printf("2:%d",iSocketClient);
		printf("waiting accept \n");
		if (-1 != iSocketClient)
		{
			iClientNum++;
			printf("Get connect from client %d : %s\n",  iClientNum, inet_ntoa(tSocketClientAddr.sin_addr));
			if (!fork()) //fork创建子进程 返回值为0的是子进程 
		{
				/* 子进程中处理客户端数据 */
				while (1)
				{
					/* 接收客户端发来的数据并显示出来 */
					iRecvLen = recv(iSocketClient, ucRecvBuf, 999, 0);
					if (iRecvLen <= 0)
					{
						close(iSocketClient); //关闭连接
						return -1;
					}
					else
					{
						ucRecvBuf[iRecvLen] = '\0';
						printf("Get Msg From Client %d: %s\n", iClientNum, ucRecvBuf);
						send(iSocketClient, "ok", 2, 0);//打印的同时发送一条数据给连接的客户端
					}
				}				
			}
		}
	}
	
	close(iSocketServer);
	return 0;
}

