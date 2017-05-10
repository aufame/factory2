#include "mc_routine.h" 
//---------------------------------------------------------------------------
static int svrUdpSocket=-1,svrTcpSocket=-1;
//---------------------------------------------------------------------------
static void SetSocketBuffer(int sockd,int recvBufsize,int sendBufsize)
{	if(recvBufsize)
	{ if(setsockopt(sockd,SOL_SOCKET,SO_RCVBUF,(char*)&recvBufsize,sizeof(int))==0)
		{ int len=sizeof(int),result;
	  	if(getsockopt(sockd,SOL_SOCKET, SO_RCVBUF, (char*)&result, (socklen_t *)&len)==0)
	  	{ result>>=1;//���õ�ֵ��ʵ�ʶ�����ֵ��������ϵ
	  		if(result!=recvBufsize)printf("SET SO_RCVBUF to %d,but limited to %d,pelease check config[/proc/sys/net/core/rmem_max]\r\n",recvBufsize,result);
	  	}
		}else printf("SET SO_RCVBUF failed\r\n");
  }	
  if(sendBufsize)
	{	if(setsockopt(sockd,SOL_SOCKET,SO_SNDBUF,(char*)&sendBufsize,sizeof(int))==0)
		{ int len=sizeof(int),result;
	  	if(getsockopt(sockd,SOL_SOCKET, SO_SNDBUF, (char*)&result, (socklen_t *)&len)==0)
	  	{ result>>=1;
	  		if(result!=sendBufsize)printf("SET SO_SNDBUF to %d,but limited to %d,pelease check config[/proc/sys/net/core/wmem_max]\r\n",sendBufsize,result);
	  	}	
		}
  }else printf("SET SO_SNDBUF failed\r\n");	
}
//---------------------------------------------------------------------------
static BOOL packet_checksum_and_decrypt(TMcPacket *packet)
{ TMcMsg *msg=&packet->msg;
	int msgLen=MC_MSG_SIZE(msg);
	if(msg_ValidChecksum(msg,msgLen))
	{	packet->terminal=(msg->sessionid)?(TTerminal *)dtmr_find(terminalLinks,msg->sessionid,0,NULL,(msg->msgid==MSG_TSR_HEARTBEAT)?HEARTBEAT_OVERTIME_S:0):NULL;
		if(packet->terminal)
		{	if(packet->terminal->spyAddr.ip)
		  { hsk_sendData(msg,(msgLen<MAXLEN_MSG_UDP)?msgLen:MAXLEN_MSG_UDP,&packet->terminal->spyAddr);
		  }
		  if(packet->peerAddr.ip!=packet->terminal->loginAddr.ip || (packet->peerAddr.socket==svrUdpSocket&& packet->peerAddr.port!=packet->terminal->loginAddr.port))
      { //�����sessionid��IP��ַ�ǰ󶨵Ĺ�ϵ���������Ӧ��ʾsessionid�Ѿ�ʧЧ��
  	    //����TCP��UDP�в�ͬ�Ķ˿ڣ�����ֻ��֤UDP�˿ڵİ󶨹�ϵ��
  	    #if 0
  	    static error_count=0;
  	    error_count++; 
  	    if(packet->peerAddr.socket==svrUdpSocket&& packet->peerAddr.port!=packet->terminal->loginAddr.port)
  	    { printf("####%2d#######packet->peerAddr.socket==svrUdpSocket&& packet->peerAddr.port!=packet->terminal->loginAddr.port,%u!=%u::%d::%u\r\n",error_count,packet->peerAddr.port,packet->terminal->loginAddr.port,packet->terminal->term_type,packet->terminal->id);  	    	
  	    }
  	    #endif
  	    packet->terminal=NULL;
  	    
      }
  	}
		if(msg->bodylen>0 && msg->encrypt>ENCRYPTION_NONE) msg_decrypt(msg);
	  return TRUE;		
	}
	return FALSE;
}
//---------------------------------------------------------------------------
TMcPacket *NET_RecvPacket(void *dgram)
{ TMcPacket *packet=(TMcPacket *)dgram;
	TMcMsg *msg=&packet->msg;
	int msgsize,sliceLen=hsk_readData(msg,MAXLEN_MSG_UDP,&packet->peerAddr);

	#ifdef DEBUG_MODE
    Log_AppendData(msg,sliceLen,&packet->peerAddr,FALSE);
  #endif

  if(sliceLen>sizeof(TMcMsg))
  { msgsize=MC_MSG_SIZE(msg);
    if(sliceLen==msgsize && packet_checksum_and_decrypt(packet))return packet; 
    else if(msg->bodylen>MAXLEN_MSG_TCP)msgsize=0;
 	}
 	else
 	{ if(!sliceLen)return NULL;
 		msgsize=0;
 	}
 	 
  if(packet->peerAddr.socket!=svrUdpSocket) //���TCP�������ݽ�����װ 	
  {	 /*BOOL bMsgHead=(sliceLen>=sizeof(TMcMsg) && (msg->msgid==MSG_USR_CHANGEHEAD||msg->msgid==MSG_DSR_COMMJSON) && msg->bodylen>0 && msg->bodylen<(MAXLEN_MSG_TCP-sizeof(TMcMsg)) );
     packet=(TMcPacket *)hsk_assemble(&packet->peerAddr,msg,sliceLen,(bMsgHead)?msgsize:0);
     */
     packet=(TMcPacket *)hsk_assemble(&packet->peerAddr,msg,sliceLen,msgsize);
     if(packet)
     { if(packet_checksum_and_decrypt(packet))return packet;
     	 else hsk_releasePacket((THskPacket *)packet); 
     }
  }
  else 
  {  //����У������UDP����(����ת������ض� ,���ڸ��ӶȽ������������TCP����)
  	 TTerminal *terminal=dtmr_find2(terminalLinks,0,0,&packet->peerAddr,sizeof(TNetAddr),T_NODE_OFFSET(TTerminal,loginAddr),0);
  	 if(terminal && terminal->spyAddr.ip)hsk_sendData(msg,sliceLen,&terminal->spyAddr);	
  }
  
  return NULL;  	
}
//---------------------------------------------------------------------------
static void *mc_dispatch(void *handler)
{ void *pbuf=malloc(sizeof(TMcPacket)+MAXLEN_MSG_UDP);
  while(1)//process user request packet  
  { TMcPacket *packet=NET_RecvPacket(pbuf);
    if(packet)
    {  if(packet->terminal)
    	{ DBLog_AppendMsg(&packet->msg,packet->terminal,FALSE);
    	}
  	((void (*)(TMcPacket *))handler)(packet);
  	hsk_releasePacket((THskPacket *)packet);
    }	
  }
  return NULL;
}
//---------------------------------------------------------------------------
void mc_handler(void* handler)
{ int i;
	for(i=0;i<NUM_DISPATCH_THREAD;i++)
	{	pthread_t _thread=0;
		pthread_create(&_thread, NULL,mc_dispatch,handler);
		//printf("Create dispatch-thread-%02d...%s!\r\n",i+1,(_thread)?"OK":"failed");	
	}
  puts("Maow daemon service Ver "MEOW_SERVICE_VERSION" @"WEB_SERVER_HOST",running...");
}
//---------------------------------------------------------------------------
void net_init(void)
{ if(hsk_init(SERVICE_PORT_UDP,SERVICE_PORT_TCP,SIZE_NET_RECV_BUFFER,MAXLEN_MSG_TCP))
	{ svrUdpSocket=hsk_getUdpSocket();
		svrTcpSocket=hsk_getTcpSocket();
		SetSocketBuffer(svrUdpSocket,MAX_SOCKET_RECV_MEM,MAX_SOCKET_SEND_MEM);
		SetSocketBuffer(svrTcpSocket,MAX_SOCKET_RECV_MEM,MAX_SOCKET_SEND_MEM);
	}
	else
	{ Log_AppendText("Net init error!");
    exit(0);//should not be here
	}		
}
//-----------------------------------------------------------------------------