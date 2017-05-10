#include "mc_routine.h"
//---------------------------------------------------------------------------
void spy_notify(U8 value, TNetAddr *spyAddr)
{ TMcMsg *msg=msg_alloc(MSG_STR_SPYNOTIFY,sizeof(TMSG_STR_SPYNOTIFY));
	int  msgLen=MC_MSG_SIZE(msg);
	msg->encrypt=ENCRYPTION_NONE;
	((TMSG_STR_SPYNOTIFY *)msg->body)->value=value;
	msg_UpdateChecksum(msg,msgLen);  //更新校验位 
	hsk_sendData(msg,msgLen,spyAddr);//发送消息包
}

void spy_forwardLoginRequest(TMcMsg *msg,TNetAddr *spyAddr)
{ int msgLen;
	U8 encrypt=msg->encrypt;
	if(encrypt)
	{	msg->encrypt=0;
 		msg->bodylen=(msg->msgid==MSG_USR_LOGIN)?sizeof(TMSG_USR_LOGIN):sizeof(TMSG_DSR_LOGIN);
 		msgLen=MC_MSG_SIZE(msg);
 		msg_UpdateChecksum(msg,msgLen); 
  }
  else
  { msgLen=MC_MSG_SIZE(msg);
  }	 	
 	hsk_sendData(msg,msgLen,spyAddr);
  if(encrypt)msg->encrypt=encrypt;
}

//---------------------------------------------------------------------------
void Handle_MSG_TSR_SPYLOGIN(TMcPacket *packet)
{ TMSG_TSR_SPYLOGIN *req=(TMSG_TSR_SPYLOGIN *)packet->msg.body;
	U32 sessionid=0;
	U8 login_error=-1;
	if(MobilePhone_check(req->name))
	{ if(!Password_check(req->psw))login_error=SPY_IDDENTIFY_ERR;//用户名或密码错误 
		else
    {	MYSQL_RES *res=db_queryf("select session from `mc_users` where username='%s' and password=md5('%s')",req->name,req->psw);
    	if(res)
    	{	MYSQL_ROW row=mysql_fetch_row(res);
       if(row)sessionid=atoi(row[0]);
       else login_error=SPY_IDDENTIFY_ERR;	//用户名或密码错误
       	mysql_free_result(res);
      } 	
	  }
	}    
	else if(req->name[0] && db_checkSQL(req->name))
	{ if(!Password_check(req->psw))login_error=SPY_IDDENTIFY_ERR;//用户名或密码错误 
		else
    { MYSQL_RES *res=db_queryf("select session from `mc_devices` where sn='%s' and password=md5('%s')",req->name,req->psw);
    	if(res)
    	{	MYSQL_ROW row=mysql_fetch_row(res);
        if(row)sessionid=atoi(row[0]);
        else login_error=SPY_IDDENTIFY_ERR;	//用户名或密码错误	
        mysql_free_result(res);
      }  	
    }  
	}
	else if(!req->name[0] && !req->psw[0]) //用户名密码都为空即为注销命令
	{ //移除指定地址的监控端
		TTerminal *terminal=dtmr_find2(terminalLinks,0,0,&packet->peerAddr,sizeof(TNetAddr),T_NODE_OFFSET(TTerminal,spyAddr),0);
    if(terminal)
    {	terminal->spyAddr.ip=0;
  	  login_error=SPY_LOGOFF_SUCCEED;
    }
	}	
	else login_error=SPY_IDDENTIFY_ERR;//用户名或密码错误	
	if(sessionid)
	{	TTerminal *terminal=(TTerminal *)dtmr_find(terminalLinks,sessionid,0,NULL,0); 
		if(terminal)
		{ //原监控端发送消息（通知监控被抢占）
			if(terminal->spyAddr.ip && (terminal->spyAddr.ip!=packet->peerAddr.ip || terminal->spyAddr.port!=packet->peerAddr.port)!=0)
			{ spy_notify(SPY_TERMINAL_PREEMPT, &terminal->spyAddr);
		  }	
		  //设置新的监控端地址
			terminal->spyAddr=packet->peerAddr;
			login_error=SPY_LOGIN_SUCCEED;//监控端登录成功
	  }	
	  else login_error=SPY_TERMINAL_OFFLINE;//终端不在线
  }
  else if(sessionid>0)
  { login_error=SPY_TERMINAL_OFFLINE;//终端不在线
  }	
  spy_notify(login_error, &packet->peerAddr);
}

