#include "mc_routine.h"
//---------------------------------------------------------------------------
//Webserver从网页端向服务器发起通知请求
//web后端页面修改后通知服务器后台同步
static TTerminal *FindTermialById(U32 id,int type)
{ TTerminal *terminal=NULL;
  MYSQL_RES *res=db_queryf("select session from `%s` where id=%u",(type==TT_USER)?"mc_users":"mc_devices",id);
  if(res)
  { MYSQL_ROW row=mysql_fetch_row(res);
    if(row && row[0])
    { U32 session=atoi(row[0]);
      if(session) terminal=(TTerminal *)dtmr_find(terminalLinks,session,0,0,0);
    }
    mysql_free_result(res);
  }
  return terminal;
}    
            	

void Handle_MSG_BSR_NOTIFY(TMcPacket *packet)
{	TMSG_SSR_NOTIFY *req=(TMSG_SSR_NOTIFY *)packet->msg.body;
	U8 ret_error=-1;
  if(req->action==ACTION_BDR_DEVSTATECHANGED)//设备信息改变
  { int index,param_count=req->param_size/sizeof(U32);
  	U32 *param_array=(U32 *)req->param_data;
    for(index=0;index<param_count;index++)
    { MYSQL_RES *res=db_queryf("select session,groupid from `mc_devices` where id=%u",param_array[index]);
      if(res)
      { MYSQL_ROW row=mysql_fetch_row(res);
        if(row && row[0] && row[1])
        { U32 session=atoi(row[0]);
          U32 groupid=atoi(row[1]);
          if(session)
          { TTerminal *terminal=(TTerminal *)dtmr_find(terminalLinks,session,0,0,0);
            if(terminal)
            { terminal->group=groupid;//更新设备的groupid
              ret_error=0; 
            }
          }else ret_error=0;//无需修改
        }
        mysql_free_result(res);
      }    
    }
  }
  else if(req->action==ACTION_BUR_USERSTATECHANGED)//用户信息改变
  { int index,param_count=req->param_size/sizeof(U32);
  	U32 *param_array=(U32 *)req->param_data;
    for(index=0;index<param_count;index++)
    { MYSQL_RES *res=db_queryf("select session,groupid from `mc_users` where id=%u",param_array[index]);
      if(res)
      { MYSQL_ROW row=mysql_fetch_row(res);
        if(row && row[0] && row[1])
        { U32 session=atoi(row[0]);
          U32 groupid=atoi(row[1]);
          if(session)
          { TTerminal *terminal=(TTerminal *)dtmr_find(terminalLinks,session,0,0,0);
            if(terminal)
            { terminal->group=groupid;//更新用户的groupid
              ret_error=0;
            }
          }
        }
        mysql_free_result(res);  
      }
    }
  }
  else if(req->action==ACTION_BUR_GROUPMSG){//消息盒子 发送群组消息
     U32 usrgroup  = *(U32 *)(req->param_data+sizeof(U32)*0);
     U32 devgroup  = *(U32 *)(req->param_data+sizeof(U32)*1);
     U32 msgtype   = *(U32 *)(req->param_data+sizeof(U32)*2);
     char *msgtitle= (char *)(req->param_data+sizeof(U32)*3);
     char *msgcontent=msgtitle+strlen(msgtitle)+1;
     char *param_end=msgcontent+strlen(msgcontent)+1;
     if((int)(param_end-req->param_data)==req->param_size){
       msg_ack(MSG_STA_GENERAL,0,packet);//处理时间会比较久，先响应
       ret_error=push_group_msg(usrgroup,devgroup,msgtype,msgcontent,msgtitle);
       return;
     }
  }

#if 0  //deprecated interface
  else if(req->action==ACTION_BUR_GROUPSMS)//短信群发（分组群发）
  { U32 groupid=*(U32 *)(req->param_data+0);
  	char *phones=NULL;
  	char *msgcontent=(char *)req->param_data+sizeof(U32);
  	char *param_end=msgcontent+strlen(msgcontent)+1;
  	if((int)(param_end-req->param_data)==req->param_size)
  	{ MYSQL_RES *res=db_queryf("select count(*) from `mc_users` where groupid=%d",groupid);
	    if(res)
	    { MYSQL_ROW row=mysql_fetch_row(res);
        int userCount=(row && row[0])?atoi(row[0]):0;
        mysql_free_result(res);  
        if(userCount>0)
        { phones=(char *)malloc(userCount*(SIZE_MOBILE_PHONE+1)+1);
        	res=db_queryf("select username from `mc_users` where groupid=%d",groupid); 
        	if(res)
        	{	char *p=phones;
        		while(userCount-->0 && (row=mysql_fetch_row(res)))
        		{ if(row[0] && MobilePhone_check(row[0])) 
        			{ p+=sprintf(p,"%s,",row[0]);
        			}
        		} 
        		mysql_free_result(res);
        		if(p>phones)*(p-1)='\0';
        		else *p='\0';
        	}
	 	    }
	 	  }  
	 	  if(phones)
	 	  { if(phones[0])ret_error=sms_send(phones,msgcontent);
	 	  	free(phones);
	 	  }	
  	}
  }
#endif

  else if(req->action==ACTION_BDR_FORCESLEEP)//强制休眠
  { int index,param_count=req->param_size/sizeof(U32);
  	U32 *param_array=(U32 *)req->param_data;
    for(index=0;index<param_count;index++)
    {	TTerminal *terminal=FindTermialById(param_array[index],TT_DEVICE);
    	if(terminal)
      { TMcMsg *reqmsg=msg_alloc(MSG_SDR_FORCE_SLEEP,0);
      	msg_send(reqmsg,NULL,terminal);
      	ret_error=0;
      } 
    }
  }
  else if(req->action==ACTION_BDR_COMMJSON){//请求终端上报JSON信息
    int index,param_count=req->param_size/sizeof(U32);
    U32 *param_array=(U32 *)req->param_data;
    U32 dev_session=0;
    for(index=0;index<param_count;index++){
      MYSQL_RES *res=db_queryf("select session,boxid from `mc_devices` where id=%u",param_array[index]);
      if(res){
        MYSQL_ROW row=mysql_fetch_row(res);
        if(row){
            dev_session=atoi(row[0]);
            if(!dev_session){
              U32 boxid=atoi(row[1]);
              if(boxid){
                 mysql_free_result(res);  
                 res=db_queryf("select session from `mc_boxes` where id=%u",boxid);
                 if(res && row) dev_session=atoi(row[0]);
              }
           }
        }
        if(res)mysql_free_result(res);  
      } 
      if(dev_session){
        TTerminal *terminal=(TTerminal *)dtmr_find(terminalLinks,dev_session,0,0,0);
    	if(terminal){
          TMcMsg *reqmsg=msg_alloc(MSG_SDR_COMMJSON,sizeof(T_VARDATA));
      	  T_VARDATA *reqBody=(T_VARDATA *)reqmsg->body;
      	  reqBody->datalen=0;
      	  msg_send(reqmsg,NULL,terminal);
      	  ret_error=0;
        } 
      }
    }
  }  
  
  msg_ack(MSG_STA_GENERAL,ret_error,packet);
}
