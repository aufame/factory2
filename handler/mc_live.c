#include "mc_routine.h"

enum{ERRLIVE_UNKNOWN=-1,ERRLIVE_OK=0,ERRLIVE_USER_NOT_EXIST=1,ERRLIVE_USER_NOT_ONLINE=2,ERRLIVE_USER_BUSY=3,ERRLIVE_USER_DENY=4,ERRLIVE_DEVICE_NOT_ONLINE=10,ERRLIVE_DEVICE_DENY=11,ERRLIVE_LIVE_NOT_EXIST=20,ERRLIVE_UID_NOT_EXIST,ERRLIVE_SELFLOOP,ERRLIVE_BIND_ERROR};
/*
直播方式1：绑定用户手机发起的转播请求 
*/
void Handle_MSG_USR_LIVE(TMcPacket *packet)
{  TMSG_USR_LIVE *req=(TMSG_USR_LIVE *)packet->msg.body;
   TTerminal *visitor_node=NULL, *dev_node=NULL;
   U32 visitor_session=0;
   char nickname[MAXLEN_NICKNAME+1];
   U8 ret_error=ERRLIVE_UNKNOWN;//未知错误
   if(!req->visitor_phone[0])ret_error=ERRLIVE_USER_NOT_EXIST;
   else if(strcmp(req->visitor_phone,packet->terminal->name)==0)ret_error=ERRLIVE_SELFLOOP;//不允许自己直播
   else
   { MYSQL_RES *res=db_queryf("select session from mc_users where username='%s'",req->visitor_phone);
     if(res)
     { MYSQL_ROW row=mysql_fetch_row(res);
       if(row)
       { visitor_session=atoi(row[0]);
         if(visitor_session)visitor_node=(TTerminal *)dtmr_find(terminalLinks,visitor_session,0,0,0); 
       }
       mysql_free_result(res);   
     }  
     if(!visitor_session)
     {  ret_error=ERRLIVE_USER_NOT_EXIST;//用户名不存在
        Log_AppendText("ERRLIVE_USER_NOT_EXIST:%s",req->visitor_phone);
     }  
     else if(!visitor_node)
     {  ret_error=ERRLIVE_USER_NOT_ONLINE;//用户不在线
        Log_AppendText("ERRLIVE_USER_NOT_ONLINE:%s",req->visitor_phone);
     }  
     else if(req->action==STAT_LIVE_CLOSE)ret_error=0;
     else if(!req->uid[0])ret_error=ERRLIVE_UID_NOT_EXIST;  //拒绝直播请求不检查uid
     else
     { U32 dev_session=0,dev_bind_userid=0;
     	 MYSQL_RES *res=db_queryf("select `mc_devices`.session,`mc_users`.id,`mc_users`.nickname from `mc_devices` inner join `mc_uidpool` on `mc_devices`.sn=`mc_uidpool`.sn left join `mc_users` on `mc_devices`.username=`mc_users`.username where `mc_uidpool`.uid='%s'",req->uid);
       if(res)
       { MYSQL_ROW row=mysql_fetch_row(res);
       	 if(row)
         { dev_session=atoi(row[0]);
           if(row[1])dev_bind_userid=atoi(row[1]);//左连接查询时，右表字段可能为NULL;
           if(dev_session)
           { dev_node=(TTerminal *)dtmr_find(terminalLinks,dev_session,0,0,0);
             if(dev_node)
             { if(row[2])strncpy(nickname,row[2],MAXLEN_NICKNAME+1);
               else strncpy(nickname,packet->terminal->name,MAXLEN_NICKNAME+1);
             }    
           }
         }
         mysql_free_result(res);   
       }	
       
       
       if(!dev_session)
       { ret_error=ERRLIVE_UID_NOT_EXIST;//UID不存在
         Log_AppendText("ERRLIVE_UID_NOT_EXIST:%s",req->uid);
       }
       else if(dev_bind_userid!=packet->terminal->id)
       { ret_error=ERRLIVE_BIND_ERROR;//用户没有绑定直播设备
         Log_AppendText("ERRLIVE_BIND_ERROR: not bind for %s",req->uid);
       }    
       else if(!dev_node)
       { ret_error=ERRLIVE_DEVICE_NOT_ONLINE;//设备不在线
         Log_AppendText("ERRLIVE_DEVICE_NOT_ONLINE for uid:%s",req->uid);
       }  
       else 
       { ret_error=ERRLIVE_OK;
       }  
     }  
   }
 
   if(ret_error==0)//申请/拒绝直播
   { TMcMsg *msg=msg_alloc(MSG_SVR_LIVE,sizeof(TMSG_SVR_LIVE));
     TMSG_SVR_LIVE *ackBody=(TMSG_SVR_LIVE *)msg->body; 
     memcpy(ackBody->usr_phone,packet->terminal->name,SIZE_MOBILE_PHONE+1);
     memcpy(ackBody->usr_nick,nickname,MAXLEN_NICKNAME+1);
     memcpy(ackBody->uid,req->uid,MAXLEN_UID+1);
     ackBody->audio=req->audio;
     ackBody->action=req->action;
     msg_request(msg,visitor_node,packet,MC_PACKET_SIZE(packet));
   }
   else
   {  //失败，返回错误
     TMcMsg *msg=msg_alloc(MSG_SUA_LIVE,sizeof(TMSG_SUA_LIVE));
     TMSG_SUA_LIVE *ackBody=(TMSG_SUA_LIVE *)msg->body;
     ackBody->error=ret_error;
     ackBody->ack_synid=packet->msg.synid;
     ackBody->nickname[0]='\0';
     msg_send(msg,packet,NULL);
   }
}

/*
直播方式2：访客手机发起点播请求
*/
void Handle_MSG_VSR_LIVE(TMcPacket *packet)
{ TMSG_VSR_LIVE *req=(TMSG_VSR_LIVE *)packet->msg.body;
  TTerminal * usr_node=NULL;
  U32 binded_usersession=0;
  U8 ret_error=ERRLIVE_UNKNOWN;//未知错误
  char visitor_nick[MAXLEN_NICKNAME+1];
  if(!req->phone[0])ret_error=ERRLIVE_USER_NOT_EXIST;
  else if(strcmp(req->phone,packet->terminal->name)==0)ret_error=ERRLIVE_SELFLOOP;//不允许自己直播
  else
  { MYSQL_RES *res=db_queryf("select session from mc_users where username='%s'",req->phone);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row)binded_usersession=atoi(row[0]);
      mysql_free_result(res);
    }
    if(binded_usersession)
    { usr_node=(TTerminal *)dtmr_find(terminalLinks,binded_usersession,0,0,0);
      if(!usr_node)ret_error=ERRLIVE_USER_NOT_ONLINE;//用户不在线
      else
      {  if((res=db_queryf("select nickname from mc_users where id=%u",packet->terminal->id)))
         { MYSQL_ROW row=mysql_fetch_row(res);
           if(row)
           { if(row[0])strcpy(visitor_nick,row[0]);
             ret_error=0;
           }
           mysql_free_result(res);
         }  
      }
    } 
    else if(!binded_usersession)
    { ret_error=ERRLIVE_USER_NOT_EXIST;//绑定用户名不存在
    }
    else
    { ret_error=ERRLIVE_USER_NOT_ONLINE;//绑定用户不在线
    }     
  }
    
  if(ret_error==0)
  { TMcMsg *msg=msg_alloc(MSG_SUR_LIVE,sizeof(TMSG_SUR_LIVE));
    TMSG_SUR_LIVE *reqBody=(TMSG_SUR_LIVE *)msg->body; 
    memcpy(reqBody->visitor_phone,packet->terminal->name,SIZE_MOBILE_PHONE+1);
    memcpy(reqBody->visitor_nick,visitor_nick,MAXLEN_NICKNAME+1);
    msg_request(msg,usr_node,packet,sizeof(TMcPacket)+packet->msg.bodylen);
    puts("SuspendPacketForResponse(binded_usersession,g_synid,MSG_USA_LIVE,packet,0);");
  }
  else
  {  //失败：返回错误
     TMcMsg *msg=msg_alloc(MSG_SVA_LIVE,sizeof(TMSG_SVA_LIVE));
     TMSG_SVA_LIVE *ackBody=(TMSG_SVA_LIVE *)msg->body;
     ackBody->error=ret_error;
     ackBody->ack_synid=packet->msg.synid;
     ackBody->nickname[0]='\0';
     msg_send(msg,packet,NULL);
  }
}

void Handle_MSG_VSR_LIVE_RET(TMcPacket *packet)
{ TMSG_VSR_LIVE_RET *req=(TMSG_VSR_LIVE_RET *)packet->msg.body;
  U32 Session_BindedUser=packet->terminal->live_user;
  TTerminal *bind_user=NULL,*visitor_node=packet->terminal;
  U8 ret_error=-1;
  if(!Session_BindedUser)ret_error=ERRLIVE_LIVE_NOT_EXIST;
  else  
  { bind_user=(TTerminal *)dtmr_find(terminalLinks,Session_BindedUser,0,0,0);
    if(!bind_user) ret_error=ERRLIVE_USER_NOT_ONLINE;
    else if(req->value) ret_error=0;
    else //直播结果为成功
    { U32 Session_Device=bind_user->live_user;
      if(Session_Device)
      { TTerminal *dev_node=(TTerminal *)dtmr_find(terminalLinks,Session_Device,0,0,0);
        if(!dev_node)ret_error=ERRLIVE_DEVICE_NOT_ONLINE;
        else if(dev_node->live_user!=visitor_node->session)
        { ret_error=ERRLIVE_LIVE_NOT_EXIST;
        }
        else  
        { ret_error=0;
          //标志进入直播状态
          bind_user->live_state=STAT_LIVE_OPEN;
          visitor_node->live_state=STAT_LIVE_OPEN;
          dev_node->live_state=STAT_LIVE_OPEN;
        }
      }
    }
  }
  if(ret_error)
  { msg_ack(MSG_SVA_LIVE_RET,ret_error,packet);
  } 
  else
  { TMcMsg *msg=msg_alloc(MSG_SUR_LIVE_RET,sizeof(TMSG_SUR_LIVE_RET));
    TMSG_SUR_LIVE_RET *reqBody=(TMSG_SUR_LIVE_RET *)msg->body; 
    memcpy(reqBody->visitor_phone,visitor_node->name,SIZE_MOBILE_PHONE+1);
    reqBody->error=req->value;
    msg_request(msg,bind_user,packet,sizeof(TMcPacket));
    puts("SuspendPacketForResponse(Session_BindedUser,g_synid,MSG_USA_LIVE_RET,packet,0);");
  }   
}

void Response_MSG_USA_LIVE_RET(TMcPacket *packet,void *extraData)
{ TMcPacket *sus_packet=(TMcPacket *)extraData;
  U8 ret_error=((TMSG_ACK_GENERAL *)packet->msg.body)->error;
  msg_ack(MSG_SVA_LIVE_RET,ret_error,sus_packet);
  puts("msg_ack(MSG_SVA_LIVE_RET,ret_error,sus_packet);");
}

void Response_MSG_VSA_LIVE(TMcPacket *packet,void *extraData)
{ TMcPacket *sus_packet=(TMcPacket *)extraData;
  U8 ret_error=((TMSG_ACK_GENERAL *)packet->msg.body)->error;
  if(!ret_error)
  { TMSG_USR_LIVE *sus_req=(TMSG_USR_LIVE *)sus_packet->msg.body;
    if(sus_req->action==STAT_LIVE_OPEN)
    { ret_error=-1;
      MYSQL_RES *res=db_queryf("select mc_devices.session as dev_session,mc_users.session as usr_session from mc_devices inner join mc_users on mc_devices.username=mc_users.username inner join mc_uidpool on mc_devices.sn=mc_uidpool.sn where mc_uidpool.uid='%s'",sus_req->uid);
      if(res)
      { MYSQL_ROW row=mysql_fetch_row(res);
        if(row)
        { U32 dev_session=atoi(row[0]);
           U32 usr_session=atoi(row[1]);
           if(dev_session && usr_session)
           {  TTerminal *dev_node=(TTerminal *)dtmr_find(terminalLinks,dev_session,0,0,0);
              TTerminal *usr_node=(TTerminal *)dtmr_find(terminalLinks,usr_session,0,0,0);
              TTerminal *visitor_node=packet->terminal;
              if(dev_node && usr_node && visitor_node)
              { ret_error=0;
                //正在请求建立的直播路径 bind_user -> device -> visiter
               usr_node->live_user=dev_node->session;
               dev_node->live_user=visitor_node->session;
               visitor_node->live_user=usr_node->session;
             }
           }
        }
        mysql_free_result(res);
      }  
    } 
  } 
  
  TMcMsg *msg=msg_alloc(MSG_SUA_LIVE,sizeof(TMSG_SUA_LIVE));
  TMSG_SUA_LIVE *ackBody=(TMSG_SUA_LIVE *)msg->body;
  ackBody->error=ret_error;
  ackBody->ack_synid=sus_packet->msg.synid;
  ackBody->nickname[0]='\0';
  if(ret_error==0)
  { MYSQL_RES *res=db_queryf("select nickname from `mc_users` where id=%u",packet->terminal->id);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row && row[0])strncpy(ackBody->nickname,row[0],MAXLEN_NICKNAME+1);
      mysql_free_result(res);
    }   
  }
  msg_send(msg,sus_packet,NULL);
}

void Response_MSG_USA_LIVE(TMcPacket *packet,void *extraData)
{ U8 ret_error=((TMSG_ACK_GENERAL *)packet->msg.body)->error;
  TMcPacket *sus_packet=(TMcPacket *)extraData;
  TMcMsg *msg=msg_alloc(MSG_SVA_LIVE,sizeof(TMSG_SVA_LIVE));
  TMSG_SVA_LIVE *ackBody=(TMSG_SVA_LIVE *)msg->body;
  ackBody->error=ret_error;
  ackBody->ack_synid=sus_packet->msg.synid;
  ackBody->nickname[0]='\0';
  if(ret_error==0)
  { MYSQL_RES *res=db_queryf("select nickname from `mc_users` where id=%u",packet->terminal->id);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row && row[0])strncpy(ackBody->nickname,row[0],MAXLEN_NICKNAME+1);
      mysql_free_result(res);
    }     
  }
  msg_send(msg,sus_packet,NULL);
}

void Handle_MSG_USR_LIVE_STOP(TMcPacket *packet)
{ TTerminal *bind_node=packet->terminal;
  U8 ret_error=-1;
  if(bind_node->live_state==STAT_LIVE_CLOSE)ret_error=1; //不存在直播
  else if(bind_node->live_state==STAT_LIVE_OPEN && bind_node->live_user)
  { TTerminal *dev_node=(TTerminal *)dtmr_find(terminalLinks,bind_node->live_user,0,0,0);
    if(dev_node && dev_node->live_state==STAT_LIVE_OPEN && dev_node->live_user)
    { TTerminal *visitor_node=(TTerminal *)dtmr_find(terminalLinks,dev_node->live_user,0,0,0);
      if(visitor_node && visitor_node->live_state==STAT_LIVE_OPEN && visitor_node->live_user==bind_node->live_user)
      {  ret_error=0;
         //消除直播状态以及路径       
         bind_node->live_state=STAT_LIVE_CLOSE;
         bind_node->live_user=0;
         dev_node->live_state=STAT_LIVE_CLOSE;
         dev_node->live_user=0;
         visitor_node->live_state=STAT_LIVE_CLOSE;
         visitor_node->live_user=0;
      }  
    } 
  }
  msg_ack(MSG_SUA_LIVE_STOP,ret_error,packet);
}

void Handle_MSG_USR_ACCEPTLIVEPUSH(TMcPacket *packet)
{ int live_push_acceptable=((TMSG_USR_ACCEPTLIVEPUSH *)packet->msg.body)->value;
  U8 ret_error=1;
  if(live_push_acceptable==0 || live_push_acceptable==1)
  { if(live_push_acceptable==packet->terminal->live_push_acceptable)
    { ret_error=0;
    }
    else
    { db_queryf("update `mc_users` set livepush=%d where id=%u",live_push_acceptable,packet->terminal->id);
      packet->terminal->live_push_acceptable=live_push_acceptable;
      ret_error=0;
    } 
  }
  msg_ack(MSG_STA_GENERAL,ret_error,packet);
}

