#include "mc_routine.h"


static void store_offline_msg(int msgType,char *msgContent,U32 userid){
  char sqlText[512];
  sprintf(sqlText,"`mc_msgbox` set category=%d,content='%s',addtime=unix_timestamp(),recipient=%d",msgType,msgContent,userid);
  if(!db_queryf("update %s where category<=0 or addtime<unix_timestamp()-7*24*60*60 order by addtime asc limit 1",sqlText))db_queryf("insert into %s",sqlText);
}
 
void push_device_msg(U32 deviceID,int msgType,char *msgContent)
{ U32 span_filter_s=(msgType==WARNINGMSG_VIBRATE)?60:SPAN_MSG_PUSH_FILTER_S;//震动消息过滤时间设定为60妙
  char strType[8];
  sprintf(strType,"%d",msgType);
  if(!dtmr_add(commDataLinks,deviceID,MSG_SUR_NOTIFY_MSGBOX,strType,NULL,0,span_filter_s|DTMR_NOVERRIDE))return;
  MYSQL_RES *res=db_queryf("select mc_users.id,mc_users.username,mc_users.session,mc_users.groupid,mc_devices.state from `mc_users`,`mc_devices` where mc_devices.id=%u and mc_devices.username=mc_users.username",deviceID);
  if(res){ 
    U32 binded_userid;
    MYSQL_ROW row=mysql_fetch_row(res);
    if(row && (binded_userid=atoi(row[0]))){
      char binded_phone[SIZE_MOBILE_PHONE+1]; 
      U32 binded_usersession=atoi(row[2]);
      int usrgroup=atoi(row[3]);
      strncpy(binded_phone,row[1],SIZE_MOBILE_PHONE+1);
      if(1)//msg_push_acceptable
      { TTerminal *usrnode;
        if(binded_usersession && (usrnode=(TTerminal *)dtmr_find(terminalLinks,binded_usersession,0,0,0)))
        {  TMcMsg *reqmsg=msg_alloc(MSG_SUR_NOTIFY_MSGBOX,sizeof(TMSG_SUR_NOTIFY_MSGBOX)+strlen(msgContent)+1);
           TMSG_SUR_NOTIFY_MSGBOX *reqbody=(TMSG_SUR_NOTIFY_MSGBOX *)reqmsg->body;
           reqbody->timestamp=time(NULL);
           reqbody->type=msgType;
           strcpy(reqbody->content,msgContent); 
           msg_request(reqmsg,usrnode,NULL,0);
        }  
        else if(msgType<10)//存储离线消息
        { store_offline_msg(msgType,msgContent,binded_userid);
        } 
      }
      if((msgType==WARNINGMSG_VIBRATE && atoi(row[4])==DEVSTATE_SLEEP) || msgType==WARNINGMSG_LOWPOWER || msgType==WARNINGMSG_FLOWDEPLETE) //强制发送短信(不管用户是否允许接收消息推送)
      {	//为降低成本，非休眠状态下的震动不发短信。
      	sms_send(msgContent,binded_phone,usrgroup);//will consume much time
      }
    }  
    mysql_free_result(res);   
  }
}

void push_device_msg_timeout(TMcPacket *request){
  U32 userid=request->terminal->id;
  TMSG_SUR_NOTIFY_MSGBOX *reqMsg=(TMSG_SUR_NOTIFY_MSGBOX *)request->msg.body;
  store_offline_msg(reqMsg->type,reqMsg->content,userid);
}


#define MIN_INTERVAL_PUSH_GROUP_MSG_S  15
int push_group_msg(U32 usrgroup,U32 devgroup,int msgType,char *msgContent,char *msgTitle){
   if(dtmr_add(commDataLinks,msgType,MSG_BSR_NOTIFY,NULL,NULL,0,MIN_INTERVAL_PUSH_GROUP_MSG_S|DTMR_NOVERRIDE)){
      char sql[200]="";
      if(usrgroup){
        if(devgroup) sprintf(sql,"select `mc_users`.id,`mc_users`.session from `mc_users` inner join `mc_devices` on `mc_users`.username=`mc_devices`.username where `mc_users`.groupid=%d and `mc_devices`.groupid=%d",usrgroup,devgroup);
        else sprintf(sql,"select id,session from `mc_users` where groupid=%d",usrgroup);
      }
      else if(devgroup){
        sprintf(sql,"select `mc_users`.id,`mc_users`.session from `mc_users` inner join `mc_devices` on `mc_users`.username=`mc_devices`.username where `mc_devices`.groupid=%d",devgroup);
      }
      MYSQL_RES *res=db_query(sql);
      if(res)
	   { MYSQL_ROW row;
	 	   while((row=mysql_fetch_row(res)))
	 	   { TTerminal *usrnode;
	 	     U32 userid=atoi(row[0]),sessionid=atoi(row[1]);
	 	   	 if(sessionid && (usrnode=(TTerminal *)dtmr_find(terminalLinks,sessionid,0,0,0)))
	 	   	 { TMcMsg *reqmsg=msg_alloc(MSG_SUR_NOTIFY_MSGBOX,sizeof(TMSG_SUR_NOTIFY_MSGBOX)+strlen(msgTitle)+strlen(msgContent)+2);
           TMSG_SUR_NOTIFY_MSGBOX *reqbody=(TMSG_SUR_NOTIFY_MSGBOX *)reqmsg->body;
           reqbody->timestamp=time(NULL);
           reqbody->type=msgType;
           sprintf(reqbody->content,"%s\r%s",msgTitle,msgContent); 
           msg_request(reqmsg,usrnode,NULL,0);
           usleep(100);
	 	     }
	 	     else//存储离线消息
	 	     { char sqlText[512];
           sprintf(sqlText,"`mc_msgbox` set category=%d,content='%s\r%s',addtime=unix_timestamp(),recipient=%d",msgType,msgTitle,msgContent,userid);
           if(!db_queryf("update %s where category<=0 or addtime<unix_timestamp()-7*24*60*60 order by addtime asc limit 1",sqlText))db_queryf("insert into %s",sqlText);
	 	       usleep(10); 
	 	     }	
	 	   }  
	 	   mysql_free_result(res);
	   }
	   return 0;
	 }else return -1;		  
}
