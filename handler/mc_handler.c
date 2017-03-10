#include "mc_routine.h"
//---------------------------------------------------------------------------
void Handle_MSG_DSR_LOGIN(TMcPacket *packet)
{ enum{DEV_LOGIN_ORIGIN=0,DEV_LOGIN_BOX=1,DEV_LOGIN_CAMERA=2};
  TTerminal *terminal=NULL;
  U32  deviceID=0,sessionid=0,loginTime,deviceGroup,deviceBox,deviceState;
  TMSG_DSR_LOGIN *content=(TMSG_DSR_LOGIN *)packet->msg.body;
  U8 error_code=1,box_login=(content->type==DEV_LOGIN_BOX);
  if(content->name[0] && db_checkSQL(content->name) && Password_check(content->psw))
  {  MYSQL_RES *res;
     if(box_login)res=db_queryf("select id,session,groupid,logintime from `mc_boxes` where sn='%s' and password=md5('%s')",content->name,content->psw); 
     else res=db_queryf("select id,session,groupid,logintime,state,boxid from `mc_devices` where sn='%s' and password=md5('%s')",content->name,content->psw); 
     if(res)
     { MYSQL_ROW row=mysql_fetch_row(res);
       if(row)
       {  deviceID=atoi(row[0]);
          sessionid=atoi(row[1]);
          deviceGroup=atoi(row[2]);
          loginTime=atoi(row[3]);
          if(!box_login)
          { deviceState=atoi(row[4]);
            deviceBox=atoi(row[5]);
          }
          if(sessionid)
          { terminal=(TTerminal *)dtmr_find(terminalLinks,sessionid,0,0,HEARTBEAT_OVERTIME_S); 
            if(terminal && terminal->id!=deviceID)
            { //上一次使用的session已经被其他设备占用（所查到的terminal是其他设备）。
              sessionid=0;
              terminal=NULL;
            }
          } 
       }
       mysql_free_result(res);   
     }  
  }

  if(deviceID)
  { extern U32 SessionID_new(void);
    if(!sessionid)sessionid=SessionID_new(); 
    if(!terminal)
    { int termsize=(box_login)?sizeof(TTermBox):sizeof(TTermDevice);
      terminal=(TTerminal *)dtmr_add(terminalLinks,sessionid,0,0,NULL,termsize,HEARTBEAT_OVERTIME_S);
      memset(terminal,0,termsize);
      loginTime=time(NULL);
    }
    terminal->term_type=(box_login)?TT_BOX:TT_DEVICE;
    terminal->id=deviceID;
    terminal->loginAddr=packet->peerAddr;
    terminal->session=sessionid;
    terminal->group=deviceGroup;
    terminal->live_state=STAT_LIVE_CLOSE;
    terminal->encrypt=packet->msg.encrypt;//消息体默认加密方式
    if(!box_login)
    { terminal->term_state=deviceState; //the login action do not change device state
      ((TTermDevice *)terminal)->boxid=deviceBox;
      if(deviceState==DEV_STATE_STARTING) ((TTermDevice *)terminal)->startup_time=time(NULL);
      else if( ((TTermDevice *)terminal)->startup_time==0) ((TTermDevice *)terminal)->startup_time=loginTime;
      //puts("################Login and set startup_time");
    }
    strncpy(terminal->name,content->name,SIZE_SN_DEVICE+1);
    error_code=0;
    db_queryf("update `%s` set session=%u,ip=%u,port=%u,logintime=%u where id=%u",(box_login)?"mc_boxes":"mc_devices",sessionid,packet->peerAddr.ip,packet->peerAddr.port,loginTime,deviceID);
    if(terminal->spyAddr.ip)
    { extern void spy_forwardLoginRequest(TMcMsg *,TNetAddr *);
      spy_forwardLoginRequest(&packet->msg,&terminal->spyAddr); 
    } 
  }
  
  packet->terminal=terminal;
  TMcMsg *msg=msg_alloc(MSG_SDA_LOGIN,sizeof(TMSG_SDA_LOGIN));
  TMSG_SDA_LOGIN *ackBody=(TMSG_SDA_LOGIN *)msg->body;
  ackBody->ack_synid=packet->msg.synid;
  ackBody->session=sessionid;
  ackBody->error=error_code;
  msg_send(msg,packet,NULL);

  if(error_code==0){ 
     //分离盒子与摄像头的登录互斥 
      if(content->type==DEV_LOGIN_BOX){
        MYSQL_RES *res=db_queryf("select session from `mc_devices` where boxid=%u",terminal->id); 
        if(res){
          MYSQL_ROW row;
          while((row=mysql_fetch_row(res))){
            U32 dev_session=atoi(row[0]);
            if(dev_session)dtmr_find(terminalLinks,dev_session,0,0,3);//设备节点的lifetime改为3秒(自行超时善后).
          } 
          mysql_free_result(res);  
        }
      }
      else if(content->type==DEV_LOGIN_CAMERA){
        if(deviceBox){
          MYSQL_RES *res=db_queryf("select session from `mc_boxes` where id=%u",deviceBox); 
          if(res){
            MYSQL_ROW row=mysql_fetch_row(res);
            if(row){
              U32 dev_session=atoi(row[0]);
              if(dev_session)dtmr_find(terminalLinks,dev_session,0,0,3);//设备节点的lifetime改为3秒(自行超时善后).
            } 
            mysql_free_result(res);  
          }
        } 
      }
      DBLog_AppendData("\xFF\xFF\xFF\xFF\x00",5,terminal); //登录日志
  }
}
        
void Handle_MSG_USR_LOGIN(TMcPacket *packet)
{ TTerminal *terminal=NULL,*terminalKickOff=NULL;
  U32 userid=0,sessionid=0,userGroup;
  U8 sex_type,msgpush,livepush,error_code=0;
  TMSG_USR_LOGIN *content=(TMSG_USR_LOGIN *)packet->msg.body;
  if(db_checkSQL(content->name) && (content->psw[0]=='\0' || Password_check(content->psw)))//允许空密码登录（for电信乐驾）
  {  MYSQL_RES *res=db_queryf("select id,session,groupid,sex,msgpush,livepush from `mc_users` where username='%s' and password=md5('%s')",content->name,content->psw);
     if(res)
     {  MYSQL_ROW row=mysql_fetch_row(res);
        if(row)
        { userid=atoi(row[0]);
          sessionid=atoi(row[1]);
          userGroup=atoi(row[2]);
          sex_type=atoi(row[3]);
          msgpush=atoi(row[4]);
          livepush=atoi(row[5]);
          if(sessionid)
          { terminal=(TTerminal *)dtmr_find(terminalLinks,sessionid,0,0,HEARTBEAT_OVERTIME_S);
            if(terminal)
            {  if(terminal->id!=userid)
               { //上一次使用的session已经被其他用户占用（所查到的terminal是其他用户）。
                 sessionid=0;
                 terminal=NULL;
               }
               else if(memcmp(&terminal->loginAddr,&packet->peerAddr,sizeof(TNetAddr))!=0)
               { //同一用户名多处登录的状况
                 //将原先登录的用户踢下线
                 TMcMsg *reqmsg=msg_alloc(MSG_SUR_KICKOFF,0);
                 msg_request(reqmsg,terminal,NULL,0);
                 //安全删除原先登录的用户节点
                 dtmr_remove(terminal);//删除后的节点无法被查找，但会保留足够长一段时间
                 terminalKickOff=terminal;
                 terminal=NULL;
                 //sessionid=0; //sessionID可继续使用
               }
            }
          }
        }
        mysql_free_result(res);  
    }
  }
  if(!userid)
  { error_code=1;//用户名或密码错误。
  }
  else
  { extern U32 SessionID_new(void);
    if(!sessionid)sessionid=SessionID_new(); 
    if(!terminal)
    { terminal=(TTerminal *)dtmr_add(terminalLinks,sessionid,0,0,NULL,sizeof(TTermUser),HEARTBEAT_OVERTIME_S);
      memset(terminal,0,sizeof(TTermUser));
      if(terminalKickOff && terminalKickOff->spyAddr.ip) terminal->spyAddr=terminalKickOff->spyAddr;
      else terminal->spyAddr.ip=0;
    }
    terminal->term_type=TT_USER;
    terminal->id=userid;
    terminal->loginAddr=packet->peerAddr;
    terminal->session=sessionid;
    terminal->group=userGroup;
    terminal->live_state=STAT_LIVE_CLOSE;
    terminal->live_user=0;
    terminal->sex_type=sex_type;
    terminal->msg_push_acceptable=msgpush;
    terminal->live_push_acceptable=livepush;
    terminal->encrypt=packet->msg.encrypt;//消息体默认加密方式
    strncpy(terminal->name,content->name,SIZE_MOBILE_PHONE+1);
    db_queryf("update `mc_users` set session=%u,ip=%u,port=%u,logintime=unix_timestamp() where id=%u",sessionid,packet->peerAddr.ip,packet->peerAddr.port,userid);
    if(terminal->spyAddr.ip)
    { extern void spy_forwardLoginRequest(TMcMsg *,TNetAddr *);
      spy_forwardLoginRequest(&packet->msg,&terminal->spyAddr); 
    } 
  }
  packet->terminal=terminal;
  TMcMsg *msg=msg_alloc(MSG_SUA_LOGIN,sizeof(TMSG_SUA_LOGIN));
  TMSG_SUA_LOGIN *ackBody=(TMSG_SUA_LOGIN *)msg->body;
  ackBody->ack_synid=packet->msg.synid;
  ackBody->error=error_code;
  ackBody->session=sessionid;
  msg_send(msg,packet,NULL);
  if(error_code==0)DBLog_AppendData("\xFF\xFF\xFF\xFF\x00",5,terminal); //登录日志
}

void Handle_MSG_USR_LOGOUT(TMcPacket *packet)
{ db_queryf("update `mc_users` set session=0,logouttime=unix_timestamp() where id=%u",packet->terminal->id);
  dtmr_remove(packet->terminal);
  msg_ack(MSG_STA_GENERAL,0,packet);
  if(packet->terminal->spyAddr.ip)spy_notify(SPY_TERMINAL_OFFLINE, &packet->terminal->spyAddr);
}

void Handle_MSG_USR_REGIST(TMcPacket *packet)
{ TMSG_USR_REGIST *req=(TMSG_USR_REGIST *)packet->msg.body;
  U8 ret_error=-1;
  if(MobilePhone_check(req->phone) && Password_check(req->psw))
  { int vcode_err=vcode_apply(req->verifycode,req->phone);
    if(vcode_err==0)
    { db_lock(TRUE);
      MYSQL_RES *res=db_queryf("select id from `mc_users` where username='%s'",req->phone);
      if(res)
      { MYSQL_ROW row=mysql_fetch_row(res);
        if(row && atoi(row[0]))ret_error=1; //用户名已经存在
        else
        { char sqlText[256];
          req->nick[MAXLEN_NICKNAME]='\0';
          sprintf(sqlText,"`mc_users` set username='%s',password=md5('%s'),groupid=%u,score=0,sex=0,nickname='%s',session=0,ip=%u,port=%u,logintime=0,logouttime=0,regtime=unix_timestamp()",req->phone,req->psw,req->groupid,db_filterSQL(req->nick),packet->peerAddr.ip,packet->peerAddr.port);
          if(db_queryf("update %s where groupid=0 order by logintime asc limit 1",sqlText))ret_error=0;//herelong
          else
          { db_queryf("insert into %s",sqlText);
            ret_error=0;
          } 
        }
        mysql_free_result(res);
      }  
      db_lock(FALSE);
    }
    else if(vcode_err==ERR_TIMEOUT)ret_error=3; //验证码已经失效
  	else ret_error=2; //验证码错误
  }
  msg_ack(MSG_SUA_REGIST,ret_error,packet);
}


void Handle_MSG_USR_QUERY_VERSION(TMcPacket *packet)
{ const int JsonMaxLen=2048;
  TMcMsg *ackmsg=msg_alloc(MSG_SUA_QUERY_VERSION,sizeof(TMSG_SUA_QUERY_VERSION)+JsonMaxLen);
  TMSG_SUA_QUERY_VERSION *ackbody=(TMSG_SUA_QUERY_VERSION *)ackmsg->body;
  U32 groupid=(packet->terminal)?packet->terminal->group:((TMSG_USR_QUERY_VERSION *)packet->msg.body)->usrgroup;
  int offset=0;
  char *json=(char *)ackbody->json.data;
  MYSQL_RES *res=db_queryf("select app_ver_main,app_ver_minor,app_url from `mc_usrgroup` where id=%u",groupid);
  if(res)
  { MYSQL_ROW row=mysql_fetch_row(res);
    if(row)
    {	offset=sprintf(json,"{\"app_ver\":\"%s.%s\"",row[0],row[1]);
    	if(row[2])offset+=sprintf(json+offset,",\"app_url\":\"http://"WEB_SERVER_HOST"%s\"",row[2]);	
    }
    mysql_free_result(res);
  } 
  if(offset && packet->terminal)
  { MYSQL_ROW row;
    int dev_count=0;
    res=db_queryf("select sn,name,ssid,groupid from `mc_devices` where `mc_devices`.username='%s'",packet->terminal->name);
    if(res)
    { while((row = mysql_fetch_row(res)))
      { if(dev_count++>0) json[offset++]=',';	
        else offset+=sprintf(json+offset,",\"devices\":[");	
        offset+=sprintf(json+offset,"{\"sn\":\"%s\",\"name\":\"%s\",\"ssid\":\"%s\",\"group\":\"Group%s\"}",row[0],row[1],row[2],row[3]);	 
      }
      mysql_free_result(res);
    }
    if(dev_count>0)
    { offset+=sprintf(json+offset,"]");	
      res=db_queryf("select distinct `mc_devgroup`.id,`mc_devgroup`.mainfw_ver,`mc_devgroup`.mainfw_url,`mc_devgroup`.mainfw_log from  `mc_devgroup` inner join `mc_devices` on `mc_devgroup`.id=`mc_devices`.groupid where `mc_devices`.username='%s'",packet->terminal->name);
      if(res)
      { int group_count=0;
        while((row = mysql_fetch_row(res)))
        { if(group_count++>0)json[offset++]=',';
          else offset+=sprintf(json+offset,",\"groups\":[");
          offset+=sprintf(json+offset,"{\"group\":\"Group%s\",\"mainfw_ver\":\"%s\",\"mainfw_url\":\"http://"WEB_SERVER_HOST"%s\",\"mainfw_log\":\"http://"WEB_SERVER_HOST"%s\"}",row[0],row[1],(row[2])?row[2]:"",(row[3])?row[3]:"");	 
        }
        if(group_count>0)offset+=sprintf(json+offset,"]");
        mysql_free_result(res);
      }
    }	
  }
  if(offset)json[offset++]='}';
  json[offset++]='\0';
  if(offset>=JsonMaxLen)
  { puts("###Handle_MSG_USR_QUERY_VERSION, json buffer overflow!");
    abort();//force core dump ;	
  }
  ackmsg->bodylen=sizeof(TMSG_SUA_QUERY_VERSION)+offset;	
  ackbody->ack_synid=packet->msg.synid;
  ackbody->json.datalen=offset;
  msg_send(ackmsg,packet,NULL);
}

void Handle_MSG_DSR_SYNC(TMcPacket *packet)
{ char *ssid=((TMSG_DSR_SYNC *)packet->msg.body)->ssid;
  U8 ret_error=1;
  if(ssid[0] && db_checkSQL(ssid))
  { ssid[MAXLEN_SSID]='\0';
    db_queryf("update `mc_devices` set ssid='%s' where id=%u",ssid,packet->terminal->id);
    ret_error=0;
  }
  msg_ack(MSG_SDA_SYNC,ret_error,packet);
}

void Handle_MSG_TSR_HEARTBEAT(TMcPacket *packet)
{ msg_ack(MSG_STA_GENERAL,0,packet);
}

void Handle_MSG_USR_GETUSERHEAD(TMcPacket *packet)
{ TMSG_USR_GETUSERHEAD *req=(TMSG_USR_GETUSERHEAD *)packet->msg.body;
  U32 userid=0;
  if(MobilePhone_check(req->phone))
  {  MYSQL_RES *res=db_queryf("select id from `mc_users` where username='%s'",req->phone);
     if(res)
     { MYSQL_ROW row=mysql_fetch_row(res);
       if(row && row[0])userid=atoi(row[0]);
        mysql_free_result(res);
     }  
  }
  if(userid>0)
  { extern U32  Userlogo_Load(U32 userid,void *dataBuffer,int bufszie);
    int maxImageDataLen=MAXLEN_MSG_TCP-(sizeof(TMcMsg)+sizeof(TMSG_SUA_GETUSERHEAD)+1);
    TMcMsg *ackmsg=msg_alloc(MSG_SUA_GETUSERHEAD,maxImageDataLen);
    TMSG_SUA_GETUSERHEAD *ackbody=(TMSG_SUA_GETUSERHEAD *)ackmsg->body;
    ackbody->ack_synid=packet->msg.synid;
    ackbody->data_size=Userlogo_Load(userid,ackbody->data,maxImageDataLen);      
    ackmsg->bodylen=sizeof(TMSG_SUA_GETUSERHEAD)+ackbody->data_size;
    packet->terminal->encrypt=ENCRYPTION_NONE;//头像不加密
    msg_send(ackmsg,packet,NULL); 
    //hsk_closeTcpClient(&packet->peerAddr);
  }  
}

void Handle_MSG_USR_CHANGEHEAD(TMcPacket *packet)
{ extern BOOL Userlogo_Save(U32 userid,void *data,int datalen);
  TMSG_USR_CHANGEHEAD *req=(TMSG_USR_CHANGEHEAD *)packet->msg.body;
  U8 ret_error=(Userlogo_Save(packet->terminal->id,req->data,req->datalen))?0:1;
  msg_ack(MSG_STA_GENERAL,ret_error,packet);
  //hsk_closeTcpClient(&packet->peerAddr);
}

void Handle_MSG_USR_GETUSERINFO(TMcPacket *packet)
{ TMcMsg *ackmsg=msg_alloc(MSG_SUA_GETUSERINFO,sizeof(TMSG_SUA_GETUSERINFO));
  TMSG_SUA_GETUSERINFO *ackBody=(TMSG_SUA_GETUSERINFO *)ackmsg->body;
  U8 ret_error=-1;
  MYSQL_RES *res=db_queryf("select nickname,score from `mc_users` where id=%u",packet->terminal->id);
  if(res)
  { MYSQL_ROW row=mysql_fetch_row(res);
    if(row)
    { ret_error=0;
      if(row[0])strncpy(ackBody->nickname,row[0],MAXLEN_NICKNAME+1);
      else ackBody->nickname[0]='\0';
      ackBody->score=atoi(row[1]);
      ackBody->sex=packet->terminal->sex_type;
      ackBody->msg_push_acceptable=packet->terminal->msg_push_acceptable;
      ackBody->live_push_acceptable=packet->terminal->live_push_acceptable;
    }
    mysql_free_result(res);
  }   
  if(!ret_error)
  { ackBody->ack_synid=packet->msg.synid;
    msg_send(ackmsg,packet,NULL);
  }  
}

void Handle_MSG_USR_CHANGENICK(TMcPacket *packet)
{ TMSG_USR_CHANGENICK *req=(TMSG_USR_CHANGENICK *)packet->msg.body;
  db_queryf("update `mc_users` set nickname='%s' where id=%u",db_filterSQL(req->nick),packet->terminal->id);
  msg_ack(MSG_STA_GENERAL,0,packet);
}

void Handle_MSG_USR_CHANGESEX(TMcPacket *packet)
{ int sex_type=((TMSG_USR_CHANGESEX *)packet->msg.body)->value;
  U8 ret_error=1;
  if(sex_type==packet->terminal->sex_type)
  { ret_error=0;
  }
  else if( sex_type<3)
  { db_queryf("update `mc_users` set sex=%d where id=%u",sex_type,packet->terminal->id);
    packet->terminal->sex_type=sex_type;
    ret_error=0; 
  } 
  msg_ack(MSG_STA_GENERAL,ret_error,packet);  
}

void Handle_MSG_USR_ACCEPTMSGPUSH(TMcPacket *packet)
{ int msg_push_acceptable=((TMSG_USR_ACCEPTMSGPUSH *)packet->msg.body)->value;
  U8 ret_error=1;
  if(msg_push_acceptable==packet->terminal->msg_push_acceptable)
  { ret_error=0;
  }
  else if((msg_push_acceptable==0 || msg_push_acceptable==1))
  { db_queryf("update `mc_users` set msgpush=%d where id=%u",msg_push_acceptable,packet->terminal->id);
    packet->terminal->msg_push_acceptable=msg_push_acceptable;
    ret_error=0;
  }
  msg_ack(MSG_STA_GENERAL,ret_error,packet);  
}


void Handle_MSG_USR_CHANGEPSW(TMcPacket *packet)
{ TMSG_USR_CHANGEPSW *req=(TMSG_USR_CHANGEPSW *)packet->msg.body;
  U8 ret_error=-1;//unknown error
  if(req->check_mode==0)//使用验证码（旧密码字段无效）
  { //用户在未登录状态，使用验证码修改密码
    if(MobilePhone_check(req->mobilephone) && Password_check(req->new_psw))
    { int vcode_err=vcode_apply(req->verifycode,req->mobilephone);
      if(vcode_err==0)
    	{ db_queryf("update `mc_users` set password=md5('%s') where username='%s'",req->new_psw,req->mobilephone);
        ret_error=0;
    	}
    	else if(vcode_err==ERR_TIMEOUT)ret_error=3; //验证码已经失效
  	else ret_error=2; //验证码错误
    }   
  } 
  else if(req->check_mode==1)//使用旧密码验证（验证码字段无效）
  { //用户在已登录状态，使用旧修改密码（要判断是否登录）
    if(Password_check(req->old_psw) && Password_check(req->new_psw) && packet->terminal && packet->terminal->id>0)
    {  MYSQL_RES *res=db_queryf("select id from `mc_users` where id=%u and password=md5('%s')",packet->terminal->id,req->old_psw);
    	 if(res){
           MYSQL_ROW row=mysql_fetch_row(res);
           if(row && row[0]){
             db_queryf("update `mc_users` set password=md5('%s') where id=%u",req->new_psw,packet->terminal->id);
             ret_error=0;
           }
           else ret_error=1; //凭证不正确（这里是密码错误）  
           mysql_free_result(res);	
         }  	
    }
  }
  msg_ack(MSG_SUA_CHANGEPSW,ret_error,packet);  
}

void Handle_MSG_USR_BIND(TMcPacket *packet)
{ // action: 0绑定; 1取消绑定
  enum{BIND_ERR_UNKNOWN=-1,BIND_OK=0,BIND_DEV_NOT_EXIST=1,BIND_CANNOT_CROSS_GROUPS=2,BIND_ALREADY_BY_SELF=10,BIND_ALREADY_BY_OTHER=11,BIND_NOT_BY_YOU=20};
  TMSG_USR_BIND *req=(TMSG_USR_BIND *)packet->msg.body;
  TMcMsg *ackmsg=msg_alloc(MSG_SUA_BIND,sizeof(TMSG_SUA_BIND));
  TMSG_SUA_BIND *ackBody=(TMSG_SUA_BIND *)ackmsg->body;
  ackBody->error=BIND_DEV_NOT_EXIST; //设备不存在
  ackBody->uid[0]=0; //初始化UID
  if(req->action==0)  //绑定操作
  {	MYSQL_RES *res=db_queryf("select `mc_devices`.id,`mc_devices`.username,`mc_devices`.groupid,`mc_uidpool`.uid,`mc_usrgroup`.devgroups from `mc_usrgroup`,(`mc_devices` left join `mc_uidpool` on `mc_devices`.sn=`mc_uidpool`.sn) where `mc_devices`.sn='%s' and `mc_usrgroup`.id=%u",req->device_sn,packet->terminal->group);
    if(res)
    {	MYSQL_ROW row=mysql_fetch_row(res);
      if(row)
      { char *p_binduser_origin=row[1];
      	if(p_binduser_origin && p_binduser_origin[0])
      	{	if(strcmp(p_binduser_origin,packet->terminal->name)==0)
      	  { ackBody->error=BIND_ALREADY_BY_SELF; //已经被你绑定
      	  }
      	  else
      	  { ackBody->error=BIND_ALREADY_BY_OTHER;  //已经被其他手机绑定
         	}
      	}
      	else if(row[4]==NULL || row[4][0]=='\0' ||str_keySeek(row[4],row[2],',')) //在允许的设备分组白明单中
      	{	if(row[3])strncpy(ackBody->uid,row[3],MAXLEN_UID+1);
      		ackBody->error=0;
          db_queryf("update `mc_devices` set username='%s' where id=%s",packet->terminal->name,row[0]);
      	}
      	else	
      	{ ackBody->error=BIND_CANNOT_CROSS_GROUPS;//不能跨组绑定
      	}
      }		
      mysql_free_result(res);
    }
  }
  else if(req->action==1) //绑定取消
  {	 MYSQL_RES *res=db_queryf("select id,username from `mc_devices` where sn='%s'",req->device_sn);
     if(res)
     { MYSQL_ROW row=mysql_fetch_row(res);
     	 if(row && row[1])
     	 { if(strcmp(row[1],packet->terminal->name)==0)
         { ackBody->error=0;
           db_queryf("update `mc_devices` set username=null where id=%s",row[0]);
         }
         else
         { ackBody->error=BIND_NOT_BY_YOU;//未被你绑定
         }	
     	 }	
     	 mysql_free_result(res);
     }
  }   
  ackBody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL);
}

void Handle_MSG_USR_GETBINDLIST(TMcPacket *packet){
  const int MAX_ITEM_SIZE=128;
  TMcMsg *ackmsg=msg_alloc(MSG_SUA_GETBINDLIST,sizeof(TMSG_SUA_GETBINDLIST)+MAX_BINDED_NUM*MAX_ITEM_SIZE);
  TMSG_SUA_GETBINDLIST *ackBody=(TMSG_SUA_GETBINDLIST *)ackmsg->body;
  MYSQL_RES *res=db_queryf("select `mc_devices`.sn,`mc_devices`.name,`mc_devices`.ssid,`mc_uidpool`.uid,`mc_devices`.state from `mc_devices` left join `mc_uidpool` on `mc_devices`.sn=`mc_uidpool`.sn where `mc_devices`.username='%s' limit %d",packet->terminal->name,MAX_BINDED_NUM);
  char *json=(char *)ackBody->json.data;
  int jslen=sprintf(json,"{\"items\":[");	
  if(res){
    MYSQL_ROW row;
    int bind_count=0;
    while((row = mysql_fetch_row(res))){ 
      if(bind_count++>0) json[jslen++]=',';	
      jslen+=sprintf(json+jslen,"{\"sn\":\"%s\",\"name\":\"%s\",\"ssid\":\"%s\",\"uid\":\"%s\",\"state\":\"%s\"}",row[0],row[1],row[2],row[3],row[4]);
    }
    mysql_free_result(res);
  }  
  jslen+=sprintf(json+jslen,"]}");
  jslen++;//保留null-terminate符位置

  ackBody->ack_synid=packet->msg.synid;
  ackBody->json.datalen=jslen;
  ackmsg->bodylen=sizeof(TMSG_SUA_GETBINDLIST)+jslen;//重新计算实际消息体长度。
  msg_send(ackmsg,packet,NULL);
}


void Handle_MSG_VSR_GETBINDUSER(TMcPacket *packet)
{ TMSG_VSR_GETBINDUSER *req=(TMSG_VSR_GETBINDUSER *)packet->msg.body;
  TMcMsg *ackmsg=msg_alloc(MSG_SVA_GETBINDUSER,sizeof(TMSG_SVA_GETBINDUSER));
  TMSG_SVA_GETBINDUSER *ackBody=(TMSG_SVA_GETBINDUSER *)ackmsg->body;
  ackBody->binded=0;
  if(req->sn[0] && db_checkSQL(req->sn))
  { MYSQL_RES *res=db_queryf("select username from `mc_devices` where sn='%s'",req->sn);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row && row[0] && row[0][0])
      { ackBody->binded=1;
        strncpy(ackBody->phone,row[0],SIZE_MOBILE_PHONE+1);
      }
      mysql_free_result(res);
    }  
  }
  ackBody->phone[SIZE_MOBILE_PHONE]='\0';//无论绑定与否，这一位必须为零，否则现有安卓APP报错。
  ackBody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL); 
}


void Handle_MSG_USR_QUERY_STATE(TMcPacket *packet){
  U8 ret_error=1,ret_state=DEV_STATE_OFFLINE;
  TMSG_USR_QUERY_STATE *req=(TMSG_USR_QUERY_STATE *)packet->msg.body;
  //printf("###GOT USR_QUERY_STATE %s\n",req->sn);
  if(req->sn[0]){
    MYSQL_RES *res=db_queryf("select session,boxid,groupid,state from `mc_devices` where sn='%s'",req->sn);
    if(res){
      MYSQL_ROW row=mysql_fetch_row(res);
      if(row){
        int groupid=atoi(row[2]);
        if(groupid!=17 && groupid!=18 && groupid!=20){// temporary logic
          ret_state=atoi(row[3]);
        }  
        else{
            U32 dev_session=atoi(row[0]); 
            if(!dev_session){
                U32 boxid=atoi(row[1]);
                if(boxid){
                    if(res)mysql_free_result(res);
                    res=db_queryf("select session from `mc_boxes` where id=%u",boxid);
                    if(res){
                        row=mysql_fetch_row(res);
                        if(row) dev_session=atoi(row[0]); 
                    }
                }
            }
            if(dev_session){//一代终端或二代盒子
                TTerminal *dev_node=(TTerminal *)dtmr_find(terminalLinks,dev_session,0,0,0);
                if(dev_node){
                    TMcMsg *reqmsg=msg_alloc(MSG_SDR_QUERY_STATE,sizeof(TMSG_SDR_QUERY_STATE));
                    memcpy(((TMSG_SDR_QUERY_STATE *)reqmsg->body)->sn,req->sn,SIZE_SN_DEVICE+1);
                   // printf("###SEND SDR_QUERY_STATE %s\n",req->sn);
                    msg_request(reqmsg,dev_node,packet,sizeof(TMcPacket));
                    if(res)mysql_free_result(res);
                    return;
                }
            }
        }
        ret_error=0; 
      }
      if(res)mysql_free_result(res);
    } 
  }
  TMcMsg *ackmsg=msg_alloc(MSG_SUA_QUERY_STATE,sizeof(TMSG_SUA_QUERY_STATE));
  TMSG_SUA_QUERY_STATE *ackbody=(TMSG_SUA_QUERY_STATE *)ackmsg->body;
  ackbody->error=ret_error;
  ackbody->state=ret_state;
  ackbody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL);
 // printf("###RESPONSE STATE DEV_STATE_OFFLINE to %s\n",req->sn);
}


void Handle_MSG_DSR_NOTIFY_STATE(TMcPacket *packet){
/*设备状态说明（对于二代设备，由于拆分成盒子与摄像头终端两部分，不同部分负责上报不同的状态，明细如下）：
 *State 0: 离线状态, 此状态不上报（离线设备不能上报），而是由程序来判断；
 *State 1: 休眠状态, 盒子上报(汽车熄火后设备进入休眠状态，定时上报间隔约45秒) 
 *State 2: 唤醒状态, 终端上报(休眠状态下被远程唤醒后的状态，并且在IDLE一段时间后会回复到休眠状态,除非汽车发动否则) 
 *State 3: 在线状态, 终端上报(汽车发动后设备将始终处于工作状态,除非熄火否则不会休眠) 
 *State 4: 正在休眠, 终端上报 
 *State 5: 正在启动, 盒子上报(盒子检测到acc点火或者震动会自动开机,并上报正在启动状态，然后再打开摄像头) 
 *State 6: 巡航状态, 终端上报 
 *State 7: 熄火事件, 终端上报 (熄火不改变状态)
 */

  extern void staticMap_generate(TTerminal *terminal);
  extern void device_stateNotifyUser(TTerminal *terminal,U32 devID);
  U8 new_state=((TMSG_DSR_NOTIFY_STATE *)packet->msg.body)->value;
  TTerminal *terminal=packet->terminal;
  msg_ack(MSG_SDA_NOTIFY_STATE,0,packet);
 // if(strcmp(terminal->name,"CAM-019522FF18000098")==0)printf("######[%s] notify state:%d\r\n",terminal->name,new_state);
  if(terminal->term_type==TT_BOX){
    MYSQL_RES *res=db_queryf("select id,session,state from `mc_devices` where boxid=%u",terminal->id);
    if(res)
    { MYSQL_ROW row;
      while((row=mysql_fetch_row(res))){
        if(atoi(row[2])!=new_state){
          db_queryf("update `mc_devices` set state=%d where id=%s",new_state,row[0]);
          U32 dev_session=atoi(row[1]); 
          if(dev_session){
             TTerminal *dev_node=(TTerminal *)dtmr_find(terminalLinks,dev_session,0,0,0);
             if(dev_node){
               dev_node->term_state=new_state;
               device_stateNotifyUser(dev_node,0);
               if(dev_node->term_state==DEV_STATE_STARTING)((TTermDevice *)dev_node)->startup_time=time(NULL);
             }
          }
        }
      }
      mysql_free_result(res);
    } 
  }/*
  else if(new_state==DEV_EVENT_ENGINEOFF){
     U32 end_time=time(NULL);
     U32 start_time=((TTermDevice *)terminal)->startup_time;
    // if(strcmp(terminal->name,"CAM-019522FF18000098")==0) printf("##########[%s]EngineOff...start_time:%u,end_time:%u,duration=%d*60000ms\r\n\r\n",terminal->name,start_time,end_time,(end_time-start_time)/60);
     if(end_time>start_time+30 && start_time>end_time-24*60*60){
        char xml[255];
        int xmlLen=sprintf(xml,"<xml><action>create</action><device>%s</device><starttime>%u</starttime><endtime>%u</endtime><session>%u</session></xml>",terminal->name,start_time,end_time,terminal->session);
        int ret=hsk_httpPost("http://"WEB_SERVER_HOST"/service/routine/trackmap.php",xml,xmlLen,NULL,0,6);
        if(ret>0)((TTermDevice *)terminal)->startup_time=end_time;
        //printf("####POST xml:%s  ########ret=%d\r\n",xml,ret);
     }
  }*/
  else if(terminal->term_state!=new_state && new_state!=DEV_EVENT_ENGINEOFF){//修改状态变量并写入数据库
    //printf("###state from %d to %d\r\n",terminal->term_state,new_state);
    if(new_state==DEV_STATE_ONLINE)((TTermDevice *)terminal)->startup_time=time(NULL);
    else if(new_state==DEV_STATE_SLEEP && terminal->term_state!=DEV_STATE_WAKEUP)staticMap_generate(terminal);
    terminal->term_state=new_state;
    db_queryf("update `mc_devices` set state=%d where id=%u",new_state,terminal->id);
    device_stateNotifyUser(terminal,0);
 }
}


void Handle_MSG_USR_READ_OFFLINEMSG(TMcPacket *packet)
{ //mc_msgbox表的category字段为负表示已经标志为删除的消息。
  //mc_msgbox表的recipient字段为消息接收者的userid，如果小于0表示接收分组的群发消息。
  MYSQL_RES *res=db_queryf("select content,category,addtime from `mc_msgbox` where recipient=%d and category>0",packet->terminal->id);
  if(res)
  {  int rowCount=0,msgDataBytes=0;	 
     MYSQL_ROW row;
     while((row=mysql_fetch_row(res)))
     { if(row[0])
       { rowCount++;
  	 msgDataBytes+=(sizeof(TMSG_SUR_NOTIFY_MSGBOX)+strlen(row[0])+1);
  	 // puts(row[0]);
       }
     }
     TMcMsg *ackmsg=msg_alloc(MSG_SUA_READ_OFFLINEMSG,sizeof(TMSG_SUA_READ_OFFLINEMSG)+msgDataBytes);
     TMSG_SUA_READ_OFFLINEMSG *ackBody=(TMSG_SUA_READ_OFFLINEMSG *)ackmsg->body;
     TMSG_SUR_NOTIFY_MSGBOX *msgBox=ackBody->msg_list;
     ackBody->ack_synid=packet->msg.synid;
     ackBody->msg_count=rowCount;
     mysql_data_seek(res,0);
     while((row=mysql_fetch_row(res)))
     { if(row[0])
       { int msglen=strlen(row[0])+1;
  	 memcpy(msgBox->content,row[0],msglen);
  	 msgBox->type=atoi(row[1]);
  	 msgBox->timestamp=atoi(row[2]);
  	 msgBox=(TMSG_SUR_NOTIFY_MSGBOX *)((char *)msgBox + (msglen+sizeof(TMSG_SUR_NOTIFY_MSGBOX)));
  	 // puts(row[0]);
       }
     }
     msg_send(ackmsg,packet,NULL);
     mysql_free_result(res);
  }	
}

void Handle_MSG_USR_DELETE_OFFLINEMSG(TMcPacket *packet)
{ //将mc_msgbox表的category字段取负表示删除消息
  db_queryf("update `mc_msgbox` set category=-category where recipient=%d and category>0",packet->terminal->id);
  msg_ack(MSG_SUA_DELETE_OFFLINEMSG,0,packet);
}

//摄像头抓拍完成通知
void Handle_MSG_DSR_NOTIFY_SNAPSHOT(TMcPacket *packet){
  char strWarning[256]="\0";
  BOOL gotSnapshot=FALSE;
  TMSG_DSR_NOTIFY_SNAPSHOT *req=(TMSG_DSR_NOTIFY_SNAPSHOT *)packet->msg.body;
  msg_ack(MSG_STA_GENERAL,0,packet);
  MYSQL_RES *res=db_queryf("select ssid,groupid from `mc_devices` where id=%d",packet->terminal->id);
  if(res){
    MYSQL_ROW row = mysql_fetch_row(res);
    if(row && row[0]){
      int devGroupID=atoi(row[1]); 
      char strTime[32];
      str_fromTime(strTime,"%Y/%m/%d %H:%M:%S",time(NULL));
      int contentLen=sprintf(strWarning,"%s%s在%s检测到一次震动，请您及时确认车辆状况是否异常",(devGroupID==ZSWL_DEV_GROUP)?"设备":"小瞳",row[0],strTime);  
      mysql_free_result(res);
      res=db_queryf("select resname from `mc_snapshot` where termid=%d and property=1 and timestamp=%u",packet->terminal->id,req->timestamp);
      if(res){
        MYSQL_ROW row = mysql_fetch_row(res);
        if(row && row[0]){
          str_fromTime(strTime,"%Y/%m/%d",req->timestamp);
    	  sprintf((char *)strWarning+contentLen,"<a>http://"WEB_SERVER_HOST""WEB_SNAPSHOT_ROOT"%s/%s_4.jpg</a>",strTime,row[0]);	
          gotSnapshot=TRUE;
        }
      }
    }
    if(res)mysql_free_result(res);
  }  
  if(gotSnapshot)push_device_msg(packet->terminal->id,WARNINGMSG_SNAPSHOT_1,strWarning);//震动抓拍通知
}

//单片机震动通知
void Handle_MSG_DSR_NOTIFY_STRIKE(TMcPacket *packet){
  msg_ack(MSG_SDA_NOTIFY_STRIKE,0,packet);
  char strWarning[256]="\0";
  char *segment=(packet->terminal->term_type==TT_BOX)?"boxid":"id";
  MYSQL_RES *res=db_queryf("select id,ssid,groupid from `mc_devices` where %s=%u",segment,packet->terminal->id);
  if(res){
    MYSQL_ROW row;
    char strTime[32];
    str_fromTime(strTime,"%Y/%m/%d %H:%M:%S",time(NULL));
    while((row = mysql_fetch_row(res))){
      if(row[1]){
        int devGroupID=atoi(row[2]); 
        sprintf(strWarning,"%s%s在%s检测到一次震动，请您及时确认车辆状况是否异常",(devGroupID==ZSWL_DEV_GROUP)?"设备":"小瞳",row[1],strTime);  
        push_device_msg(atoi(row[0]),WARNINGMSG_VIBRATE,strWarning);//震动预警
      }
    }
    mysql_free_result(res);
  }  
}

void Handle_MSG_DSR_NOTIFY_LOWPOWER(TMcPacket *packet){
  char strWarning[200];
  char *segment=(packet->terminal->term_type==TT_BOX)?"boxid":"id";
  msg_ack(MSG_STA_GENERAL,0,packet);
  MYSQL_RES *res=db_queryf("select id,ssid,groupid from `mc_devices` where %s=%u",segment,packet->terminal->id);
  if(res){
    MYSQL_ROW row;
    while((row = mysql_fetch_row(res))){
      if(row[1]){
        int devGroupID=atoi(row[2]); 
        char *devName=(devGroupID==ZSWL_DEV_GROUP)?"设备":"小瞳";
        sprintf(strWarning,"%s%s检测电瓶电压过低，将暂停远程功能，请及时发动汽车充电。如车辆发动时发现%s未启动，请手动开机。",devName,row[1],devName);  
        push_device_msg(atoi(row[0]),WARNINGMSG_LOWPOWER,strWarning);//缺电预警
      }
    }
    mysql_free_result(res);
  }  
}

void Handle_MSG_USR_WAKEUP(TMcPacket *packet)
{ TMSG_USR_WAKEUP *req=(TMSG_USR_WAKEUP *)packet->msg.body;
  U32 dev_session=0;
  if(req->device_sn[0] && db_checkSQL(req->device_sn))
  { MYSQL_RES *res=db_queryf("select session,boxid from `mc_devices` where sn='%s'",req->device_sn);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row)
      { U32 dev_box=atoi(row[1]);
        if(dev_box)
        { mysql_free_result(res);
          res=db_queryf("select session from `mc_boxes` where id=%u",dev_box);
          if(res)
          { row=mysql_fetch_row(res);
            if(row)dev_session=atoi(row[0]);
          }
        }
        else
        { dev_session=atoi(row[0]);
        }
      }
      if(res)mysql_free_result(res);
    }   
  }
  if(dev_session)
  { TTerminal *dev_node=(TTerminal *)dtmr_find(terminalLinks,dev_session,0,0,0);
    if(dev_node)
    { TMcMsg *reqmsg=msg_alloc(MSG_SDR_WAKEUP,sizeof(TMSG_SDR_WAKEUP));
      TMSG_SDR_WAKEUP *reqbody=(TMSG_SDR_WAKEUP *)reqmsg->body;
      reqbody->value=req->action;
      msg_request(reqmsg,dev_node,packet,MC_PACKET_SIZE(packet));
    }else goto label_fail;
  }
  else
  { label_fail:
    msg_ack(MSG_SUA_WAKEUP,1,packet);
  }
}

void Handle_MSG_DSR_UPLOAD_GPS(TMcPacket *packet)
{  TMSG_DSR_UPLOAD_GPS *req=(TMSG_DSR_UPLOAD_GPS *)packet->msg.body;
   U8 ret_error=1;
   U32 gps_data_len=req->count*sizeof(TGPSLocation);
   U32 gps_packet_len=gps_data_len+sizeof(TMSG_DSR_UPLOAD_GPS);
   if(req->count>0 && packet->msg.bodylen>=gps_packet_len)
   { ret_error=0; 
   }  
   msg_ack(MSG_SDA_UPLOAD_GPS,ret_error,packet);
   if(ret_error==0)
   {   db_lock(TRUE);
       MYSQL *conn=db_conn();
       MYSQL_STMT *stmt=mysql_stmt_init(conn);  
       static char InsertSQL[]="insert into `mc_gps`(termid,data,addtime) values(?,?,unix_timestamp())";
       if(mysql_stmt_prepare(stmt,InsertSQL,sizeof(InsertSQL))==0)
       { MYSQL_BIND binds[2];
  	     memset(binds,0,sizeof(binds));//把is_null、length等字段默认值设置为NULL等默认值，否则执行会报错  
  	     binds[0].buffer=&packet->terminal->id;
  	     binds[0].buffer_type=MYSQL_TYPE_LONG;
  	     binds[1].buffer=req->gpsItems;
  	     binds[1].buffer_type=MYSQL_TYPE_BLOB;
  	     binds[1].buffer_length=gps_data_len;
  	     if(mysql_stmt_bind_param(stmt,binds)==0)
  	     { mysql_stmt_execute(stmt);
  	     }
       }
       mysql_stmt_close(stmt);
       db_lock(FALSE); 
   }  
}

void Handle_MSG_USR_QUERY_GPS(TMcPacket *packet)
{ char *sn=((TMSG_USR_QUERY_GPS *)packet->msg.body)->sn;
	U8 ret_error=-1;
  TMcMsg *ackmsg=msg_alloc(MSG_SUA_QUERY_GPS,sizeof(TMSG_SUA_QUERY_GPS));
  TMSG_SUA_QUERY_GPS *ackBody=(TMSG_SUA_QUERY_GPS *)ackmsg->body;
 	if(db_checkSQL(sn))
  { MYSQL_RES *res=db_queryf("select id from `mc_devices` where sn='%s'",sn);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row)
      { U32 termid=atoi(row[0]);
      	mysql_free_result(res);
      	res=db_queryf("select data,addtime from `mc_gps` where termid=%u order by addtime desc limit 1",termid);
        if(res)
        { row=mysql_fetch_row(res);
          if(row)
          { //mysql_fetch_lengths一定要在mysql_fetch_row调用后才能调用，不然会出现内存非法访问的问题
          	unsigned long *lengths=mysql_fetch_lengths(res);
          	if(lengths)
          	{	int count=lengths[0]/sizeof(TGPSLocation);
          		if(count>0)
          		{ ret_error=0;
          		  ackBody->location=((TGPSLocation *)row[0])[count-1];
          	    ackBody->time=atoi(row[1]);
          	  }  
          	}  
          }
        }
      }
      if(res)mysql_free_result(res);  	
    }	
  } 
  ackBody->error=ret_error;
  ackBody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL); 
}

void Handle_MSG_DSR_UPLOAD_BEHAVIOR(TMcPacket *packet)
{ U8 ret_error=0;
  msg_ack(MSG_SDA_UPLOAD_BEHAVIOR,ret_error,packet);
  
  //todo: 驾驶行为存储到数据库
}

#if 1 
void Handle_MSG_DSR_UPLOAD_IMSI(TMcPacket *packet)
{ TMSG_DSR_UPLOAD_IMSI *req=(TMSG_DSR_UPLOAD_IMSI *)packet->msg.body;
  U8 ret_error=1;
  req->imsi[SIZE_IMSI]='\0';
  if(strlen(req->imsi)==SIZE_IMSI && db_checkSQL(req->imsi)){
    if(db_queryf("update `%s` set imsi='%s' where id=%u",(packet->terminal->term_type==TT_BOX)?"mc_boxes":"mc_devices",req->imsi,packet->terminal->id))
    { if(packet->terminal->term_type==TT_BOX)db_queryf("update `mc_devices` set imsi='%s' where boxid=%u",req->imsi,packet->terminal->id);
    }
    ret_error=0;
  }
  msg_ack(MSG_SDA_UPLOAD_IMSI,ret_error,packet);
}

void Handle_MSG_USR_QUERY_ACCESSNO(TMcPacket *packet)
{ TMSG_USR_QUERY_ACCESSNO *req=(TMSG_USR_QUERY_ACCESSNO *)packet->msg.body;
  TMcMsg *ackmsg=msg_alloc(MSG_SUA_QUERY_ACCESSNO,sizeof(TMSG_SUA_QUERY_ACCESSNO));
  TMSG_SUA_QUERY_ACCESSNO *ackBody=(TMSG_SUA_QUERY_ACCESSNO *)ackmsg->body;
  ackBody->error=-1;
  ackBody->accessno[0]='\0';
  if(req->device_sn[0] && db_checkSQL(req->device_sn))
  { MYSQL_RES *res=db_queryf("select `mc_simcard`.accessno from `mc_simcard` inner join `mc_devices` on `mc_simcard`.imsi=`mc_devices`.imsi where `mc_devices`.sn='%s'",req->device_sn);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row) 
      { ackBody->error=0;
        if(row[0]&&row[0][0])strncpy(ackBody->accessno,row[0],SIZE_ACCESSNO+1);
      }else ackBody->error=1;
      mysql_free_result(res);  
    }
  }
  ackBody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL);
}

#else

void Handle_MSG_DSR_UPLOAD_IMSI(TMcPacket *packet)
{ TMSG_DSR_UPLOAD_IMSI *req=(TMSG_DSR_UPLOAD_IMSI *)packet->msg.body;
  U8 ret_error=1;
  BOOL need_update_accessno=FALSE;
  req->imsi[SIZE_IMSI]='\0';
  if(strlen(req->imsi)==SIZE_IMSI && db_checkSQL(req->imsi))
  { MYSQL_RES *res=db_queryf("select imsi,accessno from `mc_devices` where id=%u",packet->terminal->id);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row)
      { if(!row[0] || strcmp(row[0],req->imsi)!=0)
        { db_queryf("update `mc_devices` set imsi='%s',accessno=null where id=%u",req->imsi,packet->terminal->id);
          need_update_accessno=TRUE;
        }
        else if(!row[1] || !row[1][0])need_update_accessno=TRUE;
        ret_error=0;
      }
      mysql_free_result(res);  
    } 
  }
  msg_ack(MSG_SDA_UPLOAD_IMSI,ret_error,packet);
  if(need_update_accessno)
  {	MYSQL_RES *res=db_queryf("select accessno,simgroup from `mc_simcard` where imsi='%s'",req->imsi);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
    	if(row)
    	{	db_queryf("update `mc_devices` set accessno='%s',simgroup=%s where id=%u",row[0],row[1],packet->terminal->id);
    		need_update_accessno=FALSE;
      }	
      mysql_free_result(res);  
    }	
  }  
}
void Handle_MSG_USR_QUERY_ACCESSNO(TMcPacket *packet)
{ TMSG_USR_QUERY_ACCESSNO *req=(TMSG_USR_QUERY_ACCESSNO *)packet->msg.body;
  TMcMsg *ackmsg=msg_alloc(MSG_SUA_QUERY_ACCESSNO,sizeof(TMSG_SUA_QUERY_ACCESSNO));
  TMSG_SUA_QUERY_ACCESSNO *ackBody=(TMSG_SUA_QUERY_ACCESSNO *)ackmsg->body;
  ackBody->error=-1;
  ackBody->accessno[0]='\0';
  if(req->device_sn[0] && db_checkSQL(req->device_sn))
  { MYSQL_RES *res=db_queryf("select accessno from `mc_devices` where sn='%s'",req->device_sn);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row) 
      { ackBody->error=0;
        if(row[0]&&row[0][0])strncpy(ackBody->accessno,row[0],SIZE_ACCESSNO+1);
      }else ackBody->error=1;
      mysql_free_result(res);  
    }
  }
  ackBody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL);
}

#endif


void Handle_MSG_USR_CONFIGS(TMcPacket *packet)
{/////////////////////////////////////////////
  #define config_key1 "pay_url"
  #define config_key2 "trackmap_url"
  #define config_key3 "video_share_url"
  #define config_key4 "appshow_url"
  MYSQL_RES *res=db_query("select "config_key1","config_key2","config_key3","config_key4" from `mc_configs`");
  if(res)
  { MYSQL_ROW row=mysql_fetch_row(res);
    if(row)
    { TMcMsg *ackmsg=msg_alloc(MSG_SUA_CONFIGS,sizeof(TMSG_SUA_CONFIGS)+1024);
      TMSG_SUA_CONFIGS *ackBody=(TMSG_SUA_CONFIGS *)ackmsg->body;
      ackBody->ack_synid=packet->msg.synid;
      ackBody->json.datalen=1+sprintf((char *)ackBody->json.data,"{\""config_key1"\":\"%s\",\""config_key2"\":\"%s\",\""config_key3"\":\"%s\",\""config_key4"\":\"%s\"}",(row[0])?row[0]:"",(row[1])?row[1]:"",(row[2])?row[2]:"",(row[3])?row[3]:"");
      ackmsg->bodylen=sizeof(TMSG_SUA_CONFIGS)+ackBody->json.datalen;
      msg_send(ackmsg,packet,NULL);
    }
    mysql_free_result(res);  
  }
}

void Handle_MSG_DSR_QUERY_SNQQ(TMcPacket *packet)
{ TMcMsg *ackmsg=msg_alloc(MSG_SDA_QUERY_SNQQ,sizeof(TMSG_SDA_QUERY_SNQQ));
	TMSG_SDA_QUERY_SNQQ *ackBody=(TMSG_SDA_QUERY_SNQQ *)ackmsg->body;
	ackBody->error=-1;
	ackBody->snqq[0]='\0';
	MYSQL_RES *res=db_queryf("select snqq,qqlicense from `mc_devices` where id=%u",packet->terminal->id);
  if(res)
  { MYSQL_ROW row=mysql_fetch_row(res);
    if(row && row[0] && row[1])
    { ackBody->error=0;
      strncpy(ackBody->snqq,row[0],SIZE_SN_QQ+1);
      strncpy(ackBody->license,row[1],256);
    }
    mysql_free_result(res);  
  }
  ackBody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL);
}

/*
void get_sn808_by_snqq(char *sn808,char *snqq)
{ memcpy(sn808,"20101",5);//头5位固定码
	strncpy(sn808+5,(char *)snqq+9,7);//后7位与snqq的一致
	sn808[SIZE_SN_808]='\0';
}*/


void Handle_MSG_DSR_QUERY_SN808(TMcPacket *packet)
{ TMcMsg *ackmsg=msg_alloc(MSG_SDA_QUERY_SN808,sizeof(TMSG_SDA_QUERY_SN808));
	TMSG_SDA_QUERY_SN808 *ackBody=(TMSG_SDA_QUERY_SN808 *)ackmsg->body;
	ackBody->error=-1;
	ackBody->sn808[0]='\0';
	MYSQL_RES *res=db_queryf("select sn808 from `mc_devices` where id=%u",packet->terminal->id);
  if(res)
  { MYSQL_ROW row=mysql_fetch_row(res);
    if(row)
    { ackBody->error=0;
      if(row[0]&&row[0][0])strncpy(ackBody->sn808,row[0],SIZE_SN_808+1);
    }
    mysql_free_result(res);  
  }
  ackBody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL);
}


void Handle_MSG_USR_QUERY_SN808(TMcPacket *packet)
{ TMSG_USR_QUERY_SN808 *req=(TMSG_USR_QUERY_SN808 *)packet->msg.body;
	TMcMsg *ackmsg=msg_alloc(MSG_SUA_QUERY_SN808,sizeof(TMSG_SUA_QUERY_SN808));
	TMSG_SUA_QUERY_SN808 *ackBody=(TMSG_SUA_QUERY_SN808 *)ackmsg->body;
	ackBody->error=-1;
	ackBody->sn808[0]='\0';
	if(req->device_sn[0] && db_checkSQL(req->device_sn))
	{ MYSQL_RES *res=db_queryf("select sn808 from `mc_devices` where sn='%s'",req->device_sn);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row) 
      { ackBody->error=0;
        if(row[0]&&row[0][0])strncpy(ackBody->sn808,row[0],SIZE_SN_808+1);
      }else ackBody->error=1;
      mysql_free_result(res);  
    }
  }
  ackBody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL);
}

void Handle_MSG_USR_QUERY_SN_FROM808(TMcPacket *packet)
{ TMSG_USR_QUERY_SN_FROM808 *req=(TMSG_USR_QUERY_SN_FROM808 *)packet->msg.body;
	TMcMsg *ackmsg=msg_alloc(MSG_SUA_QUERY_SN_FROM808,sizeof(TMSG_SUA_QUERY_SN_FROM808));
	TMSG_SUA_QUERY_SN_FROM808 *ackBody=(TMSG_SUA_QUERY_SN_FROM808 *)ackmsg->body;
	ackBody->error=-1;
	ackBody->device_sn[0]='\0';
	if(req->sn808[0] && db_checkSQL(req->sn808))
	{ MYSQL_RES *res=db_queryf("select sn from `mc_devices` where sn808='%s'",req->sn808);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row) 
      { ackBody->error=0;
        if(row[0])strncpy(ackBody->device_sn,row[0],SIZE_SN_DEVICE+1);
      }else ackBody->error=1;
      mysql_free_result(res);  
    }
  }
  ackBody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL);	
}


void Handle_MSG_DSR_COMMJSON(TMcPacket *packet)
{  const int max_json_size=8192;
   T_VARDATA *req=(T_VARDATA *)packet->msg.body;
   msg_ack(MSG_STA_GENERAL,0,packet);
   if(req->datalen>=0 && req->datalen<max_json_size)
   { char sql[max_json_size+50];
     char *segment=(packet->terminal->term_type==TT_BOX)?"boxid":"id";
     req->data[req->datalen]='\0';
     sprintf(sql,"update `mc_devices` set json='%s' where %s=%u",db_filterSQL((char *)req->data),segment,packet->terminal->id);
     db_query(sql);
  }
}

/*
static CancelBoxBinding(int boxid){
   MYSQL_RES *res=db_queryf("select id,session,state from mc_devices where boxid=%d",boxid);
   if(res){
     MYSQL_ROW row;
     while((row=mysql_fetch_row(res))){
         U32 dev_session=atoi(row[1]);
                U32 dev_state=atoi(row[2]);
                if(dev_session==0 && dev_state!=DEV_STATE_OFFLINE){
                  U32 dev_id=atoi(row[0]);
                }
              }
              mysql_free_result(res);
            }
}
*/

void Handle_MSG_DSR_UPDATE_BOXSN(TMcPacket *packet)
{ TMSG_DSR_UPDATE_BOXSN *req=(TMSG_DSR_UPDATE_BOXSN *)packet->msg.body;
  U8 ret_error=1;
  req->boxsn[SIZE_SN_BOX]='\0';
  if(strlen(req->boxsn)==SIZE_SN_BOX && db_checkSQL(req->boxsn))
  { MYSQL_RES *res=db_queryf("select id,imsi from `mc_boxes` where sn='%s'",req->boxsn);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row && row[0])
      { U32 boxid=atoi(row[0]);
        TTermDevice *tbox=(TTermDevice *)(packet->terminal);
        if(boxid!=tbox->boxid)
        { char *box_imsi=(row[1])?row[1]:"";  
          //CancelBoxBinding(atoi(row[0]));//cancel bind of the target box to any other devices;
          db_queryf("update `mc_devices` set boxid=0,imsi=null,state=0 where boxid=%s",row[0]);
          db_queryf("update `mc_devices` set boxid=%s,imsi='%s' where id=%u",row[0],box_imsi,packet->terminal->id);
          tbox->boxid=boxid;
        }
        ret_error=0;
      }
      mysql_free_result(res);  
    } 
  }
  msg_ack(MSG_STA_GENERAL,ret_error,packet);
}

