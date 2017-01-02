#include "mc_routine.h"
//---------------------------------------------------------------------------
HAND terminalLinks=NULL,commDataLinks=NULL;
//commDataLinks通用性规则约定：hTaskID存储消息ID，由字段值决定附件数据结构类型。
//---------------------------------------------------------------------------
//将终端在线状态变化后通知绑定的用户手机
void device_stateNotifyUser(TTerminal *devTerm,U32 devID){
  MYSQL_RES *res=db_queryf("select mc_users.session,mc_devices.sn,mc_devices.state from (mc_users inner join mc_devices on mc_devices.username=mc_users.username) where mc_devices.id=%u ",(devTerm)?devTerm->id:devID);
  if(res){
     MYSQL_ROW row=mysql_fetch_row(res);
     if(row){
        U32 binded_usersession=atoi(row[0]);
        if(binded_usersession){
          TTerminal * usrnode=(TTerminal *)dtmr_find(terminalLinks,binded_usersession,0,0,0);
          if(usrnode){//if binded user is online
            TMcMsg *reqmsg=msg_alloc(MSG_SUR_NOTIFY_STATE,sizeof(TMSG_SUR_NOTIFY_STATE));
            TMSG_SUR_NOTIFY_STATE *reqbody=(TMSG_SUR_NOTIFY_STATE *)reqmsg->body;
            if(row[1])memcpy(reqbody->device_sn,row[1],SIZE_SN_DEVICE+1);
            reqbody->state_type=0;
            reqbody->state_value=(devTerm)?devTerm->term_state:atoi(row[2]);
            msg_request(reqmsg,usrnode,MSG_USA_NOTIFY_STATE,NULL,0);
          }
        }  
      }
      mysql_free_result(res);
  } 
}

//---------------------------------------------------------------------------
void staticMap_generate(TTerminal *terminal){
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
}
//---------------------------------------------------------------------------
//终端设备或手机的心跳超时处理
static void terminal_HbTimeout(HAND ttasks,void *taskCode,U32 *taskID,char *taskName,U32 *sUpdateLifeTime){
  extern void spy_notify(U8 value, TNetAddr *spyAddr);
  TTerminal * terminal=(TTerminal *)taskCode;
 // Log_AppendText("\r\n[HeatBeatTimeout:%s]",terminal->name);
  switch(terminal->term_type){
    case TT_BOX:{
           db_queryf("update `mc_boxes` set session=0,logouttime=unix_timestamp() where id=%u",terminal->id);
            MYSQL_RES *res=db_queryf("select id,session,state from mc_devices where boxid=%u",terminal->id);
            if(res)
            { MYSQL_ROW row;
              while((row=mysql_fetch_row(res))){
                U32 dev_session=atoi(row[1]);
                U32 dev_state=atoi(row[2]);
                if(dev_session==0 && dev_state!=DEV_STATE_OFFLINE){
                  U32 dev_id=atoi(row[0]);
                  db_queryf("update `mc_devices` set state=%d where id=%u",DEV_STATE_OFFLINE,dev_id);
                  device_stateNotifyUser(NULL,dev_id);//通知绑定手机终端摄像头已离线
                }
              }
              mysql_free_result(res);
            }
            if(terminal->spyAddr.ip)spy_notify(SPY_TERMINAL_OFFLINE, &terminal->spyAddr);
         }
         break;
    case TT_DEVICE:{//device
           U32 box_session=0;
           U32 boxid=((TTermDevice *)terminal)->boxid;
           if(boxid)//盒子未离线
           { MYSQL_RES *res=db_queryf("select session from mc_boxes where id=%u",boxid);
             if(res)
             { MYSQL_ROW row=mysql_fetch_row(res);
               if(row) box_session=atoi(row[0]);
               mysql_free_result(res);
             }
           }
           if(box_session){//存在在线的盒子
             //只释放session,不修改终端state(只要盒子在线，终端系统就没有离线).
             db_queryf("update `mc_devices` set session=0,logouttime=unix_timestamp() where id=%u",terminal->id);
           }
           else{//没有盒子或者盒子不在线
             //释放session,并修改终端state(确定全套系统离线).
             db_queryf("update `mc_devices` set session=0,state=%d,logouttime=unix_timestamp() where id=%u",DEV_STATE_OFFLINE,terminal->id);
             terminal->term_state=DEV_STATE_OFFLINE;
             device_stateNotifyUser(terminal,0);//通知绑定手机终端摄像头已离线
           }
           staticMap_generate(terminal);
           if(terminal->spyAddr.ip)spy_notify(SPY_TERMINAL_OFFLINE, &terminal->spyAddr);
         }
         break;
    case TT_USER: //user
           db_queryf("update `mc_users` set session=0,logouttime=unix_timestamp() where id=%u",terminal->id);
           if(terminal->spyAddr.ip)spy_notify(SPY_TERMINAL_OFFLINE, &terminal->spyAddr);
         break;
  }
  DBLog_AppendData("\xFF\xFF\xFF\xFF\x01",5,terminal); //超时登出日志
}
//---------------------------------------------------------------------------
U32 SessionID_new(void)
{ while(1)
  { U32 rand_session=rand();
    if(rand_session)
    { if(!dtmr_find(terminalLinks,rand_session,0,0,0))return rand_session;
    }	
  }	
}
//---------------------------------------------------------------------------
void terminal_init(void)
{ MYSQL_RES *res;
  U32 local_UdpSocket=hsk_getUdpSocket();
  terminalLinks=dtmr_create(1024,HEARTBEAT_OVERTIME_S,terminal_HbTimeout);
  commDataLinks=dtmr_create(0,60,NULL);
  res=db_query("select id,username,session,ip,port,groupid,sex,msgpush,livepush from `mc_users` where session<>0");
  if(res)
  { MYSQL_ROW row;
    while((row = mysql_fetch_row(res)))
    { U32 sessionid=atoi(row[2]);//field["session"]
      TTerminal *node=(TTerminal *)dtmr_add(terminalLinks,sessionid,0,0,NULL,sizeof(TTermUser),HEARTBEAT_OVERTIME_S);
      if(node)
      { node->term_type=TT_USER;
        node->session=sessionid;
        node->spyAddr.ip=0;
        node->loginAddr.socket=local_UdpSocket;
        node->live_user=0;//直播路径
        node->live_state=STAT_LIVE_CLOSE; //直播状态
        node->id=atoi(row[0]);//field["id"]
        strncpy(node->name,row[1],SIZE_MOBILE_PHONE+1);//field["username"]
        node->loginAddr.ip=atoi(row[3]);//field["ip"]
        node->loginAddr.port=atoi(row[4]);//field["port"]
        node->group=atoi(row[5]);//field["groupid"]
        node->sex_type=atoi(row[6]);//field["sex"]
        node->msg_push_acceptable=atoi(row[7]);//field["msgpush"]
        node->live_push_acceptable=atoi(row[8]);//field["livepush"]
      }
    }   
    mysql_free_result(res); 
  }

  res=db_query("select id,sn,session,ip,port,groupid,state,boxid from `mc_devices` where session<>0");
  if(res)
  { MYSQL_ROW row;
    while((row = mysql_fetch_row(res)))
    { U32 sessionid=atoi(row[2]);//field["session"]
      TTerminal *node=(TTerminal *)dtmr_add(terminalLinks,sessionid,0,0,NULL,sizeof(TTermDevice),HEARTBEAT_OVERTIME_S);
      if(node)
      { node->term_type=TT_DEVICE;
        node->session=sessionid; 
        node->spyAddr.ip=0;
        node->loginAddr.socket=local_UdpSocket;
        node->live_state=STAT_LIVE_CLOSE; //直播状态
        node->live_user=0;//直播路径
        node->id=atoi(row[0]);//field["id"]
        strncpy(node->name,row[1],SIZE_SN_DEVICE+1);//field["sn"]
        node->loginAddr.ip=atoi(row[3]);//field["ip"]
        node->loginAddr.port=atoi(row[4]);//field["port"]
        node->group=atoi(row[5]);//field["groupid"]
        node->term_state=atoi(row[6]);//field["state"]
        ((TTermDevice *)node)->boxid=atoi(row[7]);//field["boxid"];
        ((TTermDevice *)node)->startup_time=0;
      }
    }   
    mysql_free_result(res); 
  }

  res=db_query("select id,sn,session,ip,port,groupid from `mc_boxes` where session<>0");
  if(res)
  { MYSQL_ROW row;
    while((row = mysql_fetch_row(res)))
    { U32 sessionid=atoi(row[2]);//field["session"]
      TTerminal *node=(TTerminal *)dtmr_add(terminalLinks,sessionid,0,0,NULL,sizeof(TTermBox),HEARTBEAT_OVERTIME_S);
      if(node)
      { node->term_type=TT_BOX;
        node->session=sessionid; 
        node->spyAddr.ip=0;
        node->loginAddr.socket=local_UdpSocket;
        node->id=atoi(row[0]);//field["id"]
        strncpy(node->name,row[1],SIZE_SN_BOX+1);//field["sn"]
        node->loginAddr.ip=atoi(row[3]);//field["ip"]
        node->loginAddr.port=atoi(row[4]);//field["port"]
        node->group=atoi(row[5]);//field["groupid"]
      }
    }   
    mysql_free_result(res); 
  }
}

