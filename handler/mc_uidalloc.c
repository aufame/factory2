#include "mc_routine.h"
//---------------------------------------------------------------------------
/*
UID池中的UID，根据分配状况分两种基本状态：
(1). 未分配UID（已经释放或未使用的空闲UID）
(2). 已分配UID（已绑定到某个终端的UID）。
对于已分配UID，根据其设备在线状态又分两种：
(1) 在线UID （设备在线)
(2) 离线UID （设备离线)
UID分配机制：
 （1）用户申请分配UID时，如果当前UID没有被释放，则仍旧分配当前UID。
 （2）用户申请分配UID时，如果当前UID已经被释放，分两种情况。一种是直接从UID池中分配一个空闲的UID；另一种是，强制释放一个离线时间最长的UID。      如果当前UID池中空闲UID充足，则采用第一种，否则采用第二种。（临界条件空闲UID数<uid_reserved_num)。
*/
//---------------------------------------------------------------------------
void Handle_MSG_DSR_APPLYFORUID(TMcPacket *packet){
  TMcMsg *ackmsg=msg_alloc(MSG_SDA_APPLYFORUID,sizeof(TMSG_SDA_APPLYFORUID));
  TMSG_SDA_APPLYFORUID *ackbody=(TMSG_SDA_APPLYFORUID *)ackmsg->body;
  char bind_phone[SIZE_MOBILE_PHONE+1];
  BOOL uid_changed=FALSE;
  ackbody->error=1;
  bind_phone[0]='\0';

  db_lock(TRUE);
  //get bindedUser and origin UID of the device
  //the return UID should be null where the origin UID of the device is not in the uidpool
  //MYSQL_RES *rs=db_queryf("select `mc_devices`.uid,`mc_devices`.username,`mc_uidpool`.uid from `mc_devices` left join `mc_uidpool` on `mc_devices`.sn=`mc_uidpool`.sn where `mc_devices`.id=%u",packet->terminal->id);
  MYSQL_RES *rs=db_queryf("select `mc_devices`.username,`mc_uidpool`.uid,`mc_uidpool`.id from `mc_devices` left join `mc_uidpool` on `mc_devices`.sn=`mc_uidpool`.sn where `mc_devices`.id=%u",packet->terminal->id);
  if(rs)
  { MYSQL_ROW row=mysql_fetch_row(rs);
    if(row){
      if(row[1] && row[1][0])
      { //原来的UID尚未被回收，则仍分配使用原来的UID
        strncpy(ackbody->uid,row[1],MAXLEN_UID+1);
        ackbody->error=0;
      }
      else
      { if(row[0])strncpy(bind_phone,row[0],SIZE_MOBILE_PHONE+1);	
        if(row[2])db_queryf("update `mc_uidpool` set sn=null where id=%s",row[2]); //this case may not happen.
      }
    }	
    mysql_free_result(rs);  	
  }
  
  if(ackbody->error){
    //获取一个空闲的UID
    if((rs=db_query("select uid from `mc_uidpool` where sn is null and uid is not null order by id asc limit 1"))){
      MYSQL_ROW row=mysql_fetch_row(rs);
      if(row && row[0]){
         strncpy(ackbody->uid,row[0],MAXLEN_UID+1);
         ackbody->error=0;
         uid_changed=TRUE;
      }
      mysql_free_result(rs);  
    }
    if(!uid_changed){//找到一个离线时间最长的UID，并计划将其回收重新分配
      if((rs=db_query("select `mc_uidpool`.uid from `mc_devices` inner join `mc_uidpool` on `mc_devices`.sn=`mc_uidpool`.sn where `mc_devices`.session=0 and `mc_devices`.sn is not null and `mc_uidpool`.uid is not null order by `mc_devices`.logouttime asc limit 1"))){
       MYSQL_ROW row=mysql_fetch_row(rs);
       if(row && row[0]){
         strncpy(ackbody->uid,row[0],MAXLEN_UID+1);
    	 ackbody->error=0;
    	 uid_changed=TRUE;
        }
        mysql_free_result(rs);  
      }
    }		
  }
  ackbody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL); 	
  
  //如果UID发生变更时，调整UID绑定关系，并通知绑定手机
  if(!ackbody->error && uid_changed){
    db_queryf("update `mc_uidpool` set sn='%s',updatetime=unix_timestamp() where uid='%s'",packet->terminal->name,ackbody->uid);
    if(bind_phone[0]){
      if((rs=db_queryf("select session from `mc_users` where username='%s'",bind_phone))){
        MYSQL_ROW row=mysql_fetch_row(rs);
        if(row && row[0]){
          U32 binded_usersession=atoi(row[0]);
          if(binded_usersession){
            TTerminal * usrnode=(TTerminal *)dtmr_find(terminalLinks,binded_usersession,0,NULL,0);
            if(usrnode){//if binded user is online
              TMcMsg *reqmsg=msg_alloc(MSG_SUR_NOTIFY_STATE,sizeof(TMSG_SUR_NOTIFY_STATE));
              TMSG_SUR_NOTIFY_STATE *ackbody=(TMSG_SUR_NOTIFY_STATE *)reqmsg->body;
              strncpy(ackbody->device_sn,packet->terminal->name,SIZE_SN_DEVICE+1);
              ackbody->state_type=1;//UID已经变更(state值无效)
              ackbody->state_value=0;//UID已经变更(state值无效)
              msg_request(reqmsg,usrnode,MSG_USA_NOTIFY_STATE,NULL,0);
            }
          }    
        }
        mysql_free_result(rs);
      }
    }   
  }
  db_lock(FALSE);
}
