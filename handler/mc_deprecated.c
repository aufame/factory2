#include "mc_routine.h"
//---------------------------------------------------------------------------
//上传ICCI的接口已经废弃
void Handle_MSG_DSR_UPLOAD_ICCID(TMcPacket *packet){
#if 0 
  TMSG_DSR_UPLOAD_ICCID *req=(TMSG_DSR_UPLOAD_ICCID *)packet->msg.body;
  U8 ret_error=1;
  req->iccid[SIZE_ICCID]='\0';
  if(strlen(req->iccid)==SIZE_ICCID && db_checkSQL(req->iccid))
  { db_queryf("update `mc_devices` set iccid='%s' where id=%u",req->iccid,packet->terminal->id);
    ret_error=0;
  }
  msg_ack(MSG_SDA_UPLOAD_ICCID,ret_error,packet); 
#else
  msg_ack(MSG_SDA_UPLOAD_ICCID,0,packet); 
#endif
}

typedef struct
{ U32 ack_synid;
  U32 app_version_main,app_version_minor;
  char app_download_url[MAXLEN_URL]; 
  U32  mainfw_version;
  char fw_download_url[MAXLEN_URL]; 
  char fw_upgradelog_url[MAXLEN_URL]; 
}TMSG_SUA_VERSION;

typedef struct
{ char device_sn[SIZE_SN_DEVICE+1];
  char device_ssid[MAXLEN_SSID+1];
  char device_uid[MAXLEN_UID+1];
  U8   state;//0:离线;1:休眠;2:唤醒;3:在线;
}TBindMapItem;

typedef struct
{ U32 ack_synid;
  S32 bind_num;//绑定终端个数
  TBindMapItem binded[0];
}TMSG_SUA_GETBINDLIST_DEPRECATED;


void Handle_MSG_USR_VERSION_DEPRECATED(TMcPacket *packet)
{ const int GROUPID_DEFAULT=1;//1为默认分组
  TMcMsg *ackmsg=msg_alloc(MSG_SUA_VERSION_DEPRECATED,sizeof(TMSG_SUA_VERSION));
  TMSG_SUA_VERSION *ackbody=(TMSG_SUA_VERSION *)ackmsg->body;
  U32 usrGroup=(packet->terminal)?packet->terminal->group:GROUPID_DEFAULT;
  ackbody->ack_synid=packet->msg.synid;
  MYSQL_RES *res;
  res=db_queryf("select app_ver_main,app_ver_minor,app_url from `mc_usrgroup` where id=%u",usrGroup);
  if(res)
  { BOOL got_devUpgradeInfo=FALSE; 
    MYSQL_ROW row=mysql_fetch_row(res);
    if(row)
    { ackbody->app_version_main=(row[0])?atoi(row[0]):0;
      ackbody->app_version_minor=(row[1])?atoi(row[1]):0;
      if(row[2]&&row[2][0])
      { if(sprintf(ackbody->app_download_url,"http://"WEB_SERVER_HOST"%s",row[2])>=MAXLEN_URL)abort();
      }else ackbody->app_download_url[0]='\0';
      if(packet->terminal)
      { mysql_free_result(res);
        res=db_queryf("select groupid from `mc_devices` where username='%s'",packet->terminal->name);
        if(res){
          U32 devGroup=0;
          while((row=mysql_fetch_row(res))){
            if(row && row[0]){
              U32 newgroup=atoi(row[0]);
              if(devGroup==0){
                devGroup=newgroup;
              }
              else if(devGroup!=newgroup){
                devGroup=0;
                break;
              }
            }
          }
          if(devGroup){
            mysql_free_result(res);
            res=db_queryf("select mainfw_ver,mainfw_url,mainfw_log from `mc_devgroup` where id=%d",devGroup);
            if(res && (row=mysql_fetch_row(res))){
              ackbody->mainfw_version=(row[0])?atoi(row[0]):0;
              if(row[1]&&row[1][0]){
                 if(sprintf(ackbody->fw_download_url,"http://"WEB_SERVER_HOST"%s",row[1])>=MAXLEN_URL)abort();
              } else ackbody->fw_download_url[0]='\0';
              if(row[2]&&row[2][0]){
                 if(sprintf(ackbody->fw_upgradelog_url,"http://"WEB_SERVER_HOST"%s",row[2])>=MAXLEN_URL)abort();
              }else ackbody->fw_upgradelog_url[0]='\0';
              got_devUpgradeInfo=TRUE;
            }
          }
        }
      }
      if(!got_devUpgradeInfo)
      { ackbody->mainfw_version=0;
        ackbody->fw_download_url[0]='\0';
        ackbody->fw_upgradelog_url[0]='\0';
      }
      msg_send(ackmsg,packet,NULL); 
    }
    if(res)mysql_free_result(res);
  } 
}
;
void Handle_MSG_USR_GETBINDLIST_DEPRECATED(TMcPacket *packet)
{ TMcMsg *ackmsg=msg_alloc(MSG_SUA_GETBINDLIST_DEPRECATED,sizeof(TMSG_SUA_GETBINDLIST_DEPRECATED)+MAX_BINDED_NUM*sizeof(TBindMapItem));
  TMSG_SUA_GETBINDLIST_DEPRECATED *ackBody=(TMSG_SUA_GETBINDLIST_DEPRECATED *)ackmsg->body;
  U32 binded_num=0;
  MYSQL_RES *res=db_queryf("select `mc_devices`.sn,`mc_devices`.ssid,`mc_devices`.state,`mc_uidpool`.uid from `mc_devices` left join `mc_uidpool` on `mc_devices`.sn=`mc_uidpool`.sn where `mc_devices`.username='%s'",packet->terminal->name);
  if(res)
  { MYSQL_ROW row;
    while((row = mysql_fetch_row(res)) && binded_num<MAX_BINDED_NUM)
    { 
      TBindMapItem *item=&ackBody->binded[binded_num];
      strncpy(item->device_sn,(row[0])?row[0]:"",SIZE_SN_DEVICE+1);
      strncpy(item->device_ssid,(row[1])?row[1]:"",MAXLEN_SSID+1);
      item->state=atoi(row[2]); 
      strncpy(item->device_uid,(row[3])?row[3]:"",MAXLEN_UID+1);
      binded_num++;
    }
    mysql_free_result(res);
  }  
  ackBody->ack_synid=packet->msg.synid;
  ackBody->bind_num=binded_num;
  ackmsg->bodylen=sizeof(TMSG_SUA_GETBINDLIST_DEPRECATED)+sizeof(TBindMapItem)*binded_num;//计算实际消息体长度
  msg_send(ackmsg,packet,NULL);
}


