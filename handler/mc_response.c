#include "mc_routine.h"
//---------------------------------------------------------------------------
void Response_MSG_TIMEOUT(TMcPacket *request,void *extraData){
  switch(request->msg.msgid){
      case MSG_SUR_NOTIFY_MSGBOX:{
             extern void push_device_msg_timeout(TMcPacket *);
             push_device_msg_timeout(request);
           }
           break;
  }
}

void Response_MSG_DSA_QUERY_STATE(TMcPacket *response,void *extraData){
 TMcPacket *sus_packet=(TMcPacket *)extraData;
 TMSG_DSA_QUERY_STATE *ackData=(TMSG_DSA_QUERY_STATE *)response->msg.body;
 TMcMsg *ackmsg=msg_alloc(MSG_SUA_QUERY_STATE,sizeof(TMSG_SUA_QUERY_STATE));
 TMSG_SUA_QUERY_STATE *ackbody=(TMSG_SUA_QUERY_STATE *)ackmsg->body;
 ackbody->error=ackData->error;
 ackbody->state=ackData->state;
 ackbody->ack_synid=sus_packet->msg.synid;
 msg_send(ackmsg,sus_packet,NULL);
 if(ackData->error==0 && response->terminal->term_type==TT_DEVICE && response->terminal->term_state!=ackData->state){
   response->terminal->term_state=ackData->state;
   db_queryf("update `mc_devices` set state=%d where id=%u",ackData->state,response->terminal->id);
 } 
 //printf("###RESPONSE STATE %d\n",(raw->error)?-1:raw->state);
 //printf("####respose query state =%d\r\n",ackbody->error);
}

void  Response_MSG_DSA_WAKEUP(TMcPacket *response,void *extraData)
{ TMcPacket *sus_packet=(TMcPacket *)extraData;
  U8 ret_error=((TMSG_ACK_GENERAL *)response->msg.body)->error;
  msg_ack(MSG_SUA_WAKEUP,ret_error,sus_packet);
  
 // printf("####respose wakeup =%d\r\n",ret_error);
/* 终端设备响应成功只表示响应操作，不表示已经成功执行唤醒或者休眠。
   当终端设备执行完唤醒或者休眠后（状态发生变更时），会通过MSG_DSR_NOTIFY_STATE指令来通知服务器。*/
}

void Response_MSG_USA_NOTIFY_MSGBOX(TMcPacket *response,void *extraData){
}

void Response_MSG_USA_KICKOFF(TMcPacket *response,void *extraData){
  /* TMSG_ACK_GENERAL *ackBody=(TMSG_ACK_GENERAL *)response->msg.body;
  if(ackBody->error==0)
  { Log_AppendText("user kicked off!");
  }*/
}

void Response_MSG_USA_NOTIFY_STATE(TMcPacket *response, void *extraData){
  /*TMSG_ACK_GENERAL *ackBody=(TMSG_ACK_GENERAL *)response->msg.body;
  if(ackBody->error==0)Log_AppendText("terminal state notify succeed!");
  */
}

