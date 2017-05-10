//---------------------------------------------------------------------------
#ifndef _MC_ROUTINE_H
#define _MC_ROUTINE_H
//---------------------------------------------------------------------------
#include <mysql/mysql.h>
#include "mc_base.h"
#include "hybServKit.h"
#include "mc_config.h"
#include "mc_intern.h"
#include "mc_string.h"
#include "mc_msg.h"
//---------------------------------------------------------------------------
int  app_exepath(char *pathbuf,int bufsize);
void Log_AppendData(void *data,int datalen,TNetAddr *peerAddr,BOOL bSendOrRecv);
void Log_AppendText(const char *format, ...);
void DBLog_AppendMsg(TMcMsg *msg,TTerminal *terminal,BOOL bSendOrRecv);
void DBLog_AppendData(void *data,int dataLen,TTerminal *terminal);
BOOL MobilePhone_check(char *number);
BOOL Password_check(char *number);
void spy_notify(U8 value, TNetAddr *spyAddr);
int vcode_apply(char *code,char *phone);
int sms_send(char *content,char *phones,int usrgroup);
TMcMsg *msg_alloc(U32 msgID,U32 bodyLen);
BOOL msg_decrypt(TMcMsg *msg);
void msg_UpdateChecksum(void *data,int datalen);
BOOL msg_ValidChecksum(void *data,int datalen);
void msg_send(TMcMsg *msg,TMcPacket *packet,TTerminal *terminal);
void msg_sendto(TMcMsg *msg,TNetAddr *peerAddr,TNetAddr *forwardAddr);
//void msg_request(TMcMsg *msg,TTerminal *terminal,U32 ackMsgID,TMcPacket *srcPacket,U32 msgBodyLenToStore);
void msg_request(TMcMsg *msg,TTerminal *terminal,void *extraData,U32 extraSize);
void msg_ack(U32 msgid,U8 error,TMcPacket *packet);
void push_device_msg(U32 deviceID,int msgType,char *msgContent);
int push_group_msg(U32 usrgroup,U32 devgroup,int msgType,char *msgContent,char *msgTitle);
//---------------------------------------------------------------------------
extern HAND terminalLinks,commDataLinks;
//---------------------------------------------------------------------------
#endif
