#ifndef _MC_MAIN_H
#define _MC_MAIN_H
//---------------------------------------------------------------------------
#ifdef DEBUG_MODE
  #define HINT_UNEXPECTED_MSG() Log_AppendText("Unexpected MSG:%x from [%s:%d]@%u",packet->msg.msgid,inet_ntoa(*((struct in_addr *)&packet->peerAddr.ip)),packet->peerAddr.port,time(NULL))
  #define HINT_GOT_MSG(MSGNAME)    puts("[GOT: "#MSGNAME"]")
#else
  #define HINT_UNEXPECTED_MSG() 
  #define HINT_GOT_MSG(MSGNAME)
#endif
//---------------------------------------------------------------------------
#define BEGIN_MESSAGE_MAP_ONLINE    if(packet->terminal){switch(packet->msg.msgid){
#define BEGIN_MESSAGE_MAP_ANYWAY    }}switch(packet->msg.msgid){ 
#define END_MESSAGE_MAP             default:HINT_UNEXPECTED_MSG();msg_ack(MSG_STA_GENERAL,(packet->terminal)?2:1,packet);}
//#define MESSAGE_HANDLER(MSGNAME)    case MSGNAME:{extern void Handle_##MSGNAME(TMcPacket *);HINT_GOT_MSG(#MSGNAME);if(MSGNAME&MSG_STA_GENERAL){if(!msg_response_dispatch(packet,Handle_##MSGNAME))puts("unexpected response msg:"#MSGNAME);}else Handle_##MSGNAME(packet);/*puts("[DONE: "#MSGNAME"]");*/return;}

#define MESSAGE_HANDLER(MSGNAME)    case MSGNAME:{HINT_GOT_MSG(#MSGNAME);if(MSGNAME&MSG_STA_GENERAL){extern void Response_##MSGNAME(TMcPacket *,void *);if(!msg_response_dispatch(packet,Response_##MSGNAME))puts("unexpected response msg:"#MSGNAME);}else{extern void Handle_##MSGNAME(TMcPacket *);Handle_##MSGNAME(packet);/*puts("[DONE: "#MSGNAME"]");*/}return;}
//---------------------------------------------------------------------------
extern void mc_init(void);
extern void mc_handler(void*);
extern BOOL msg_response_dispatch(TMcPacket *packet,void msgHandle(TMcPacket *,void *));
//---------------------------------------------------------------------------
#endif
