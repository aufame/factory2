//---------------------------------------------------------------------------
#ifndef _MC_INTERN_H
#define _MC_INTERN_H
//---------------------------------------------------------------------------
enum{TT_USER=0,TT_DEVICE=1,TT_BOX=2};
enum{UDP=0,TCP=1};
//enum{SESSION_NULL=0,SESSION_OFFLINE=1,SESSION_RESEARVED1,SESSION_RESEARVED2,MIN_SESSIONID=10};
//如果用户的sessionid为0表示该用户已经删除/不存在，为1表示离线;大于等于MIN_SESSIONID表示在线。
enum{ENCRYPTION_NONE=0,ENCRYPTION_AES128=1,ENCRYPTION_RAS1024=2};
enum{STAT_LIVE_CLOSE=0,STAT_LIVE_OPEN=1};
enum{SPY_NONE_ERR=0,SPY_IDDENTIFY_ERR,SPY_LOGOFF_SUCCEED,SPY_LOGIN_SUCCEED,SPY_TERMINAL_OFFLINE,SPY_TERMINAL_PREEMPT};
enum{DEV_STATE_OFFLINE=0,DEV_STATE_SLEEP,DEV_STATE_WAKEUP,DEV_STATE_ONLINE,DEV_STATE_GOTOSLEEP,DEV_STATE_STARTING,DEV_STATE_CRUISE,DEV_EVENT_ENGINEOFF};
//---------------------------------------------------------------------------
#define SERVER_DYNAMIC_SESSION(msg)      ~((msg)->msgid+(msg)->synid)
#define MC_MSG_SIZE(msg)                  (sizeof(TMcMsg)+(msg)->bodylen+1)
#define MC_PACKET_SIZE(packet)            (sizeof(TMcPacket)+(packet)->msg.bodylen+1)
//#define RESPONSE_APPENDIX(packet)        *((void **)&packet->msg)
//---------------------------------------------------------------------------
#pragma pack (push,1)
//---------------------------------------------------------------------------
typedef struct
{ U32  id,session;
  U32  live_user; //正在请求建立的直播路径 bind_user -> device -> visiter
  TNetAddr loginAddr,spyAddr;//udp address
 
  //以下位域结构必须定义成无符号类型，否则一位的1会被编译器解释成-1。 
  U32 sex_type:2;//0:保密;1:男;2:女
  U32 term_type:2;//0表示device, 1表示user
  U32 term_state:4; //for terminnal 0:离线;1:休眠;2唤醒;3:在线
  U32 encrypt:8;//终端消息的默认加密方式
  U32 group:8;//分设备类型	
  U32 live_state:1;//直播状态；
  U32 msg_push_acceptable:1; //是否接受服务器消息通知推送
  U32 live_push_acceptable:1;//是否接受其他手机的直播推送
  char name[0];
}TTerminal;

typedef struct
{ TTerminal terminal;
  char username[SIZE_MOBILE_PHONE+1];
}TTermUser;

typedef struct
{ TTerminal terminal;
  char sn[SIZE_SN_DEVICE+1];
  U32 boxid;
  U32 onlinetime;//上线的时间
}TTermDevice;

typedef struct
{ TTerminal terminal;
  char sn[SIZE_SN_BOX+1];
}TTermBox;

typedef struct
{ U32 msgid;
  U32 sessionid; //会话ID：登录后服务器将为其分配一个唯一的session的ID。
  U32 synid;     //流水号：按发送顺序从 0 开始循环累加
  U32 bodylen;    //消息体长度
  U8  encrypt;   //消息体加密方式(0：不加密 1：AES)
  U8  body[0];   //消息体内容
}TMcMsg;

typedef struct
{ TTerminal *terminal;
  TNetAddr peerAddr;
  TMcMsg msg;
}TMcPacket;

typedef struct
{ U16 year;
  U8 month,day,hour,minute,second,reserved;
}TMcTime;

typedef struct
{ U32 /*ack_msg,*/retry_counter;
  void *extraData;
  TMcPacket reqPacket;
}TSuspendRequest;

/*
typedef struct
{ U32 ack_msg,retry_counter;
	TTerminal *terminal;
	TMcMsg    *reqMsg;
        //TMcPacket *srcPacket;
	void      *extraData;
}TSuspendRequest;
*/

//---------------------------------------------------------------------------
#pragma pack (pop)  
//---------------------------------------------------------------------------

#endif
