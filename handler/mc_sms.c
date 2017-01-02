#include "mc_routine.h"
//确保本文件是utf-8编码存储

//漫道科技短信接口(new)
static char params_pattern[]="account="SMS_ACCOUNT"&pswd="SMS_PASSWORD"&mobile=%s&msg=%s&needstatus=false";
int sms_check_error(char *ret){if(strlen(ret)==16 && ret[15]=='0') return 0;else return -1;}

#define SMS_MONITOR_SPAN_S       1*60*60   //1小时   
#define SMS_MAX_PER_SPAN         20        //SMS_MONITOR_SPAN_S时间段内最多能发的短信数量
#define SMS_INDEX_ID             MSG_USR_VERIFYCODE
#define SMS_BUFSIZE              320
static char vcode_pattern[]="您收到一条来自喵星球的邀请消息，验证码：%s，请尽快验证登录，开启喵星球的神奇之旅吧～";

typedef struct
{	TNetAddr srcAddr;
	U32  lastSendTick;
	U32  sendCount;
	char code[SIZE_VERIFY_CODE+1];
}TSMSRecord;         

static void vcode_new(char *code)
{ int i;
  for(i=0;i<SIZE_VERIFY_CODE;i++)
  { unsigned char d=(unsigned int)rand()%10;
    code[i]='0'+d;
  }
  code[6]='\0';
}

static BOOL do_send_sms(char *phone,char *content)
{  char smsbuf[SMS_BUFSIZE+1];
   if(ENABLE_SMS_MODULE)
   { sprintf(smsbuf,params_pattern,phone,content);
     // printf("send[%d]:",strlen(smsbuf));puts(smsbuf);
     if(hsk_httpPost(SMS_SERVER,smsbuf,strlen(smsbuf),smsbuf,SMS_BUFSIZE,6)>0)
     { //printf("recv:");puts(smsbuf);
       if(sms_check_error(smsbuf)==0)
       { return TRUE;
       }	
     }
   }
   else 
   { return TRUE;
   }
   return FALSE;
}

int sms_send(char *phones,char *content)
{	if(content && content[0] && phones && phones[0])
	{ TSMSRecord *node=dtmr_add(commDataLinks,SMS_INDEX_ID,SMS_INDEX_ID,phones,NULL,sizeof(TSMSRecord),SMS_MONITOR_SPAN_S|DTMR_NOVERRIDE|DTMR_LOCK);
		if(node)node->sendCount=0;	 
		else if((node=dtmr_find(commDataLinks,SMS_INDEX_ID,SMS_INDEX_ID,phones,DTMR_LOCK))) 
		{ if(time(NULL)-node->lastSendTick<MIN_SMS_INTERVAL_S)
			{ dtmr_unlock(node,0);
				return ERR_OVERFREQUENCY;
		  }	
			else if(node->sendCount>=SMS_MAX_PER_SPAN)
			{	dtmr_unlock(node,0);
				return ERR_OVERRUN;
		  }	
		}
		else return ERR_UNKNOWN;	
		node->srcAddr.ip=0;
		node->code[0]='\0';
		node->lastSendTick=time(NULL);	
		node->sendCount++;	 
		dtmr_unlock(node,0);
		if(do_send_sms(phones,content)) return ERR_NONE;
	}
	return ERR_UNKNOWN;
}

static int do_send_vcode(char *phone,TNetAddr *srcAddr)
{	U32 now_tick_s=(U32)time(NULL);
	TSMSRecord *node=(TSMSRecord *)dtmr_find2(commDataLinks,SMS_INDEX_ID,SMS_INDEX_ID,srcAddr,sizeof(TNetAddr),T_NODE_OFFSET(TSMSRecord,srcAddr),DTMR_LOCK); 
  if(node)
  { if(now_tick_s-node->lastSendTick<MIN_SMS_INTERVAL_S)
    { dtmr_unlock(node,0);
  	  return ERR_OVERFREQUENCY;
    }
    else if(node->sendCount>=SMS_MAX_PER_SPAN)
  	{ dtmr_unlock(node,0);
		  return ERR_OVERRUN;
		}		
    else
    { char *phone2=dtmr_getName(node);
    	if(strcmp(phone2,phone)==0)goto label_sms_send;
    	else
    	{	node->sendCount++;
    	  node->lastSendTick=now_tick_s;	
        dtmr_unlock(node,0);
      }
    }  	
  }
  if((node=(TSMSRecord *)dtmr_add(commDataLinks,SMS_INDEX_ID,SMS_INDEX_ID,phone,NULL,sizeof(TSMSRecord),SMS_MONITOR_SPAN_S|DTMR_NOVERRIDE|DTMR_LOCK)))
  { node->code[0]='\0';
    node->sendCount=0;	
    goto label_sms_send;
  }	
  else if((node=(TSMSRecord *)dtmr_find(commDataLinks,SMS_INDEX_ID,SMS_INDEX_ID,phone,DTMR_LOCK)))
  {  if(now_tick_s-node->lastSendTick<MIN_SMS_INTERVAL_S)
   	 { dtmr_unlock(node,0);
   	 	 return ERR_OVERFREQUENCY;
     }
     else if(node->sendCount>=SMS_MAX_PER_SPAN)
		 {	dtmr_unlock(node,0);
				return ERR_OVERRUN;
		 }		
     else
     { char smsbuf[SMS_BUFSIZE+1];
     	 label_sms_send:	
     	 if(!node->code[0])vcode_new(node->code);
    	 node->sendCount++;	
       node->srcAddr=*srcAddr;
       node->lastSendTick=now_tick_s;	
       sprintf(smsbuf,vcode_pattern,node->code);
		   dtmr_unlock(node,0);	
     	 if(do_send_sms(phone,smsbuf))return ERR_NONE;
     }
  }	
  return ERR_UNKNOWN;
}
 
int vcode_apply(char *phone,char *code)
{ //验证手机验证码只能使用一次，在验证验正确后立即释放验证码。
	int ret_error=ERR_UNKNOWN;
	if(phone && code)
	{ TSMSRecord *node=(TSMSRecord *)dtmr_find(commDataLinks,SMS_INDEX_ID,SMS_INDEX_ID,phone,DTMR_LOCK);
	  if(node &&  time(NULL)-node->lastSendTick<VERIFYCODE_LIFETIME_S)
	  { if(strcmp(node->code,code)==0)
	  	{ ret_error=ERR_NONE;
	  		node->code[0]='\0';//验证码接受成功后马上释放(不能删除，只改掉原来的验证码，用于记录上一次发送时间就行)
	    }else 	ret_error=ERR_WRONG; //验证码错误
	  }else ret_error=ERR_TIMEOUT; //验证码不存在（可能已超时） 
	  if(node)dtmr_unlock(node,0);
	} 
	return ret_error;
} 

void Handle_MSG_USR_VERIFYCODE(TMcPacket *packet)
{  //一个客户端（IP:port)在一分钟内只允许申请发送一次验证码（不管发送个哪个手机）
	 char *phone=((TMSG_USR_VERIFYCODE *)packet->msg.body)->phone;
   int ret_error=(MobilePhone_check(phone))?do_send_vcode(phone,&packet->peerAddr):ERR_UNKNOWN;
   msg_ack(MSG_SUA_VERIFYCODE,ret_error,packet);
}

