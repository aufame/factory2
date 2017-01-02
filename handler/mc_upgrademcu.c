#include "mc_routine.h"
//---------------------------------------------------------------------------
typedef struct t_mcufwInfo
{ struct t_mcufwInfo *next,*prev;
        U32 type;
	U32 groupid;
	U32 version;
	U32 size;
	U8 *data;
}TMcufwInfo;
//---------------------------------------------------------------------------
static sem_t  mcufw_rw_mutex;
static TMcufwInfo _mcufwList;
extern U32  Mcufw_Load(U32 groupid,void *dataBuffer,int bufszie);
//---------------------------------------------------------------------------
void mcufw_init(void)
{ memset(&_mcufwList,0,sizeof(TMcufwInfo));
	BINODE_ISOLATE(&_mcufwList,prev,next);
  sem_init(&mcufw_rw_mutex, 0, 1);
}

void Handle_MSG_DSR_MCU_CHECKVERSION(TMcPacket *packet)
{  U32 fw_version_local=((TMSG_DSR_MCU_CHECKVERSION *)packet->msg.body)->local_version;
   U32 term_type=packet->terminal->term_type;
   TMcMsg *msg=msg_alloc(MSG_SDA_MCU_CHECKVERSION,sizeof(TMSG_SDA_MCU_CHECKVERSION));
   TMSG_SDA_MCU_CHECKVERSION *ackBody=(TMSG_SDA_MCU_CHECKVERSION *)msg->body;
   ackBody->error=1;
   MYSQL_RES *res;
   if(term_type==TT_BOX)res=db_queryf("select `mc_boxgroup`.id,`mc_boxgroup`.mcufw_ver,`mc_boxgroup`.mcufw_url from  `mc_boxgroup` inner join `mc_boxes` on `mc_boxes`.groupid=`mc_boxgroup`.id where `mc_boxes`.id=%u",packet->terminal->id);
   else res=db_queryf("select `mc_devgroup`.id,`mc_devgroup`.mcufw_ver,`mc_devgroup`.mcufw_url from `mc_devgroup` inner join `mc_devices`  on `mc_devices`.groupid=`mc_devgroup`.id where `mc_devices`.id=%u",packet->terminal->id);
  if(res)
  { MYSQL_ROW row=mysql_fetch_row(res);
    if(row && row[0])
    { U32 fw_version_latest=atoi(row[1]);
      U32 fw_groupid=atoi(row[0]);
      TMcufwInfo *header=&_mcufwList,*node;
      sem_wait(&mcufw_rw_mutex);
      for(node=header->next;node!=header;node=node->next)
      { if(node->groupid==fw_groupid && node->type==term_type)break;
      }
      if(node==header || fw_version_latest!=node->version)
      { char *p_url=row[2];
        if(p_url && p_url[0]=='/')
        { char url_buf[MAXLEN_URL+1];
          if(sprintf(url_buf,"http://"WEB_SERVER_HOST"%s",p_url)>MAXLEN_URL)abort();
          p_url=url_buf;
          if(node==header)
          { node=(TMcufwInfo *)malloc(sizeof(TMcufwInfo));
            node->data=NULL;
            node->type=term_type;
            node->groupid=fw_groupid;
            BINODE_INSERT(node,header,next,prev);
          }
          else if(node!=header->next)
          { // 移动头部
            BINODE_REMOVE(node,prev,next);
  	    BINODE_INSERT(node,header,next,prev);
  	  }
  	  node->version=fw_version_latest; 
          if(node->data)free(node->data);
          node->size=hsk_httpGet(p_url,NULL,0,5);
          if((S32)node->size<0)
          { node->size=0;
     	    node->data=NULL;
  	  }
  	  else
  	  { node->data=(U8 *)malloc(node->size);	
  	  }	
  	  if(node->data && hsk_httpGet(p_url,(char *)node->data,node->size,10)!=node->size)
  	  { free(node->data);
  	    node->data=NULL;
  	    node->version=0;
   	  }
        }

      }  
      if(node->version>fw_version_local && node->data)
      { ackBody->error=0; //可升级
        ackBody->fw_size=node->size;
        ackBody->fw_version=node->version;
      }
      packet->terminal->group=fw_groupid;  		
      sem_post(&mcufw_rw_mutex);	 
    }
    mysql_free_result(res);  
  }    	
  ackBody->ack_synid=packet->msg.synid;
  msg_send(msg,packet,NULL);
}

void Handle_MSG_DSR_MCU_UPGRADE(TMcPacket *packet){
  TMSG_DSR_MCU_UPGRADE *req=(TMSG_DSR_MCU_UPGRADE *)packet->msg.body;
  U32 fw_packet_size=req->fw_packet_size;	
  U32 fw_groupid=packet->terminal->group;
  U32 term_type=packet->terminal->term_type;
  U8 ret_error=1;
  TMcufwInfo *node;
  sem_wait(&mcufw_rw_mutex);   
  if(fw_packet_size>0){
    TMcufwInfo *header=&_mcufwList;
    for(node=header->next;node!=header;node=node->next){
      if(node->groupid==fw_groupid && node->type==term_type){
        if(node->data && node->version==req->fw_version && req->fw_offset<node->size){
          if(req->fw_offset+fw_packet_size>node->size)fw_packet_size=node->size-req->fw_offset;
	  ret_error=0;
	}
	break;
      }	
    }
    if(ret_error)fw_packet_size=0;
  }
  TMcMsg *msg=msg_alloc(MSG_SDA_MCU_UPGRADE,sizeof(TMSG_SDA_MCU_UPGRADE)+fw_packet_size);
  TMSG_SDA_MCU_UPGRADE *ackBody=(TMSG_SDA_MCU_UPGRADE *)msg->body;
  if(fw_packet_size) memcpy(ackBody->packet_data,node->data+req->fw_offset,fw_packet_size);
  ackBody->error=ret_error;
  ackBody->packet_size=fw_packet_size;
  ackBody->ack_synid=packet->msg.synid;
  sem_post(&mcufw_rw_mutex);
  msg_send(msg,packet,NULL);	
}
