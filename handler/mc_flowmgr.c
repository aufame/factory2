#include "mc_routine.h"
#define FLOWPACKAGE_UPTATE_INTERVAL_S  60
#define QUERY_BUFFER_SIZE  4096
#define QUERY_FLOW_SERVER  "http://"WEB_SERVER_HOST"/admeow/mc_flowpackage.php"
//---------------------------------------------------------------------------
static int stat_flowState(TFlowPackageItem *packetItems,int packetCount,U32 *totalUsed,U32 *totalRemains)
{ int i,expiredCount=0;
  U32 max_end_time=0;
  U32 now_time=(U32)time(NULL);
  U64 total_flow=0,total_used=0;
  for(i=0;i<packetCount;i++)
  { if(packetItems[i].end_time>now_time)
    { total_flow+=packetItems[i].total_flow;
      total_used+=packetItems[i].used_flow;
      if(packetItems[i].end_time>max_end_time)max_end_time=packetItems[i].end_time;
    }
    else expiredCount++;
  }
  if(totalUsed)*totalUsed=total_used;
  if(totalRemains)*totalRemains=total_flow-total_used;
  if(total_used==total_flow)
  { return -2;//流量耗尽
  }
  else if(total_used>total_flow*0.95)	 
  { return -1;//流量耗尽95%以上。
  }	
  else if(max_end_time)
  { int days_due=(max_end_time-now_time)/60/60/24;
    if(days_due<=5)
    { if(days_due==0)days_due=1;
      return days_due;
    }	
  }	
  return 0;
}

static int http_request_flowpackage(int simgroup,char *accessno,char *queryBuffer,int bufLen)
{ char query_params[50];
  int packet_count=-1;
  int query_params_length=sprintf(query_params,"simgroup=%d&accessno=%s",simgroup,accessno);
  if(hsk_httpPost(QUERY_FLOW_SERVER,query_params,query_params_length,queryBuffer,bufLen,9)>0)
  { TFlowPackageItem *packetItems=(TFlowPackageItem *)queryBuffer;
    char *p,*segment=queryBuffer,flow_unit;
    int len;
    packet_count=0;
    while(segment)
    { segment=str_xmlSeek(segment,"CumulRspList",&len);
      if(!segment)continue;
      
      if(!(p=str_xmlSeek(segment,"OFFER_NAME",&len)) )continue;
      else if(len>=MAXLEN_PACKAGENAME)len=MAXLEN_PACKAGENAME-1;
      memcpy(packetItems->name,p,len);
      packetItems->name[len]='\0';
      if(strstr(packetItems->name,"短信"))continue;
      
      if((p=str_xmlSeek(segment,"START_TIME",&len)) && len==14)
      {
       		packetItems->start_time=str_toTime(p,"%Y%m%d%H%M%S"); 
       		//printf("%s,%u\r\n",timebuf,packetItems->start_time);
       		if(!packetItems->start_time)continue;
     }else continue;
       	  
      if((p=str_xmlSeek(segment,"END_TIME",&len))&& len==14)
       	{	packetItems->end_time=str_toTime(p,"%Y%m%d%H%M%S");
       		//printf("%s,%u\r\n",timebuf,packetItems->end_time);
       		if(!packetItems->end_time)continue;
       	}else continue;
       			    
      p=str_xmlSeek(segment,"UNIT_NAME",&len);
      if(p && (p[0]=='M' || p[0]=='K'))
      { flow_unit=p[0];
      	p=str_xmlSeek(segment,"CUMULATION_TOTAL",&len);
      	if(p)
       	{ packetItems->total_flow=atoi(p);
       	  p=str_xmlSeek(segment,"CUMULATION_ALREADY",&len);
       	  if(p)
       	  { packetItems->used_flow=atoi(p);
       	    if(flow_unit=='M')
       	    { packetItems->used_flow*=1024;
              packetItems->total_flow*=1024;
       	    }
       	    packet_count++;
       	    packetItems++;	
       	  } 
       	}	
      }	
     
      
    }//end of while     
  }
  return packet_count;
}
//---------------------------------------------------------------------------
void Handle_MSG_USR_QUERY_FLOWPACKAGE(TMcPacket *packet)
{ char query_buffer[QUERY_BUFFER_SIZE+1],accessno[SIZE_ACCESSNO+1];
  char *devicesn=((TMSG_USR_QUERY_FLOWPACKAGE *)packet->msg.body)->sn;
  int  packet_count=0,deviceID=0;
  TMSG_SUA_QUERY_FLOWPACKAGE *lastQuery=NULL;
  U8 ret_error=-1;
  accessno[0]='\0';
  if(devicesn[0] && db_checkSQL(devicesn))
  { MYSQL_RES *res=db_queryf("select mc_devices.id,mc_simcard.accessno,mc_simcard.simgroup from mc_devices inner join mc_simcard on mc_devices.imsi=mc_simcard.imsi where mc_devices.sn='%s'",devicesn);
    if(res)
    { MYSQL_ROW row=mysql_fetch_row(res);
      if(row)
      { deviceID=atoi(row[0]);
   	lastQuery=dtmr_find(commDataLinks,deviceID,MSG_SUA_QUERY_FLOWPACKAGE,NULL,0);
	if(lastQuery)
	{ packet_count=lastQuery->number;
	  ret_error=0;
	}
	else 	
	{ strncpy(accessno,row[1],SIZE_ACCESSNO);
	  accessno[SIZE_ACCESSNO]='\0';
	  packet_count=http_request_flowpackage(atoi(row[2]),accessno,query_buffer,QUERY_BUFFER_SIZE);
	  if(packet_count>=0)ret_error=0;
	  else packet_count=0;	
	}  
      }
      else ret_error=1;//SIM卡号不存在
      mysql_free_result(res);
    }  
  }
  int msgBodyLen=sizeof(TMSG_SUA_QUERY_FLOWPACKAGE)+packet_count*sizeof(TFlowPackageItem);
  TMcMsg *ackmsg=msg_alloc(MSG_SUA_QUERY_FLOWPACKAGE,msgBodyLen);
  TMSG_SUA_QUERY_FLOWPACKAGE *ackbody=(TMSG_SUA_QUERY_FLOWPACKAGE *)ackmsg->body;	
  if(lastQuery)
  { memcpy(ackbody,lastQuery,msgBodyLen);
  }
  else if(!ret_error)
  { int i;
    ackbody->number=packet_count;
    for(i=0;i<packet_count;i++)
    { TFlowPackageItem *item=(TFlowPackageItem *)query_buffer + i;
      MYSQL_RES *res=db_queryf("select name from `mc_flowpackage` where alias='%s'",item->name);
      if(res)
      { MYSQL_ROW row=mysql_fetch_row(res);
        if(row && row[0]) strncpy(item->name,row[0],MAXLEN_PACKAGENAME);
	mysql_free_result(res);
      }
    }
    memcpy(ackbody->items,query_buffer,packet_count*sizeof(TFlowPackageItem));	
    dtmr_add(commDataLinks,deviceID,MSG_SUA_QUERY_FLOWPACKAGE,NULL,ackbody,msgBodyLen,FLOWPACKAGE_UPTATE_INTERVAL_S);
  }
  else
  { ackbody->number=0;
  }
  ackbody->error=ret_error;
  ackbody->ack_synid=packet->msg.synid;
  msg_send(ackmsg,packet,NULL); 
}

void monitor_flow(void)
{ char query_buffer[QUERY_BUFFER_SIZE+1];
  const int MAX_PER_PAGE=50;
  U32 start_time=time(NULL);
  int page=0;
  MYSQL_RES *res;
  printf("####query flow starting...!\r\n");
  while((res=db_queryf("select mc_devices.id,mc_devices.username,mc_devices.groupid,mc_simcard.id,mc_simcard.accessno,mc_simcard.flowstate,mc_simcard.simgroup from mc_devices inner join mc_simcard on mc_devices.imsi=mc_simcard.imsi where mc_devices.session>0 and mc_devices.username is not null limit %d,%d",page*MAX_PER_PAGE,MAX_PER_PAGE)))
  { MYSQL_ROW row;
    int page_row_count=mysql_num_rows(res);
    while((row=mysql_fetch_row(res)))
    { char *accessno=row[4];
      if(accessno && accessno[0] && MobilePhone_check(row[1]))
      { //printf("####query flow:%s:%s\r\n",row[1],row[4]);
	int packet_count=http_request_flowpackage(atoi(row[6]),accessno,query_buffer,QUERY_BUFFER_SIZE);
	if(packet_count>0)
	{ U32 total_used=0,total_remains=0;
	  int flowstate_new=stat_flowState((TFlowPackageItem *)query_buffer,packet_count,&total_used,&total_remains);
	  //printf("####query flow result==>%d\r\n",flowstate_new);
	  int flowstate_old=atoi(row[5]);
	  if(flowstate_new!=flowstate_old)
	  { U32 devID=atoi(row[0]);
            U32 simcard=atoi(row[3]);
            if(db_queryf("update `mc_simcard` set flowstate=%d where id=%u and flowstate=%d",flowstate_new,simcard,flowstate_old))
	    { if(flowstate_new)
	      { char strWarning[256];
                int dev_group=atoi(row[2]); 
                char *devTitle=(dev_group==ZSWL_DEV_GROUP1 ||dev_group==ZSWL_DEV_GROUP2)?"设备":"小瞳";
                printf("####query flow send notify to msgbox:%s\r\n",row[1]);
		if(flowstate_new==-2){
	          sprintf(strWarning,"%s温馨提醒：您的流量套餐已用完，为保证您的正常使用，请登录APP通过“流量管理”进行充值",devTitle);
                  push_device_msg(devID,WARNINGMSG_FLOWDEPLETE,strWarning);
                }
		else if(flowstate_new==-1){
                  //int curMonth,curDay;
		  time_t timep=time(NULL);
                  struct tm *pToday=gmtime(&timep); /*转换为struct tm结构的UTC时间*/
	          sprintf(strWarning,"%s温馨提醒：截至%d月%d日，您的流量套餐已使用%uM，剩余流量%uM，为保证您的正常使用，请及时登录APP通过“流量管理”进行续费充值",devTitle,pToday->tm_mon+1,pToday->tm_mday,total_used,total_remains);
		  push_device_msg(devID,WARNINGMSG_LOWFLOW,strWarning);		
		}	
		else{
	          sprintf(strWarning,"%s温馨提醒：您的流量套餐即将到期，为保证您的正常使用，请及时登录APP通过“流量管理”进行续费充值",devTitle);
                  push_device_msg(devID,WARNINGMSG_FLOWTOEXPIRE,strWarning);
                }
              }
            }	
          }	
        }
        sleep(2);	
      }
    }	
    mysql_free_result(res);
    if(page_row_count)page++;
    else break;
  }
  printf("####query flow finished(consumed %d minutes)\r\n\r\n",((U32)time(NULL)-start_time)/60);
} 

