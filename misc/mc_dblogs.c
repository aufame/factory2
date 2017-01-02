#include "mc_routine.h"
#define  DBLOG_QUEUE_SIZE        8*1024*1024
#define  DBLOG_RECORD_MAXLEN     128
//---------------------------------------------------------------------------
#pragma pack (push,1)
//---------------------------------------------------------------------------
typedef struct
{ U32 termid;
  U8  termtype,bSendOrRecv;
  U8  data[0];
}TMcDBLog;
//---------------------------------------------------------------------------
#pragma pack (pop)  
//---------------------------------------------------------------------------
void DBLog_AppendData(void *data,int datalen,TTerminal *terminal)
{ if(data && datalen && terminal)
	{ U8 record_data[DBLOG_RECORD_MAXLEN+sizeof(TMcDBLog)];
		TMcDBLog *dblog=(TMcDBLog *)record_data;
		dblog->termid=terminal->id;
		dblog->termtype=terminal->term_type;
		if(datalen>DBLOG_RECORD_MAXLEN)datalen=DBLOG_RECORD_MAXLEN;
		memcpy(dblog->data,data,datalen);
		mb_post(dblog,datalen+sizeof(TMcDBLog));	
	} 
}

void DBLog_AppendMsg(TMcMsg *msg,TTerminal *terminal,BOOL bSendOrRecv)
{ if(msg && terminal)
	{ if( (msg->msgid==MSG_TSR_HEARTBEAT)||(msg->msgid==MSG_DSR_UPLOAD_GPS)||(msg->msgid==MSG_SDA_UPLOAD_GPS)||(msg->msgid==MSG_STA_GENERAL && ((TMSG_STA_GENERAL *)msg->body)->ack_msgid==MSG_TSR_HEARTBEAT))return; 
		U8 record_data[DBLOG_RECORD_MAXLEN+sizeof(TMcDBLog)];
		TMcDBLog *dblog=(TMcDBLog *)record_data;
		int datalen=MC_MSG_SIZE(msg);
		dblog->termid=terminal->id;
		dblog->termtype=terminal->term_type;
		dblog->bSendOrRecv=bSendOrRecv&0x1;
		if(datalen>DBLOG_RECORD_MAXLEN)datalen=DBLOG_RECORD_MAXLEN;
		memcpy(dblog->data,msg,datalen);
		mb_post(dblog,datalen+sizeof(TMcDBLog));	
	}
}

void *dblog_process(void *param)
{ U8 record_data[DBLOG_RECORD_MAXLEN+sizeof(TMcDBLog)];
	char *logsTableNames[3]={"mc_usrlogs","mc_devlogs","mc_boxlogs"};
	while(1)
	{ int datalen=mb_receive(record_data,DBLOG_RECORD_MAXLEN);
		if(datalen>0)
		{ TMcDBLog *dblog=(TMcDBLog *)record_data;
			#if 1
			 db_lock(TRUE);
       MYSQL *conn=db_conn();
       MYSQL_STMT *stmt=mysql_stmt_init(conn);  
       char InsertSQL[128];
       int sqlLen=sprintf(InsertSQL,"insert into `%s`(termid,dir,data,addtime) values(%u,%d,?,unix_timestamp())",logsTableNames[dblog->termtype],dblog->termid,dblog->bSendOrRecv);
       if(mysql_stmt_prepare(stmt,InsertSQL,sqlLen)==0)
       { MYSQL_BIND binds[1];
  	     memset(binds,0,sizeof(binds));//把is_null、length等字段默认值设置为NULL等默认值，否则执行会报错  
  	     binds[0].buffer=dblog->data;
  	     binds[0].buffer_type=MYSQL_TYPE_BLOB;
  	     binds[0].buffer_length=datalen;
  	     if(mysql_stmt_bind_param(stmt,binds)==0)
  	     { mysql_stmt_execute(stmt);
  	     }
       }
       mysql_stmt_close(stmt);
       db_lock(FALSE); 
			#else
			char record_hexbuf[DBLOG_RECORD_MAXLEN*3+4]; 
			int hexlen=str_dataToHex(dblog->data,datalen-sizeof(TMcDBLog),record_hexbuf,DBLOG_RECORD_MAXLEN*3,' ');
			if(datalen==DBLOG_RECORD_MAXLEN)
			{ record_hexbuf[hexlen++]='.'; 
    	  record_hexbuf[hexlen++]='.';
    	  record_hexbuf[hexlen++]='.';
    	  record_hexbuf[hexlen]='\0';
			}
			if(!db_queryf("update `%s` set data='%s',dir=%d,addtime=unix_timestamp() where termid=%d and addtime<unix_timestamp()-2*24*60*60 order by addtime desc limit 1",logsTableNames[dblog->termtype],record_hexbuf,dblog->bSendOrRecv,dblog->termid))
	  	db_queryf("insert into `%s` set data='%s',termid=%d,dir=%d,addtime=unix_timestamp()",logsTableNames[dblog->termtype],record_hexbuf,dblog->termid,dblog->bSendOrRecv);
	  	#endif
		  usleep(1);
		}
		else sleep(1);	
	}
	return NULL;
} 

void dblog_init(void)
{ pthread_t _thread=0;
  mb_create(DBLOG_QUEUE_SIZE);
  pthread_create(&_thread, NULL,dblog_process,NULL);
}
