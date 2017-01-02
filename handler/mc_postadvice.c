#include "mc_routine.h"
//---------------------------------------------------------------------------
#define MIN_ADVICE_POST_INTERVAL_S        15
//---------------------------------------------------------------------------
void Handle_MSG_USR_POST_ADVICE(TMcPacket *packet)
{  
	 MYSQL *conn=NULL;
	// U32 now_time;
	 TMSG_USR_POST_ADVICE *req=(TMSG_USR_POST_ADVICE *)packet->msg.body;
	 U8 ret_error=-1; //0:成功;1:类型错误;2:电话号码格式错误;3:内容长度错误;4:提交过于频繁
	 if(req->type!=1 && req->type!=2)ret_error=1;	
	 else if(!MobilePhone_check(req->mobile))ret_error=2;	
	 else
	 { int adviceSize=str_lenOfUTF8(req->advice);
	 	 if(adviceSize<1 || adviceSize>512) ret_error=3;
	 	 else 
	 	 { if(dtmr_find(commDataLinks,MSG_USR_POST_ADVICE,MSG_USR_POST_ADVICE,req->mobile,0) || dtmr_find2(commDataLinks,MSG_USR_POST_ADVICE,MSG_USR_POST_ADVICE,&packet->peerAddr,sizeof(TNetAddr),0,0) ) ret_error=4;
	 	 	 else conn=db_conn();
	 	 }
	 }
 	 if(conn)
	 {  char insertSQL[256];
 	 	  U32 sqlLen,adviceID=0;
      db_lock(TRUE);
 	 	  MYSQL_STMT *stmt=mysql_stmt_init(conn);  
 	 	  MYSQL_RES *res=db_query("select min(id) from `mc_advices` where type=0");
 	 	  if(res)
 	 	  {	MYSQL_ROW row=mysql_fetch_row(res);
        //查询统计结构可能返回NULL指针(row!=NULL,但row[0]==NULL)，而atoi(NULL)会使程序崩溃，所以这里要mark下。
        if(row && row[0])adviceID=atoi(row[0]);
        mysql_free_result(res);
      }  	
      if(adviceID>0) sqlLen=sprintf(insertSQL,"update `mc_advices` set type=%d,mobile=?,userid=%u,advice=?,ip=%u,addtime=unix_timestamp() where id=%u",req->type,(packet->terminal)?packet->terminal->id:0,packet->peerAddr.ip,adviceID);
      else sqlLen=sprintf(insertSQL,"insert into `mc_advices`(type,mobile,userid,advice,ip,addtime) values(%d,?,%u,?,%u,unix_timestamp())",req->type,(packet->terminal)?packet->terminal->id:0,packet->peerAddr.ip);

      if(mysql_stmt_prepare(stmt,insertSQL,sqlLen)==0)
      { MYSQL_BIND  bind[2]; 
     	  memset(bind,0,sizeof(bind));//把is_null、length等字段默认值设置为NULL等默认值，否则执行会报错  
        bind[0].buffer_type= MYSQL_TYPE_STRING;    
        bind[0].buffer= req->mobile;    
        bind[0].buffer_length=strlen(req->mobile); //如果设定了buffer_length，则可以不试用length
        bind[1].buffer_type= MYSQL_TYPE_VAR_STRING;    
        bind[1].buffer= req->advice;    
        bind[1].buffer_length=strlen(req->advice); //如果设定了buffer_length，则可以不试用length
     	  if (mysql_stmt_bind_param(stmt, bind)==0)    
        { if (mysql_stmt_execute(stmt)==0)    
          { dtmr_add(commDataLinks,MSG_USR_POST_ADVICE,MSG_USR_POST_ADVICE,req->mobile,&packet->peerAddr,sizeof(TNetAddr),MIN_ADVICE_POST_INTERVAL_S);
          	ret_error=0;  
          }       
        }
      }
      mysql_stmt_close(stmt);      
      db_lock(FALSE);
	 }
	 msg_ack(MSG_STA_GENERAL,ret_error,packet);
}
