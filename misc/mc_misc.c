#include "mc_routine.h"
//---------------------------------------------------------------------------
BOOL MobilePhone_check(char *number)
{ if(number)
  { int i;
    for(i=0;i<SIZE_MOBILE_PHONE;i++)
    { if(number[i]<'0' || number[i]>'9')return FALSE;
    }
    if(i==SIZE_MOBILE_PHONE && number[i]=='\0')return TRUE;
  }
  return FALSE;
}

BOOL Password_check(char *number)
{ if(number)
  { int i;
    for(i=0;i<=MAXLEN_PASSWORD;i++)
    { if(number[i]==' ' || number[i]=='\'' || number[i]=='"' || number[i]=='<' || number[i]=='>')return FALSE;
      else if(number[i]=='\0')break;
    }
    if(i>0 && number[i]=='\0')return TRUE;
  }
  return FALSE;
}

int app_exepath(char *pathbuf,int bufsize)
{ int nLen=readlink("/proc/self/exe",pathbuf,bufsize);
	if(nLen>0)
	{ char *q=NULL,*p=pathbuf;
		while(*p)
		{ if(*p=='/')q=p;
			p++;
		}
		if(q)
		{	*++q='\0';
			return (int)(q-pathbuf); 
		}
	}	
	return 0;
}
  
//---------------------------------------------------------------------------
//后期调试时，日志打印可以转向文件
void Log_AppendData(void *data,int datalen,TNetAddr *peerAddr,BOOL bSendOrRecv){
  if(datalen>0){
    char tempbuf[512];
    if(peerAddr)printf("%s %dBytes %s %s:%d",(bSendOrRecv)?"[SEND":"\r\n[RECV",datalen,(bSendOrRecv)?"to":"from",inet_ntoa(*((struct in_addr *)&peerAddr->ip)),peerAddr->port);
    else if(bSendOrRecv) printf("[SEND to self]");
    datalen=str_dataToHex(data,(datalen>512/3)?512/3:datalen,tempbuf,512,' ');
    tempbuf[datalen]='\0';
    puts(tempbuf);
  } 	
}

void Log_AppendText(const char *format, ...)
{ const int log_buf_size=512;
	char temp_log_buf[log_buf_size+1];
	va_list arg_ptr;
  va_start(arg_ptr, format);
  if(vsprintf(temp_log_buf, format, arg_ptr)>log_buf_size)
  { puts("[ERROR]#################Log_AppendText###############out of range!");
  	puts(temp_log_buf);
  	exit(0);	
  }
  va_end(arg_ptr);
  puts(temp_log_buf);
}
