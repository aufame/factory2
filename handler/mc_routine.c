#include "mc_routine.h"

//---------------------------------------------------------------------------
static pthread_t sub_routine_thread=0;

// 定位光标  
#define MOVETO(x,y) printf("\033[%d;%dH", (x), (y))  
  
// 光标复位  
#define RESET_CURSOR() printf("\033[H")  
  
// 左移光标  
#define MOVELEFT(y) printf("\033[%dD", (y))  
 // 上移光标  
#define MOVEUP(x) printf("\033[%dA", (x))  

#define SLEEP_TIME_M                 5   

 

void test_routine(void)
{/* char xml[255],response[255];
  U32 start_time=time(NULL);
 U32 end_time=start_time+3*24*60*60;
 int xmlLen=strcpy(xml,"<xml><action>create</action><device>D6054846343664481243</device><starttime>1470730127</starttime><endtime>1470989327</endtime><session>808909153</session></xml>");
 int ret=hsk_httpPost("http://www.mplanet.cn/wap/trackmap/app.php",xml,xmlLen,response,255,6);
 printf("####### %s  result=%d\r\n",response,ret);
 */
}

extern void monitor_flow(void);

static void *thread_sub_routine_task(void *param)
{ //删除一周前上传的GPS数据以及操作日志
  db_query("delete from mc_gps where addtime<unix_timestamp()-7*24*60*60");
  sleep(5);
  db_query("delete from mc_usrlogs where addtime<unix_timestamp()-7*24*60*60");
  sleep(5);
  db_query("delete from mc_devlogs where addtime<unix_timestamp()-7*24*60*60");
  sleep(5);
  if(ENABLE_FLOW_MONITOR)monitor_flow();
  
  sub_routine_thread=0;//标记任务结束
  return NULL;
} 

static void *thread_routine_task(void *param)
{ U32 runtime_day=0,runtime_hour=0,runtime_minute=0;
  U32 now_hour=tm_getLocalHour(time(NULL));
  test_routine();
  while(1)
  { sleep(SLEEP_TIME_M*60);	
		if((runtime_minute+=SLEEP_TIME_M)>=60)
		{ runtime_minute-=60;
			if(++runtime_hour>=24)
			{ runtime_hour-=24;
				runtime_day++;
			}
			if(++now_hour>=24)now_hour=0;
			else if(now_hour==5 && sub_routine_thread==0)
			{	pthread_create(&sub_routine_thread, NULL,thread_sub_routine_task,NULL);
			}		
		}	
    printf("Running %dday-%dhour-%dmin   \r\n",runtime_day,runtime_hour,runtime_minute); 
    MOVEUP(1);
	}
	return NULL;
} 

void routine_init(void)
{ pthread_t _thread=0;
  pthread_create(&_thread, NULL,thread_routine_task,NULL);
}
//--------------------------------------------------------------------------- 
#if 0
//---------------------------------------------------------------------------
/*
void *test_dispatch2(void *interval)
{ int sInterval=*(int *)interval;
	while(1)
	{ printf("To foud herelng...[%d][%u]\r\n",sInterval,pthread_self());
	
		void *node;
		if((node=TTSK_FindTask(testLinks,0,0,"18913949200",TTSK_LOCK|5)))
		{ printf("Found herelng[%d][%u]!\r\n",sInterval,pthread_self());
			sleep(sInterval);	
			printf("unlock[%d][%u]\r\n",sInterval,pthread_self());
			TTSK_UnlockTask(node);

			
			sleep(2);	
		}else printf("Not found herelng!\r\n");
		
	}
	puts("break");
	return NULL;
} 
*/
//#define downBufferSize 80000
//static char downBuffer[downBufferSize];

static void dtmr_timeout(HAND ttasks,void *taskCode,U32 *taskID,char *taskName,U32 *sUpdateLifeTime)
{ 
  printf("[Timeout:%XH]\r\n",taskID[0]);
 
}
void routine_task(void)
{	
	//int ret=hsk_httpGet("http://www.mplanet.cn/uploadfiles/upgrade/mcufw.3.bin",downBuffer,downBufferSize,30);
	//printf("ret=%d\r\n",ret);
	HAND testLinks;

 char strTime[32],strWarning[160];
 int interval1=5,interval2=3;
 pthread_t _thread1=0,_thread2=0;
 testLinks=dtmr_create(0,60,dtmr_timeout);
 dtmr_add(testLinks,1,2,"herelong",NULL,0,1);
 dtmr_add(testLinks,0,0,"18913949200",NULL,0,1);
   
 //pthread_create(&_thread1, NULL,test_dispatch1,(void *)&interval1);
 //pthread_create(&_thread2, NULL,test_dispatch2,(void *)&interval1);
while(1)
{  sleep(1);
	//printf("\r\n###############test over!\r\n");
} 
	//exit(0);

}
//---------------------------------------------------------------------------
#endif
