#include "mc_routine.h"
//---------------------------------------------------------------------------
extern void msg_init(void);
extern void db_init(void);
extern void net_init(void);
extern void terminal_init(void);
extern void upload_init(void);
extern void mcufw_init(void);
extern void routine_init(void);
extern void dblog_init(void);
//---------------------------------------------------------------------------
void mc_init(void)
{ srand((int)time(NULL));

  db_init();//database initialize	

	dblog_init();

	msg_init(); //消息队列初始化

	net_init();//initialize tcp and udp socket  
	
	terminal_init();//load and initialize devices and users;
	
	upload_init();
	 
	mcufw_init();

	routine_init();
}
