//
//  hybServKit.h
//  
//  This file is in the public domain.
//  Originally created by jojo.luo in Q3 2011.
//
//
//---------------------------------------------------------------------------
#ifndef HYBRID_SERVER_KIT_H
#define HYBRID_SERVER_KIT_H
//---------------------------------------------------------------------------
typedef struct{void *owner;TNetAddr addr;char data[0];}THskPacket;
#define BINODE_INSERT(node,linklist,p_prev,p_next)  {(node)->p_prev=(linklist)->p_prev;(node)->p_prev->p_next=node;(node)->p_next=linklist;(linklist)->p_prev=node;}
#define BINODE_ISOLATE(node,p_prev,p_next) {(node)->p_next=node;(node)->p_prev=node;}
#define BINODE_REMOVE(node,p_prev,p_next) {(node)->p_next->p_prev=(node)->p_prev;(node)->p_prev->p_next=(node)->p_next;}
//---------------------------------------------------------------------------
int    hsk_init(int localUdpPort,int localTcpPort,int inQueueSize,int maxTcpPacketSize);
int    hsk_getUdpSocket(void);
int    hsk_getTcpSocket(void);
int    hsk_readData(void *recvBuf, int bufSize,TNetAddr *peerAddr);
void   hsk_sendData(void *data,int datalen,TNetAddr *peerAddr);
void   hsk_releasePacket(THskPacket *packet);
THskPacket *hsk_assemble(TNetAddr *peerAddr,void *sliceData,int sliceLen,int predictPacketSize);
int    hsk_httpPost(char *URL,void *formData,int formSize,char *responseBuffer,int buffersize,int sTimeout);
int    hsk_httpGet(char *URL,char *responseBuffer,int buffersize,int sTimeout);
char  *str_xmlSeek(char *xmlbuf,char *key,int *len);
int    str_lenOfUTF8(char *str);
int    str_fromTime(char *strTime,char *format,time_t timestamp);
time_t str_toTime(char *strTime,char *format);
int    str_dataToHex(void *srcData,int dataLen,char *hexBuf,int bufSize,char splitter);
char  *str_keySeek(char *keyList,char *key,char splitter);
int    tm_getLocalHour(time_t timestamp);//get local hour from unix timestamp;
//---------------------------------------------------------------------------
enum  {DTMR_LOCK=0x80000000U,DTMR_NOVERRIDE=0x40000000U,DTMR_FOREVER=0x20000000U,DTMR_KEEPLIFE=0x10000000U};
typedef void (*TTSKTimeoutEvent)(HAND,void *,U32 *,char *,U32 *);
HAND  dtmr_create(int hashLen,U32 sHoldTime,TTSKTimeoutEvent OnTimeout);
void  dtmr_destroy(HAND dtimer);
void *dtmr_add(HAND dtimer,U32 nodeIDL,U32 nodeIDH,char *nodeName,void *nodeData,U32 nodeSize,U32 sLifeTime);
void *dtmr_find(HAND dtimer,U32 nodeIDL,U32 nodeIDH,char *nodeName,U32 sUpdateLifeTime);
void *dtmr_find2(HAND dtimer,U32 nodeIDL,U32 nodeIDH,void *nodeData,U32 nodeSize,int extraOffset,U32 sUpdateLifeTime);
void  dtmr_update(void *dnode,U32 sUpdateLifeTime);
int   dtmr_getOverrideCount(void *dnode);
char *dtmr_getName(void *dnode);
int   dtmr_getSize(void *dnode);
void  dtmr_unlock(void *dnode,U32 sUpdateLifeTime);
void  dtmr_remove(void *dnode);
//---------------------------------------------------------------------------	
MYSQL *db_conn(void);
void   db_open(char *dbhost,char *dbname,char *dbuser,char *password);
void   db_close(void);
void   db_lock(BOOL lock);
BOOL   db_checkSQL(char *sql);
char  *db_filterSQL(char *text);
MYSQL_RES *db_query(char *sql);
MYSQL_RES *db_queryf(const char *format, ...);
//---------------------------------------------------------------------------
//TMailBox
//---------------------------------------------------------------------------
void   mb_create(int queue_size);
void   mb_destroy(void);
int    mb_post(void *msgData,int msgLen);
int    mb_receive(void *msgBuf,int bufSize);
//---------------------------------------------------------------------------		
#endif
