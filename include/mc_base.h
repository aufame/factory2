//---------------------------------------------------------------------------
#ifndef _MC_BASE_H
#define _MC_BASE_H
//---------------------------------------------------------------------------
#include <sys/time.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <errno.h>     //错误号定义
//---------------------------------------------------------------------------
#include <netdb.h> 
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>  
#include <fcntl.h>     //文件控制定义
#include <unistd.h>    //Unix标准函数定义
//---------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
//---------------------------------------------------------------------------
typedef void *            HAND;
typedef long              S64;
typedef unsigned long     U64;
typedef int               S32,BOOL;
typedef unsigned int      U32;
typedef unsigned short    U16;
typedef unsigned char     U8;
typedef short             S16;
typedef struct{S16 socket;U16 port;U32 ip;}TNetAddr;
#define T_NODE_OFFSET(TStruct,NodeName)  ((char *)(&((TStruct *)0)->NodeName)-(char *)0)
#define TRUE             -1
#define FALSE             0
//---------------------------------------------------------------------------
#endif