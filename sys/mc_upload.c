#include "mc_routine.h"
//---------------------------------------------------------------------------
#define UPLOADS_DIRECTORY_NAME    "uploadfiles"

#define PROFILE_DIRECTORY_NAME    "profiles"
#define UPGRADE_DIRECTORY_NAME    "upgrade"
#define GPSDATA_DIRECTORY_NAME    "gpsdata"
static char g_uploads_directory[64]="";
//---------------------------------------------------------------------------
void makeUploadSubDirectory(char *subDir)
{ char tmpPath[128],*p_dir=NULL;
	if(subDir && *subDir)
	{ if(!g_uploads_directory[0])makeUploadSubDirectory(NULL);
		sprintf(tmpPath,"%s/%s",g_uploads_directory,subDir);
    p_dir=tmpPath;
	}
	else 
	{ int n=app_exepath(tmpPath,128);
    if(n>0)
  	{ sprintf(g_uploads_directory,"%s"UPLOADS_DIRECTORY_NAME,tmpPath);
  		p_dir=g_uploads_directory;
	  }
	}
	if(p_dir && access(p_dir,0)!=0)
  { if(mkdir(p_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)!=0)
    { Log_AppendText("Can not create profile path[%s]!",p_dir);
   		exit(0);
   	}
  }  	
}
 
void upload_init(void)
{ makeUploadSubDirectory(PROFILE_DIRECTORY_NAME);
//makeUploadSubDirectory(UPGRADE_DIRECTORY_NAME);
//makeUploadSubDirectory(GPSDATA_DIRECTORY_NAME);
}

BOOL Userlogo_Save(U32 userid,void *data,int datalen)
{ char save_filepath[80];
	sprintf(save_filepath,"%s/"PROFILE_DIRECTORY_NAME"/head%d.jpg",g_uploads_directory,userid);
	FILE *f=fopen(save_filepath,"wb");
	if(f)
	{ fwrite(data,1,datalen,f);
		fclose(f);
		return TRUE;
	}
	return FALSE;
}

U32 Userlogo_Load(U32 userid,void *dataBuffer,int bufszie)
{ char logo_filepath[80];
	sprintf(logo_filepath,"%s/"PROFILE_DIRECTORY_NAME"/head%d.jpg",g_uploads_directory,userid);
	FILE *f=fopen(logo_filepath,"rb");
	if(f)
	{ int ret=fread(dataBuffer,1,bufszie,f);
		fclose(f);
		return ret;
	}
	return 0;
}

#if 0
U32 Mcufw_Load(U32 groupid,void *dataBuffer,int bufszie)
{ char filepath[80];
	sprintf(filepath,"%s/"UPGRADE_DIRECTORY_NAME"/mcufw.%d.bin",g_uploads_directory,groupid);
	FILE *f=fopen(filepath,"rb");
	if(f)
	{ int ret;
		if(dataBuffer && bufszie)
		{	ret=fread(dataBuffer,1,bufszie,f);
	  }	
		else
		{ fseek(f,0,SEEK_END);
			ret=ftell(f);
		}	
		fclose(f);
		return ret;
	}
	return 0;
}
#else
U32 Mcufw_Load(U32 groupid,void *dataBuffer,int bufszie)
{ char url[MAXLEN_URL+1];
  if(sprintf(url,"http://"WEB_SERVER_HOST"/"UPLOADS_DIRECTORY_NAME"/"UPGRADE_DIRECTORY_NAME"/mcufw.%d.bin",groupid)>MAXLEN_URL)abort();
  int ret=hsk_httpGet(url,dataBuffer,bufszie,10);
  return (ret>0)?ret:0;
}
#endif

BOOL GPSdata_Save(U32 terminalID,TMcTime *mcTime,void *data,int datalen)
{ char save_filepath[128];
	sprintf(save_filepath,"%s/"GPSDATA_DIRECTORY_NAME"/%u-%d%02d%02d%02d%02d%02d.log",g_uploads_directory,terminalID,mcTime->year,mcTime->month,mcTime->day,mcTime->hour,mcTime->minute,mcTime->second);
	FILE *f=fopen(save_filepath,"wb");
	if(f)
	{ fwrite(data,1,datalen,f);
		fclose(f);
		return TRUE;
	}
	return FALSE;
}
