#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/sysinfo.h>

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "easy_uci.h"
#include "librestapi.h"
#include "restapi_access.h"
#include "restapi_utils.h"
#include "restapi_host.h"

#define ERROR_HTML          "<html><head><meta http-equiv=\"refresh\" content=\"0;url=/index.html\"></head></html>"
#define TIME_OUT_JSON       "{\"errCode\" : \"504\"}"
#define SESSION_TIMEOUT     600 /* 10min */

extern WEBS_APPID_INFO Webs_AppIds[WEBS_APPID_MAX];
extern HRM_BOOL isLocalGUI;

int base64_decode(char *in_str, int in_len, char *out_str)
{
	BIO *b64, *bio;
	BUF_MEM *bptr = NULL;
	int counts;
	int size = 0;

	if (in_str == NULL || out_str == NULL)
		return -1;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bio = BIO_new_mem_buf(in_str, in_len);
	bio = BIO_push(b64, bio);

	size = BIO_read(bio, out_str, in_len);
	out_str[size] = '\0';

	BIO_free_all(bio);
	return size;
}

char *getcgidata(FILE *fp, char *requestmethod)
{
	char *input;
	int len;
	int i = 0;

	if (!strcmp(requestmethod, "GET"))
	{
		input = getenv("QUERY_STRING");
		return input;
	}
	else if (!strcmp(requestmethod, "POST"))
	{
		len = atoi(getenv("CONTENT_LENGTH"));
		input = (char *)malloc(sizeof(char) * (len + 1));

		memset(input, 0, len + 1);

		if (len == 0)
		{
			input[0] = '\0';
			return input;
		}

		len = fread(input, 1, len, stdin);

		return input;
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	char *uri = NULL, *ht_header = NULL;
	char *req_method;
	struct uci_context *easy_uci_ctx;

	HRM_CHAR      action[128] = {0};
	HRM_CHAR      *reqbody = NULL;
	HRM_INT32     rescode = 0;
	HRM_CHAR      *res_body = NULL;
	HRM_CHAR 	  ht_token[512] = {0};
	HRM_BOOL      isAuth = HRM_FALSE;
	FILE          *fd = NULL;
	WEBS_APPID_INFO * current_AppID = NULL;

	isLocalGUI = HRM_TRUE;

	if(strcmp(argv[0], "/www/generate_204") == 0)
	{
		RestAPI_Debug_Log(L_NOTICE, "Android Captive Portal request found!");
		puts("Content-type: text/html\r\n");
		puts(ERROR_HTML);
		return;
	}

	res_body = (HRM_CHAR *)malloc(RESTAPI_MAX_HOSTS_INFO_LENGTH);
	memset(res_body, 0, RESTAPI_MAX_HOSTS_INFO_LENGTH);

	/* prepare the browser for content */
	ht_header   = getenv("HTTP_HT_APP_AUTH");
	if(ht_header)
	{
		base64_decode(ht_header, strlen(ht_header), ht_token);
		RestAPI_Debug_Log(L_NOTICE, "WEB: %s", ht_token);
	}

	uri        = getenv("PATH_INFO");
	req_method = getenv("REQUEST_METHOD");
	reqbody    = getcgidata(stdin, req_method);

	if(!strcmp(argv[0],"/www/1"))
		sprintf(action, "%s /1%s", req_method, uri);
	else
		sprintf(action, "%s %s", req_method, uri);

	RestAPI_Debug_Log(L_NOTICE, "WEB: %s", action);

	if(reqbody && reqbody[0] != '\0')
		RestAPI_Debug_Log(L_NOTICE, "WEB: %s", reqbody);

	if ((fd = fopen ("/var/run/restapi.dat", "rb")) == NULL)
	{ 
		memset(Webs_AppIds, 0, sizeof(WEBS_APPID_INFO) * WEBS_APPID_MAX);
		Utils_LarrayInit(Webs_AppIds, WEBS_APPID_MAX, sizeof(WEBS_APPID_INFO));
	} 
	else
	{
		fread(&Webs_AppIds, sizeof(WEBS_APPID_INFO)* WEBS_APPID_MAX, 1, fd);
		fclose(fd);

		if (ht_token[0] != '\0')
		{
			int i;

			for (i=0; i<WEBS_APPID_MAX; i++)
			{
				if (strcmp(Webs_AppIds[i].AppIdAuth, ht_token) == 0)
				{
					isAuth = HRM_TRUE;
					current_AppID = Webs_AppIds + i;
					break;
				}
			}
		}
	}


	int saved_stdout, flags;

	saved_stdout = dup(STDOUT_FILENO);
	flags = fcntl(saved_stdout, F_GETFD);
	flags |= FD_CLOEXEC;
	fcntl(saved_stdout, F_SETFD, flags);
    
	freopen("/dev/null", "w", stdout);

	/* RestAPI callback register */
	RestApi_RegisterCallback_TokenA(Webs_App_TokenA);
	RestApi_RegisterCallback_TokenB(Webs_App_TokenB);
	if ((strstr(action, "POST /1/Device/API/Register")) ||
		(strstr(action, "POST /1/Device/Users/Login")) || 
		(strstr(action, "POST /1/Device/Users/LoginStatus")) ||
		(strstr(action, "POST /1/Device/Capability/Onboarding")) ||
		(isAuth == HRM_TRUE))
	{
		RestApi_Action_Process(current_AppID, action, reqbody, &rescode, res_body, RESTAPI_MAX_HOSTS_INFO_LENGTH);

		dup2(saved_stdout, STDOUT_FILENO);
		puts("Content-type: text/plain\r\n");
		puts(res_body);
	}
	else
	{
		dup2(saved_stdout, STDOUT_FILENO);
		/* request user login */
		puts("Content-type: text/html\r\n");
		puts(ERROR_HTML);
		goto end;
	}

	RestAPI_Debug_Log(L_NOTICE, "WEB: %s", res_body);
	/* Register/Login/Logout/Password need update token */
	if ((strstr(action, "POST /1/Device/API/Register") ||
	      strstr(action, "POST /1/Device/Users/Login") ||
	      strstr(action, "POST /1/Device/Users/Logout") ||
	      strstr(action, "POST /1/Device/Users/Password"))
	    && (fd = fopen ("/var/run/restapi.dat", "wb")) != NULL)
	{
		fwrite(&Webs_AppIds, sizeof(WEBS_APPID_INFO) * WEBS_APPID_MAX, 1, fd);
		fflush(fd);
		fclose(fd);
	}

end:
	close(saved_stdout);
	if (res_body) free(res_body);

	return 0;
}
