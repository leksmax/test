
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include "upload.h"

#define MAX_BOUNDARY_LEN  (128)
#define UPLOAD_CHUNK_SIZE (1024)
#define FILE_NAME_LEN  (128)
#define TMP_UPLOAD_DIR ("/tmp/")

enum {
    UPLOAD_GET_START = 0,
    UPLOAD_GET_BOUNDARY,     
    UPLOAD_GET_FILE_NAME,
    UPLOAD_GET_FILE_START,
    UPLOAD_GET_FILE_BODY,
    UPLOAD_GET_CHECK_END,
    UPLOAD_GET_FILE_END,
};

int upload_file(FILE *infp, int clen, char *rename)
{
    int ret = 0;
    FILE *fp = NULL;
    int nread = -1;
    int contentLength;
    int nowReadLen;
    int boundaryLen;
    int tmpLen;
    char *nowReadP;
    char *nowWriteP;
    char chunkBuff[UPLOAD_CHUNK_SIZE];
    char boundary[MAX_BOUNDARY_LEN];
    char tmpBoundary[MAX_BOUNDARY_LEN];
    char fileName[FILE_NAME_LEN];
    int getState = UPLOAD_GET_START;
    
    memset(chunkBuff, 0, UPLOAD_CHUNK_SIZE);
    memset(boundary, 0, MAX_BOUNDARY_LEN);
    memset(fileName, 0, FILE_NAME_LEN);
    
    nowReadLen = 0;
    contentLength = clen;
    
    while (contentLength > 0)
    {
        nowReadLen = MIN(contentLength, UPLOAD_CHUNK_SIZE);
        contentLength -= nowReadLen;

        nread = fread(chunkBuff, sizeof(char), nowReadLen, infp);
        if (nread != nowReadLen)
        {
            ret  = -1;
            goto err;
        }
        
        nowReadP = chunkBuff;
        
        while (nowReadLen > 0)
        {
            switch (getState)
            {
                case UPLOAD_GET_START:
                    nowWriteP = boundary;
                    getState = UPLOAD_GET_BOUNDARY;
                
                case UPLOAD_GET_BOUNDARY:
                    if (strncmp(nowReadP, "\r\n", 2) == 0)
                    {
                        boundaryLen = nowWriteP - boundary;
                        nowReadP ++;
                        nowReadLen --;
                        *nowWriteP = 0;
                        getState = UPLOAD_GET_FILE_NAME;
                    }
                    else
                    {
                        *nowWriteP = *nowReadP;
                        nowWriteP ++;
                    }
                    break;
                    
                case UPLOAD_GET_FILE_NAME:
                    if (strncmp(nowReadP, "filename=", 9) == 0)
                    {
                        nowReadP += 9;
                        nowReadLen -= 9;
                        nowWriteP = fileName + strlen(TMP_UPLOAD_DIR);
                        
                        while(*nowReadP != '\r')
                        {
                            if(*nowReadP == '\\' || *nowReadP == '/')
                            {
                                nowWriteP = fileName + strlen(TMP_UPLOAD_DIR);
                            }
                            else if(*nowReadP != '\"')
                            {
                                *nowWriteP = *nowReadP;
                                nowWriteP ++;
                            }
                            nowReadP ++;
                            nowReadLen --;
                        }
                        
                        *nowWriteP = 0;
                        nowReadP ++;
                        nowReadLen --;
                        getState = UPLOAD_GET_FILE_START;

                        if (!rename)
                        {
                            memcpy(fileName, TMP_UPLOAD_DIR, strlen(TMP_UPLOAD_DIR));
                        }
                        else
                        {
                            strncpy(fileName, rename, sizeof(fileName) - 1);
                        }
                        
                        if((fp = fopen(fileName, "w")) == NULL)
                        {
                            ret = -1;
                            goto err;
                        }
                    }
                    break;
                    
                case UPLOAD_GET_FILE_START:
                    if(strncmp(nowReadP, "\r\n\r\n", 4) == 0)
                    {
                        nowReadP += 3;
                        nowReadLen -= 3;
                        getState = UPLOAD_GET_FILE_BODY;
                    }
                    break;
                    
                case UPLOAD_GET_FILE_BODY:
                    if(*nowReadP != '\r')
                    {
                        fputc(*nowReadP, fp);
                    }
                    else
                    {
                        if(nowReadLen >= (boundaryLen + 2))
                        {
                            if(strncmp(nowReadP + 2, boundary, boundaryLen) == 0)
                            {
                                getState = UPLOAD_GET_FILE_END;
                                nowReadLen = 1;
                            }
                            else
                            {
                                fputc(*nowReadP, fp);
                            }
                        }
                        else
                        {
                            getState = UPLOAD_GET_CHECK_END;
                            nowWriteP = tmpBoundary;
                            *nowWriteP = *nowReadP;
                            nowWriteP ++;
                            tmpLen = 1;
                        }
                    }
                    break;
                    
                case UPLOAD_GET_CHECK_END:
                    if (*nowReadP != '\r')
                    {
                        if (tmpLen < boundaryLen + 2)
                        {
                            *nowWriteP = *nowReadP;
                            nowWriteP++;
                            tmpLen++;
                            if (tmpLen == boundaryLen + 2)
                            {
                                *nowWriteP = 0;
                                if ((tmpBoundary[1] == '\n') && (strncmp(tmpBoundary + 2, boundary, boundaryLen) == 0))
                                {
                                    getState = UPLOAD_GET_FILE_END;
                                    nowReadLen = 1;
                                }
                                else
                                {
                                    fwrite(tmpBoundary, sizeof(char), tmpLen, fp);
                                    getState = UPLOAD_GET_FILE_BODY;
                                }
                            }
                        }
                    }
                    else
                    {
                        *nowWriteP = 0;
                        fwrite(tmpBoundary, sizeof(char), tmpLen, fp);
                        nowWriteP = tmpBoundary;
                        *nowWriteP = *nowReadP;
                        nowWriteP ++;
                        tmpLen = 1;
                    }
                    break;
                case UPLOAD_GET_FILE_END:
                    nowReadLen = 1;
                    break;
                default:
                    break;
            }
            
            nowReadLen--;
            nowReadP++;
        }
    }

err:    
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

