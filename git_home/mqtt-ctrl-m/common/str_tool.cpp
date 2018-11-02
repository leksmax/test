#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include "str_tool.h"

int str_tool_replaceAll(char *str, char old_chr, char new_chr)
{
	int ret = 0;
	if (str)
	{
		int i;
		int len = strlen(str);
		for(i = 0; i < len; i++)
		{
			if (str[i] == old_chr)
			{
				str[i] = new_chr;
				ret++;
			}
		}
	}
	return ret;
}

int str_tool_replaceCnt(char *str, char old_chr, char new_chr, int cnt)
{
	int ret = 0;
	if (str)
	{
		int i;
		int len = strlen(str);
		for(i = 0; i < len; i++)
		{
			if (str[i] == old_chr)
			{
				str[i] = new_chr;
				ret++;
			}
			if (ret >= cnt)
			{
				break;
			}
		}
	}
	return ret;
}

int str_tool_replaceFirst(char *str, char old_chr, char new_chr)
{
	int ret = 0;
	if (str)
	{
		int i;
		int len = strlen(str);
		for(i = 0; i < len; i++)
		{
			if (str[i] == old_chr)
			{
				str[i] = new_chr;
				ret++;
				break;
			}
		}
	}
	return ret;
}

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char * str_tool_base64_encode( const unsigned char * bindata, int binlength, char * base64 )
{
    int i, j;
    unsigned char current;

    for ( i = 0, j = 0 ; i < binlength ; i += 3 ) 
    {        
        current = (bindata[i] >> 2) ; 
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ; 
        if ( i + 1 >= binlength )
        {        
            base64[j++] = base64char[(int)current];
            base64[j++] = '='; 
            base64[j++] = '='; 
            break;
        }        
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ; 
        if ( i + 2 >= binlength )
        {        
            base64[j++] = base64char[(int)current];
            base64[j++] = '='; 
            break;
        }        
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ; 
        base64[j++] = base64char[(int)current];
    }        
    base64[j] = '\0';
    return base64;
}

int str_tool_base64_decode(const char* base64, unsigned char * bindata)
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
                ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}

void str_tool_md5(const unsigned char* in, int len, char* out)
{
	int i;
	unsigned char buf[16];
	memset(buf, 0, sizeof(buf));
#if 1
	MD5(in, (unsigned long)len, (unsigned char*)buf);
#else
	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c, in, len);
	MD5_Final(buf, &c);
#endif
	for(i = 0; i < 16; i++)
	{
		sprintf(out + 2*i, "%02x", buf[i]);
	}
	return;
}