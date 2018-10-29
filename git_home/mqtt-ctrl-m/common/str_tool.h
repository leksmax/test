#ifndef _SRC_STR_TOOL_H_
#define _SRC_STR_TOOL_H_

#ifdef __cplusplus
extern "C" {
#endif

int str_tool_replaceAll(char *str, char old_chr, char new_chr);
int str_tool_replaceFirst(char *str, char old_chr, char new_chr);
int str_tool_replaceCnt(char *str, char old_chr, char new_chr, int cnt);

char * str_tool_base64_encode( const unsigned char * bindata, int binlength, char * base64 );
int str_tool_base64_decode(const char* base64, unsigned char* bindata);
void str_tool_md5(const unsigned char* in, int len, char* out);

#ifdef __cplusplus
}
#endif
#endif
