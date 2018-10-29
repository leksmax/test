#ifndef __NVRAM_OP_H__
#define __NVRAM_OP_H__

void SetConfig(const char *name, char *value);
void UnsetConfig(const char *name);
char* GetConfig(const char *name);

#endif
