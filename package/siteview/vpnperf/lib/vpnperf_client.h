#ifndef _SRC_VPNPERF_CLIENT_H_
#define _SRC_VPNPERF_CLIENT_H_

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * 返回值 
 *    1: 超时
 *    0: 正常
 *   -1: 错误
 * 
 */
int uds_client_request(char *path, 
    char *wbuf, int wlen, char *rbuf, int rlen, int timeout);

#ifdef __cplusplus
}
#endif

#endif
