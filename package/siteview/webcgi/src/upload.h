
#ifndef __UPLOAD_H_
#define __UPLOAD_H_

#define MAX_UPLOAD_SIZE (64 * 1024 * 1024)

#define	MIN(a, b) (((a) < (b)) ? (a) : (b))
#define	MAX(a, b) (((a) > (b)) ? (a) : (b))

int upload_file(FILE *infp, int clen, char * rename);

#endif
