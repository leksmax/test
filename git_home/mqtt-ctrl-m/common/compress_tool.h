#ifndef _COMPRESS_TOOL_H_
#define _COMPRESS_TOOL_H_

#include <stdio.h>
#include <zlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  :compress a data with gzip format
 *
 * @Param  :data
 * @Param  :ndata
 * @Param  :zdata
 * @Param  :nzdata
 *
 * @Returns  :
 */
int gzcompress(Bytef *data, uLong ndata,
		               Bytef *zdata, uLong *nzdata);

/**
 * @brief  :uncompress a gzipped data
 *
 * @Param  :zdata
 * @Param  :nzdata
 * @Param  :data
 * @Param  :ndata
 *
 * @Returns  :
 */
int gzdecompress(Byte *zdata, uLong nzdata,
		                 Byte *data, uLong *ndata);

#ifdef __cplusplus
}
#endif

#endif
