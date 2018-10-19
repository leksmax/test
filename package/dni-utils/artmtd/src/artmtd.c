
/*
 * 按照dni artmtd输出格式修改
 *
 * 目前只支持读操作
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>

#define MTD_DEVICE "/dev/mtd3"
#define MTD_BLOCK_SIZE (128 * 1024) /* NAND Device 128Kib */

#define MTD_OPT_WRITE   (1 << 0)
#define MTD_OPT_READ    (1 << 1)

void genstr_fmt(char *prefix, unsigned char * buff, int len);
void macstr_fmt(char *prefix, unsigned char * buff, int len);
void regstr_fmt(char *prefix, unsigned char * buff, int len);
void snstr_fmt(char * prefix, unsigned char * buff, int len);

struct board_param_t {
    const char *name;
    int len;
    int offset;
    char *prefix;
    void (*result_fmt)(char *prefix, unsigned char *buff, int len);
};

struct board_param_t board_params[] = {
    {
        .name = "sn",
        .len = 13,
        .offset = 26,
        .prefix = "",
        .result_fmt = snstr_fmt,
    }, {
        .name = "region",
        .len = 2,
        .offset = 39,
        .prefix = "",
        .result_fmt = regstr_fmt,
    }, {
        .name = "language",
        .len = 0, 
        .offset = 0x0,
        .prefix = "LANGUAGE: ",
        .result_fmt = genstr_fmt,
    }, {
        .name = "ssid",
        .len = 32,
        .offset = 91,
        .prefix = "ssid:",
        .result_fmt = genstr_fmt,
    }, {
        .name = "passphrase", 
        .len = 32, 
        .offset = 123,
        .prefix = "passphrase:",
        .result_fmt = genstr_fmt,
    }, { 
        .name = "wpspin", 
        .len = 8, 
        .offset = 18,
        .prefix = "wpspin:",
        .result_fmt = genstr_fmt,
    }, { 
        .name = "board_hw_id", 
        .len = 34, 
        .offset = 41,
        .prefix = "hw_id:",
        .result_fmt = genstr_fmt,
    }, { 
        .name = "board_model_id", 
        .len = 16,
        .offset = 75,        
        .prefix = "model_id:",
        .result_fmt = genstr_fmt,
    }, { 
        .name = "mac_lan",
        .len = 6,
        .offset = 0,        
        .prefix = "lan mac: ",
        .result_fmt = macstr_fmt,
    }, {
        .name = "mac_wan",
        .len = 6,
        .offset = 6,        
        .prefix = "wan mac: ",
        .result_fmt = macstr_fmt,
    }, { 
        .name = "mac_5g",
        .len = 6,
        .offset = 12,
        .prefix = "wlan5g_mac: ",
        .result_fmt = macstr_fmt,
    }, {
        /* terminating entry */
    }
};

/*
 * 普通字符串格式化输出
 */
void genstr_fmt(char *prefix, unsigned char *buff, int len)
{
    fprintf(stdout, "%s%s\n", prefix, buff);
}

/*
 * SN序列号格式化输出
 */
void snstr_fmt(char *prefix, unsigned char *buff, int len)
{
    fprintf(stdout, "sn:%s\n", buff);
    fprintf(stdout, "SN: %s\n", buff);
}

/*
 * MAC地址格式化输出
 */
void macstr_fmt(char *prefix, unsigned char *buff, int len)
{
    fprintf(stdout, "%s%02x:%02x:%02x:%02x:%02x:%02x\n", prefix,  
        buff[0], buff[1], buff[2], buff[3], buff[4], buff[5]);
}

/*
 * 国家代码格式化输出
 */
void regstr_fmt(char *prefix, unsigned char *buff, int len)
{
    uint16_t regcode = 0;
    memcpy(&regcode, buff, sizeof(uint16_t));
    fprintf(stdout, "REGION: 0x%04x\n", ntohs(regcode));
}

int art_mtd_read(int offset, unsigned char *rbuf, int rlen)
{
    int ret = 0;
    int mtd_fd = -1;

    if(rlen < MTD_BLOCK_SIZE)
    {
        fprintf(stderr, "error size!\n");
        return -1;
    }
    
    mtd_fd = open(MTD_DEVICE, O_RDONLY);
    if(mtd_fd < 1)
    {
        fprintf(stderr, "open %s failed, %s!\n", MTD_DEVICE, strerror(errno));
        return -1;
    }

    ret = lseek(mtd_fd, offset, SEEK_SET);
    if(ret < 0)
    {
        close(mtd_fd);
        fprintf(stderr, "lseek: %s\n", strerror(errno));
        return -1;
    }

    ret = read(mtd_fd, rbuf, rlen);
    if(ret < 0 || ret != rlen)
    {
        fprintf(stderr, "read: %s\n", strerror(errno));
        return -1;
    }
    
    close(mtd_fd);

    return 0;
}

int art_mtd_write(int offset, char *wbuf, int wlen)
{
    return 0;
}

void usages()
{
    fprintf(stderr, "Usage: artmtd -r name [<arguments> ...]\n");
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int mtd_opt = 0;
    struct board_param_t *board;
    unsigned char buff[128] = {0};
    unsigned char block_buff[MTD_BLOCK_SIZE];
    
    if(argc < 3)
    {
        usages();
    }

    memset(block_buff, 0x0, MTD_BLOCK_SIZE);

    if(strcmp(argv[1], "-r") == 0)
    {
        mtd_opt = MTD_OPT_READ;
    }
    else
    {
        fprintf(stderr, "operation not support right now!\n");
        return -1;
    }

    for(board = board_params; board->name != NULL; board ++ )
    {
        if(strcmp(argv[2], board->name) == 0)
        {
            if(mtd_opt & MTD_OPT_READ)
            {
                ret = art_mtd_read(0, block_buff, MTD_BLOCK_SIZE);
                if(ret < 0)
                {
                    fprintf(stderr, "art read error!\n");
                    return -1;
                }

                memcpy(buff, block_buff + board->offset, board->len);
                
                board->result_fmt(board->prefix, buff, board->len);
            }
            
            break;
        }
    }
    
    return 0;
}
