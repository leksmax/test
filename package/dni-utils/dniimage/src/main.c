
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>

#define DNI_HDR_LEN 128

char errMsg[128] = {0};

struct dni_hdr {
    char device[20];
    char version[32];
    char region[10];
    char hw_id[64];
    uint8_t cksum;
};

/*
 * artmtd -r board_model_id
 */
int get_model_id(char *model_id, int len)
{
    FILE *fp;
    int ret = 0;
    char line[128];

    fp = popen("/sbin/artmtd -r board_model_id 2>/dev/null", "r");
    if(!fp)
    {   
        fprintf(stderr, "get board_model_id error!\n");
        return -1; 
    }   

    fgets(line, sizeof(line), fp);

    ret = sscanf(line, "model_id:%s", model_id);
    if(ret != 1)
    {   
        pclose(fp);
        fprintf(stderr, "format board_model_id failed!\n");
        return -1; 
    }   

    pclose(fp);

    return 0;
}

/*
 * artmtd -r board_hw_id
 */
int get_hw_id(char *hw_id, int len)
{
    FILE *fp;
    int ret = 0;
    char line[128];

    fp = popen("/sbin/artmtd -r board_hw_id 2>/dev/null", "r");
    if(!fp)
    {   
        fprintf(stderr, "get board_hw_id error!\n");
        return -1; 
    }   

    fgets(line, sizeof(line), fp);

    ret = sscanf(line, "hw_id:%s", hw_id);
    if(ret != 1)
    {   
        pclose(fp);
        fprintf(stderr, "format board_hw_id failed!\n");
        return -1; 
    }   

    pclose(fp);

    return 0;
}

/* 
 * image header format exp:
 * device:BR500\nversion:V1.0.2.52\nregion:\nhd_id:29764958+0+128+1024+0+0\n
 */
int get_image_hdr(struct dni_hdr *hdr, char *buff, int buff_len)
{
    int ret = 0;

    ret = sscanf(buff, "device:%s\nversion:%s\n%*s\nhd_id:%s\n", hdr->device,
        hdr->version, hdr->hw_id);
    if(ret != 3)
    {
        snprintf(errMsg, sizeof(errMsg), "get image hdr failed!");
        return -1;
    }

    hdr->cksum = buff[buff_len - 1];
    
    return 0;
}

int img_check(struct dni_hdr *hdr, char *buff, int len)
{
    int ret = 0;
    int i = 0;
    uint8_t cksum = 0;
    char device[20] = {0};
    char hw_id[64] = {0};

    for (i = 0; i < (len - 1); i ++)
    {   
        cksum += buff[i];
    }

    if((0xFF - cksum) != hdr->cksum)
    {
        snprintf(errMsg, sizeof(errMsg), "image cksum failed!");
        return -1;
    }

    ret = get_model_id(device, sizeof(device));
    if(ret < 0)
    {
        return -1;
    }

    if(strcasecmp(device, hdr->device) != 0)
    {
        snprintf(errMsg, sizeof(errMsg), "board id missmatch!");
        return -1;
    }

    ret = get_hw_id(hw_id, sizeof(hw_id));
    if(ret < 0)
    {
        return -1;
    }

    if(strcasecmp(hw_id, hdr->hw_id) != 0)
    {
        snprintf(errMsg, sizeof(errMsg), "board hw id missmatch!");
        return -1;
    }

    return 0;
}

int img_show(struct dni_hdr *hdr)
{
    printf("Image Info:\n");
    printf("    board_id : %s\n", hdr->device);
    printf("    version  : %s\n", hdr->version);
    printf("    region   : %s\n", hdr->region);
    printf("    hw_id    : %s\n", hdr->hw_id);

    return 0;
}

void usages()
{
	fprintf(stderr,
        "Usage:\n"
        "   dniimage [check <file> | show <file>]\n"
        "\n"
        "    check result:\n"
        "       sucess:version\n"
        "       failed:reason\n"    
        "\n"
    );
}

int main(int argc, char *argv[])
{
    int ret = 0;
    char *buff = NULL;    
    int buff_len = 0;
	struct stat st;    
    FILE *fp = NULL;
    char *optstr, *file;
    struct dni_hdr hdr;

    if(argc < 3)
    {
        usages();
        return 0;
    }

    optstr = argv[1];
    file = argv[2];

	ret = stat(file, &st);
	if(ret < 0)
    {
		fprintf(stderr, "stat failed on %s", file);
		goto err;
	}

    buff_len = st.st_size;
	buff = malloc(buff_len);
	if(!buff)
    {
		fprintf(stderr, "no memory for buffer\n");
		goto err;
	}

	memset(buff, 0x0, buff_len);

    fp = fopen(file, "rb");
    if(!fp)
    {
        fprintf(stderr, "open %s failed!\n", file);
        goto err;
    }

    errno = 0;
    fseek(fp, 0, SEEK_SET);
	fread(buff, st.st_size, 1, fp);
	if (errno != 0) 
    {
		fprintf(stderr, "unable to read from file %s", file);
		goto err;
	}

    memset(&hdr, 0x0, sizeof(struct dni_hdr));
    ret = get_image_hdr(&hdr, buff, buff_len);
    if(ret < 0)
    {
        goto result;
    }

    if(strcmp(optstr, "check") == 0)
    {    
        ret = img_check(&hdr, buff, buff_len);    
    }
    else if(strcmp(optstr, "show") == 0) 
    {
        img_show(&hdr);
    }
    else
    {
        fprintf(stderr, "unsupported operation!\n");
        return -1;
    }

result:
    if(ret < 0)
    {
        printf("failed:%s\n", errMsg);
    }
    else
    {
        printf("success:%s\n", hdr.version);
    }
    
err:
    if(buff)
    {
        free(buff);
    }
    
    if(fp)
    {
        fclose(fp);
    }

    return 0;
}
