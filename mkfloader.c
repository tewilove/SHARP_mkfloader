#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>

#define NELEM(x) (sizeof(x)/sizeof(x[0]))
#define ROUND_UP(x,y) ((((x)+(y)-1)/(y))*(y))

struct fldr_device_info {
    char name[8];
    const char *model;
    const unsigned char *key;
    int machine;
    int entry;
};

const static unsigned char g_sec_msk[] = {
    0x53, 0x55, 0x56, 0x6D, 0x4E, 0x31, 0x78, 0x79, 0x4C, 0x52, 0x44, 0x50, 0x71, 0x76, 0x2B, 0x6E,
};

const static unsigned char g_204sh_key[] = {
    0x4F, 0x35, 0x56, 0x73, 0x59, 0x44, 0x6C, 0x56, 0x47, 0x46, 0x61, 0x4A, 0x67, 0x47, 0x57, 0x4E,
    0x61, 0x42, 0x6F, 0x35, 0x4E, 0x70, 0x70, 0x59, 0x50, 0x49, 0x41, 0x69, 0x6F, 0x69, 0x52, 0x6F,
};

const static unsigned char g_302sh_key[] = {
    0x6D, 0x6E, 0x58, 0x71, 0x70, 0x70, 0x6C, 0x44, 0x47, 0x72, 0x79, 0x2B, 0x7A, 0x31, 0x56, 0x70,
    0x71, 0x71, 0x7A, 0x58, 0x41, 0x30, 0x53, 0x6F, 0x70, 0x4F, 0x4A, 0x76, 0x7A, 0x51, 0x4C, 0x2B,
};

const static unsigned char g_303sh_key[] = {
    0x6D, 0x6E, 0x58, 0x71, 0x70, 0x70, 0x6C, 0x44, 0x47, 0x72, 0x79, 0x2B, 0x7A, 0x31, 0x56, 0x70,
    0x71, 0x71, 0x7A, 0x58, 0x41, 0x30, 0x53, 0x6F, 0x70, 0x4F, 0x4A, 0x76, 0x7A, 0x51, 0x4C, 0x2B,
};

const static unsigned char g_304sh_key[] = {
    0x64, 0x4E, 0x35, 0x35, 0x76, 0x69, 0x36, 0x76, 0x72, 0x4A, 0x6E, 0x31, 0x68, 0x54, 0x68, 0x6F,
    0x47, 0x4E, 0x54, 0x51, 0x36, 0x52, 0x2F, 0x49, 0x58, 0x46, 0x49, 0x76, 0x6B, 0x34, 0x59, 0x36,
};

const static unsigned char g_306sh_key[] = {
    0x63, 0x31, 0x55, 0x75, 0x72, 0x51, 0x34, 0x74, 0x79, 0x53, 0x4C, 0x46, 0x4F, 0x44, 0x42, 0x6D,
    0x45, 0x73, 0x2F, 0x74, 0x4C, 0x4C, 0x4D, 0x63, 0x6E, 0x6C, 0x4C, 0x71, 0x52, 0x79, 0x41, 0x58,
};

const static unsigned char g_402sh_key[] = {
    0x64, 0x4E, 0x35, 0x35, 0x76, 0x69, 0x36, 0x76, 0x72, 0x4A, 0x6E, 0x31, 0x68, 0x54, 0x68, 0x6F,
    0x47, 0x4E, 0x54, 0x51, 0x36, 0x52, 0x2F, 0x49, 0x58, 0x46, 0x49, 0x76, 0x6B, 0x34, 0x59, 0x36,
};

const static unsigned char g_sh01f_key[] = {
    0x48, 0x34, 0x46, 0x77, 0x77, 0x62, 0x78, 0x2F, 0x37, 0x62, 0x34, 0x79, 0x56, 0x4B, 0x63, 0x57,
    0x72, 0x67, 0x48, 0x6A, 0x4C, 0x74, 0x7A, 0x50, 0x37, 0x4A, 0x34, 0x38, 0x6F, 0x51, 0x63, 0x6D,
};

const static unsigned char g_sh04f_key[] = {
    0x59, 0x71, 0x47, 0x55, 0x42, 0x61, 0x54, 0x48, 0x6C, 0x4F, 0x31, 0x77, 0x59, 0x62, 0x38, 0x39,
    0x6B, 0x44, 0x7A, 0x4E, 0x61, 0x36, 0x77, 0x55, 0x4F, 0x56, 0x35, 0x5A, 0x4A, 0x30, 0x41, 0x2F,
};

const static unsigned char g_sh01g_key[] = {
    0x59, 0x71, 0x47, 0x55, 0x42, 0x61, 0x54, 0x48, 0x6C, 0x4F, 0x31, 0x77, 0x59, 0x62, 0x38, 0x39,
    0x6B, 0x44, 0x7A, 0x4E, 0x61, 0x36, 0x77, 0x55, 0x4F, 0x56, 0x35, 0x5A, 0x4A, 0x30, 0x41, 0x2F,
};

const static unsigned char g_shl23_key[] = {
    0x48, 0x34, 0x46, 0x77, 0x77, 0x62, 0x78, 0x2F, 0x37, 0x62, 0x34, 0x79, 0x56, 0x4B, 0x63, 0x57,
    0x72, 0x67, 0x48, 0x6A, 0x4c, 0x74, 0x7A, 0x50, 0x37, 0x4A, 0x34, 0x38, 0x6F, 0x51, 0x63, 0x6D,
};

const static unsigned char g_shl24_key[] = {
    0x36, 0x43, 0x6E, 0x35, 0x71, 0x75, 0x48, 0x4A, 0x4B, 0x30, 0x73, 0x59, 0x56, 0x4D, 0x6B, 0x4E,
    0x51, 0x4D, 0x63, 0x61, 0x61, 0x4D, 0x55, 0x6F, 0x41, 0x4A, 0x46, 0x68, 0x4E, 0x65, 0x41, 0x55,
};

const static unsigned char g_shl25_key[] = {
    0x36, 0x43, 0x6E, 0x35, 0x71, 0x75, 0x48, 0x4A, 0x4B, 0x30, 0x73, 0x59, 0x56, 0x4D, 0x6B, 0x4E,
    0x51, 0x4D, 0x63, 0x61, 0x61, 0x4D, 0x55, 0x6F, 0x41, 0x4A, 0x46, 0x68, 0x4E, 0x65, 0x41, 0x55,
};

const static unsigned char g_shv31_key[] = {
    0x32, 0x68, 0x63, 0x77, 0x61, 0x35, 0x7A, 0x71, 0x42, 0x6C, 0x39, 0x36, 0x75, 0x7A, 0x51, 0x4C,
    0x74, 0x41, 0x32, 0x6C, 0x66, 0x79, 0x54, 0x62, 0x30, 0x69, 0x2B, 0x41, 0x65, 0x2F, 0x76, 0x48,
};

const static unsigned char g_shf31_key[] = {
    0x32, 0x6B, 0x45, 0x31, 0x37, 0x47, 0x34, 0x6B, 0x42, 0x2B, 0x6A, 0x48, 0x4D, 0x77, 0x4D, 0x75,
    0x6F, 0x33, 0x6A, 0x59, 0x35, 0x4C, 0x43, 0x54, 0x55, 0x49, 0x78, 0x46, 0x54, 0x74, 0x4F, 0x32,
};

const static unsigned char g_sht21_key[] = {
    0x42, 0x62, 0x7A, 0x4B, 0x76, 0x4A, 0x76, 0x64, 0x65, 0x4B, 0x57, 0x65, 0x79, 0x4E, 0x52, 0x4C,
    0x76, 0x33, 0x77, 0x4E, 0x6A, 0x45, 0x71, 0x65, 0x68, 0x32, 0x42, 0x47, 0x4E, 0x38, 0x76, 0x70,
};

const static struct fldr_device_info g_devices[] = {
    { .name = { 'P', 'A', '2', '1', }, .model = "302SH",  .key = g_302sh_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'P', 'A', '2', '3', }, .model = "303SH",  .key = g_303sh_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'P', 'A', '2', '4', }, .model = "304SH",  .key = g_304sh_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'P', 'B', '2', '5', }, .model = "306SH",  .key = g_306sh_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'D', 'L', '4', '0', }, .model = "SH-01F", .key = g_sh01f_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'D', 'L', '5', '0', }, .model = "SH-04F", .key = g_sh04f_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'D', 'L', '6', '0', }, .model = "SH-01G", .key = g_sh01g_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'A', 'S', '9', '7', }, .model = "SHL23",  .key = g_shl23_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'A', 'S', '8', '7', }, .model = "SHL24",  .key = g_shl24_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'A', 'S', '9', '9', }, .model = "SHL25",  .key = g_shl25_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'A', 'L', '1', '5', }, .model = "SHV31",  .key = g_shv31_key, .machine = EM_ARM, .entry = 0x50, },
    { .name = { 'G', 'P', '4',      }, .model = "SHT21",  .key = g_sht21_key, .machine = EM_ARM, .entry = 0x28, },
};

/*
int check_model(char *a)
{
    return memcmp(a, "DL50", 4);
}

static int func1(int a, int b, int *c)
{
    char data[12];
    char buff[4];
    int n;

    sprintf(data, "%04u", a);
    n = log40(a);
    if (n >= 4) {
        buff[0] = data[n - 4] ^ *((char *) &b + 0);
        buff[1] = data[n - 3] ^ *((char *) &b + 1);
        buff[2] = data[n - 2] ^ *((char *) &b + 2);
        buff[3] = data[n - 1] ^ *((char *) &b + 3);
    } else {
        buff[0] = data[0] ^ *((char *) &b + 0);
        buff[1] = data[1] ^ *((char *) &b + 1);
        buff[2] = data[2] ^ *((char *) &b + 2);
        buff[3] = data[3] ^ *((char *) &b + 3);
    }
    return memcmp(buff, c, 4);
}

static int func2(int a, int b, int *c)
{
    char data[12];
    char *buff = (char *) c;
    int n;

    sprintf(data, "%04u", a);
    n = log40(a);
    if (n >= 4) {
        buff[0] = data[n - 4] ^ *((char *) &b + 0);
        buff[1] = data[n - 3] ^ *((char *) &b + 1);
        buff[2] = data[n - 2] ^ *((char *) &b + 2);
        buff[3] = data[n - 1] ^ *((char *) &b + 3);
    } else {
        buff[0] = data[0] ^ *((char *) &b + 0);
        buff[1] = data[1] ^ *((char *) &b + 1);
        buff[2] = data[2] ^ *((char *) &b + 2);
        buff[3] = data[3] ^ *((char *) &b + 3);
    }
}

// d1 = off + 544
// d2 = off + 512, 24
// nm = DL50\0\0\0\0\0\0
int check_info(int *d1, int *d2, int *nm)
{
    int var1[15];
    int var2[15];
    int rc, i;

    for (i = 1; i < 16; i++) {
        rc = func1(d2[0] * d2[5] * i, d1[8 * i + 0], nm);
        if (rc)
            return 2;
        rc = func1(d2[2] * d2[5] * i, d1[8 * i + 1], nm + 1);
        if (rc)
            return 2;
        func2(d2[1] * d2[5] * i, d1[8 * i + 6], var1 + i - 1);
        func2(d2[3] * d2[5] * i, d1[8 * i + 7], var2 + i - 1);
    }
    for (i = 1; i < 15; i++) {
        if (memcmp(var1, var1 + i, 4))
            return 1;
        if (memcmp(var2, var2 + i, 4))
            return 1;
    }

    return 0;
}

// after 2k offset
int check_nkb(char *d, int s)
{
    int i;
    int n = s >> 10;

    for (i = 2; i < n; i++) {
        if (d[i *1024] != d[i * 1022])
            return 1;
    }

    return 0;
}

int fixup_nkb(char *data, int size)
{
    int i, n, tail, nk, left;

    n = 0;
    tail = size - 4;
    memset(data + size - 4, 0xFF, 4);
    nk = tail / 1024;
    left = tail & 1023;
    for (i = nk; i >= 2; i--) {
        if (i == nb && left) {
            n = left - 1;
            memcpy(data + i * 1024, data + i * 1024 + 1, n);
            tail -= 1;
        } else {
            n += 1023;
            memcpy(data + i * 1024, data + i * 1024 + 1, n);
            tail -= 1;
        }
    }
    memcpy(data + 512, data + 1024, tail + 1024);
    return tail - 512;
}
*/

static int file_read(const char *path, unsigned char **data, size_t *size)
{
    int rc, fd;
    struct stat fs;
    size_t nbrd;

    rc = stat(path, &fs);
    if (rc)
        return rc;
    *size = fs.st_size;
    *data = malloc(fs.st_size);
    if (*data == NULL)
        return -1;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        free(*data);
        *data = NULL;
        return -1;
    }
    nbrd = 0;
    while (nbrd < fs.st_size) {
        int tmp;

        tmp = read(fd, *data + nbrd, fs.st_size - nbrd);
        if (tmp < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        nbrd += tmp;
    }
    close(fd);
    if (nbrd < fs.st_size) {
        free(*data);
        *data = NULL;
        return -1;
    }

    return 0;
}

static int file_write(const char *path, const unsigned char *data, size_t size)
{
    int fd;
    size_t nbwr;

    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    nbwr = 0;
    while (nbwr < size) {
        int tmp;

        tmp = write(fd, data + nbwr, size - nbwr);
        if (tmp < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        nbwr += tmp;
    }
    close(fd);

    return nbwr == size ? 0 : -1;
}

static uint32_t fldr_sum(void *data, size_t size)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i < size; i += 4)
        sum += *((uint32_t *)(data + i));

    return sum;
}

/* C6.2.24 */
static uint32_t aarch64_encode_b(unsigned long from, unsigned long to)
{
    int64_t offset;

    offset = (signed) to - (signed) from;
    if (offset < 0x10000000 &&
        offset >= -0x10000000) {
        return 0x14000000u | ((offset & 0x0fffffff) >> 2);
    }
    return 0xdeadbeefu;
}

/* A8.8.18 */
static uint32_t arm_encode_b(unsigned long from, unsigned long to)
{
    int64_t offset;

    offset = (signed) to - (signed) from - 8;
    if (offset < 0x00800000 &&
        offset >= -0x00800000) {
        return 0xea000000u | ((offset >> 2) & 0x00ffffff);
    }
    return 0xdeadbeefu;    
}

static uint32_t fldr_jump(int machine, unsigned long from, unsigned long to)
{
    switch (machine)
    {
    case EM_AARCH64:
        return aarch64_encode_b(from, to);
    case EM_ARM:
        return arm_encode_b(from, to);
    default:
        return -1;
    }
    return -1;
}

static int mkfloader(const unsigned char *data, size_t size,
        const struct fldr_device_info *device, unsigned char *iv,
        unsigned char **out_data, size_t *out_size)
{
    int i;
    int nkb;
    size_t actual_size;
    size_t nbtr;
    unsigned char *buff;
    uint32_t sum;
    struct aes_key_st key;

    /*
     * data:
     *   IV: 16 bytes
     *   AESed Data(
     *    data:
     *     data:
     *      info: offset 0x200,24
     *                   0x220,240
     *      name: offset 0x400,8(DL50, etc)
     *      ...
     *      code(with nkb): offset 0x800
     *     sum: 4
     *     padding: 16(=0xffffffff) if sum == -1
     *    sum: 4
     *   )
     */
    actual_size = size;
    // nkb
    nkb = 2 + actual_size / 1024;
    // every KB has one byte hole
    size += nkb;
    size = ROUND_UP(size, 0x10);
    // IV + head + AESed data + tail, tail will be explained bellow
    *out_size = 0x10 + 0x800 + size + 0x10;
    *out_data = calloc(1, *out_size);
    if (!*out_data)
        return -1;
    // IV
    buff = *out_data;
    for (i = 0; i < 16; i++)
        buff[i] = g_sec_msk[i] ^ iv[i];
    // AESed DATA
    buff = *out_data + 0x10;
    // head: jump to + 0x800, to simplify our customized loader
    *((uint32_t *)(buff + device->entry)) = fldr_jump(device->machine, device->entry, 0x800);
    // head: name
    memcpy(buff + 0x400, device->name, 4);
    // head: + 0x200, swap 6 dword, using all same value to simplify check
    memset(buff + 0x200, 0, 24);
    // head: this satisfies check_info()
    for (i = 0; i < 15; i++) {
        *((uint32_t *)(buff + 0x220 + i * 32)) = ((uint32_t) 0x30303030) ^ *((uint32_t *)(buff + 0x400));
        *((uint32_t *)(buff + 0x224 + i * 32)) = ((uint32_t) 0x30303030) ^ *((uint32_t *)(buff + 0x404));
        *((uint32_t *)(buff + 0x238 + i * 32)) = (uint32_t) 0x69776574;
        *((uint32_t *)(buff + 0x23C + i * 32)) = (uint32_t) 0x65766F6C;
    }
    // nkb
    nbtr = 0;
    for (i = 2; i <= nkb; i++) {
        if (i == nkb) {
            size_t n = actual_size - nbtr;

            if (n) {
                memcpy(buff + i * 1024 + 1, data + nbtr, n);
                nbtr += n;
            }
        } else {
            memcpy(buff + i * 1024 + 1, data + nbtr, 1023);
            nbtr += 1023;
        }
    }
    for (i = nkb; i >= 2; i--)
        buff[i * 1024] = buff[i * 1022];
    // tail: floader requires that last dword != -1
    //       and considering that AES block size is 16 bytes,
    //       so construct last 16 bytes in this way.
    sum = fldr_sum(buff, 0x800 + size + 8);
    if (sum == (uint32_t) 0xffffffff)
        *((uint32_t *)(buff + 0x800 + size + 4)) = (uint32_t) 0x12345679;
    *((uint32_t *)(buff + 0x800 + size + 8)) = fldr_sum(buff, 0x800 + size + 8);
    *((uint32_t *)(buff + 0x800 + size + 12)) = fldr_sum(buff, 0x800 + size + 12);
    // AES
    AES_set_encrypt_key(device->key, 256, &key);
    AES_cbc_encrypt((const unsigned char *) buff, buff, 0x800 + size + 0x10, &key, iv, AES_ENCRYPT);
    return 0;
}

int main(int argc, char *argv[])
{
    int ret = -1;
    int rc;
    size_t i;
    char ch;
    char *device = NULL;
    char *ifile = NULL, *ofile = NULL;
    size_t isize = 0, osize = 0;
    unsigned char *idata = NULL, *odata = NULL;
    unsigned char iv[16] = { 0 };
    const struct fldr_device_info *info = NULL;

    while ((ch = getopt(argc, argv, "hd:i:o:v:")) != -1) {
        switch (ch) {
        case 'd': {
            device = optarg;
            break;
        }
        case 'i': {
            ifile = optarg;
            break;
        }
        case 'o': {
            ofile = optarg;
            break;
        }
        case 'v': {
            int len;
            unsigned char digit;

            len = strlen(optarg);
            if (len != 32)
                goto fail_usage;
            for (i = 0; i < len; i++) {
                digit = optarg[i];
                if (digit >= '0' && digit <= '9')
                    digit -= '0';
                else if (digit >= 'A' && digit <= 'F')
                    digit -= ('A' - 10);
                else if (digit >= 'a' && digit <= 'f')
                    digit -= ('a' - 10);
                else
                    goto fail_usage;
                iv[i / 2] <<= 4;
                iv[i / 2] |= digit;
            }
            break;
        }
        case 'h':
        default: {
fail_usage:
            fprintf(stderr, "Usage:\n%s -d <device> -i <ifile> -o <ofile> [-v <ivec>]\n", argv[0]);
            return ret;
        }
        }
    }
    if (device == NULL ||
        ifile == NULL || ofile == NULL) {
        goto fail_usage;
    }
    for (i = 0; i < NELEM(g_devices); i++) {
        info = &g_devices[i];
        if (!strcasecmp(device, info->model) ||
            !strcasecmp(device, info->name)) {
            break;
        }
    }
    if (i == NELEM(g_devices))
        goto fail_usage;
    rc = file_read(ifile, &idata, &isize);
    if (rc || !idata || !isize)
        goto fail_file_read;
    rc = mkfloader(idata, isize, info, iv, &odata, &osize);
    if (rc)
        goto fail_mkfloader;
    rc = file_write(ofile, odata, osize);
    if (rc)
        goto fail_file_write;
    ret = 0;
fail_file_write:
    if (odata && osize)
        free(odata);
fail_mkfloader:
    if (idata && isize)
        free(idata);
fail_file_read:
    return ret;
}
