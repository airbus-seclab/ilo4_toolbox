#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CHUNK_SIZE 0x1000

typedef struct _COMPRESS_CTX {
    int opcode;
    int tmp;
    unsigned char *outbuff;
    unsigned int remaining;
    unsigned int output_size;
    unsigned int f14;
} COMPRESS_CTX;

void decompress_init(COMPRESS_CTX *ctx, unsigned char *outbuff, unsigned int remaining) {
    ctx->tmp = 0;
    ctx->outbuff = outbuff;
    ctx->remaining = remaining;
    ctx->output_size = 0;
    ctx->opcode = 3;
}

int decompress(COMPRESS_CTX *ctx, unsigned char *chunk, unsigned int chunk_size) {
    unsigned int remaining = ctx->remaining;
    unsigned int backward_size;
    int offset;
    unsigned int peek_bytes;
    unsigned char bbb;
    while(chunk_size) {
        switch(ctx->opcode) {
            case 0:
                if(ctx->tmp & 0xff) {
                    if((ctx->tmp & 0x8000) == 0) {
                        if(chunk_size > 1)
                            ctx->opcode = 2;
                        else
                            ctx->opcode = 4;
                    }
                    else {
                        ctx->opcode = 1;
                    }
                    ctx->tmp <<= 1;
                }
                else {
                    ctx->opcode = 3;
                }
                break;
            case 1:
                bbb = *(chunk++);
                *(ctx->outbuff++) = bbb;
                chunk_size--;
                ctx->remaining--;
                ctx->output_size++;
                goto END_LOOP;
                break;
            case 2:
                remaining = *(chunk++);
                chunk_size--;
                goto PEEK_BYTES;
                break;
            case 3:
                ctx->tmp = (*(chunk++) << 8) | 0xff;
                chunk_size--;
                ctx->opcode = 0;
                break;
            case 4:
                ctx->f14 = *(chunk++);
                chunk_size--;
                ctx->opcode = 5;
                break;
            case 5:
                remaining = ctx->f14;
                ctx->opcode = 6;
                break;
            case 6:
PEEK_BYTES:

                backward_size = *(chunk++) | ((remaining << 8) & 0xFFF);
                peek_bytes = ((remaining >> 4)+3);
                if( ctx->remaining < peek_bytes) {
                    return 0x40;
                }
                chunk_size--;
                ctx->remaining -= peek_bytes;
                offset = backward_size + 1;
                do {
                    unsigned char read_byte = 0;
                    if(ctx->output_size >= offset) {
                        read_byte = (ctx->outbuff)[-offset];
                    }
                    *(ctx->outbuff++) = read_byte;
                    ctx->output_size++;
                    peek_bytes--;
                } while(peek_bytes);
END_LOOP:
                ctx->opcode = 0;
                if( !ctx->remaining)
                    return 2;
                break;
            default:
                return 0xff;
                break;
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {
    int fd, fdout;
    char *inbuff;
    char *outbuff;
    char *chunk;
    int csize;
    int dsize;
    COMPRESS_CTX ctx;
    int chunk_size;
    int res;

    if(argc < 4) {
        printf("usage: %s <compressed file> <final size> <output file>\n", argv[0]);
        exit(1);
    }

    fd = open(argv[1], O_RDONLY);
    if(fd == -1) {
        perror("open");
        exit(1);
    }

    dsize = atoi(argv[2]);

    csize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    inbuff = malloc(csize);
    outbuff = malloc(dsize);
    chunk = malloc(CHUNK_SIZE);

    decompress_init(&ctx, outbuff, dsize);

    while(csize) {

        if(csize > CHUNK_SIZE)
            chunk_size = CHUNK_SIZE;
        else
            chunk_size = csize;
        csize -= chunk_size;
        read(fd, chunk, chunk_size);
        res = decompress(&ctx, chunk, chunk_size);
    }

    if(res != 2) {
        printf("Final Error: %x\n", res);
        printf("Remaining: %x\n", ctx.remaining);
        printf("Outsize: %x\n", ctx.output_size);
    }

    printf("Writing %x bytes...\n", dsize);
    fdout = open(argv[3], O_CREAT|O_TRUNC|O_WRONLY, 0644);
    while(dsize) {
        res=write(fdout, outbuff, dsize);
        dsize -= res;
    }
    close(fdout);

    return 0;
}
