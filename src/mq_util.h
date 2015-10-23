/*
*  Copyright (c) 2013 UCWeb Inc.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation.
* You may obtain a copy of the License at
*
*       http://www.gnu.org/licenses/gpl-2.0.html
*
* Email: osucmq@ucweb.com
* Author: ShaneYuan
*/

#ifndef  __MQ_UTIL_H__
#define  __MQ_UTIL_H__
#ifdef __cplusplus
extern "C" 
{
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/types.h>
#include <pthread.h>

#include "log.h"
#include "file.h"
#include "uthash.h"

////////////////////////////////////////////////////////////////////////////////

#define MAX_DB_FILE_SIZE                 g_mq_conf.db_file_max_size * 1024 * 1024  /* DB file size */
#define MAX_DB_FILE_SIZE_LIMIT           64    /* DB file size limit, can't big than 64MB */
#define DB_FILE_HEAD_LEN                 128   /* db file head length */
#define DB_FILE_HEAD_OF_COUNT_LEN        12    /* number of count in db file head */
#define DB_FILE_HEAD_OF_VERSION_LEN      1     /* version length of db file */
#define DB_FILE_VERSION                  1     /* version of db file */

#define MAX_FULL_FILE_NAME_LEN           256   /* absolute path limit length */
#define MAX_DATA_PATH_NAME_LEN           128   /* DB file path limit length */ //db 文件路径长度限制
#define MAX_DATA_FILE_NAME_LEN           128   /* DB file name limit length */

/* Length of the message head */
#define MSG_HEAD_OF_ONE_MAGIC_NUM_LEN    1     /* magic number length */
#define MSG_HEAD_OF_CRC16_LEN            2     /* message crc16 length */
#define MSG_HEAD_OF_DELAY_LEN            4     /* message delay length */
#define MSG_HEAD_OF_MSGLEN_LEN           4     /* message length */
#define MSG_HEAD_LEN                     12    /* message head length */

#define MSG_HEAD_OF_FIRST_MAGIC_NUM      0xFE  /* first magic code */
#define MSG_HEAD_OF_SECOND_MAGIC_NUM     0xAC  /* second magic code */

////////////////////////////////////////////////////////////////////////////////
//保存文件内存映射之后的一些相关信息
typedef struct mq_db_map
{
    int            fd;          //文件的fd
    int            stat;
    int            flag;          /* is mmap flag */
    char           *map_mem;    //内存映射之后的地址
    uint32_t       pos;         //当前要写的位置
    uint32_t       opt_count;   //当前文件写消息的次数
    uint64_t       cur_index;   //当前第几个文件(一个文件写満之后会再次创建一个新的文件)
}mq_db_map_t;

//队列
typedef struct mq_queue
{
    char           qname[32 + 1];  /* queue name */
    int            rtag_fd;        /* rtag file fd */

    int            wtag_fd;        /* rtag file fd */
    
    int            sync_intv;      /* sync inteval */       //同步间隔, 默认存入多少条消息同步到硬盘上一次，默认情况下是１０条
    uint32_t       maxque;         /* mas queue items */    //当maxque为０时说明队列不限制元素的个数,不为０时则限制元素的个数
    uint64_t       put_num;        /* put msg number */
    uint64_t       get_num;        /* get msg number */ 
    mq_db_map_t    cur_rdb;        /* current read db */
    mq_db_map_t    cur_wdb;        /* current write db */

    pthread_mutex_t mutex;
}mq_queue_t;

typedef struct mq_queue_list
{
    char qname[32 + 1];            /* key */
    mq_queue_t mq_queue;           /* node of hash table */
    UT_hash_handle hh;             /* makes this structure hashable */
}mq_queue_list_t;

typedef struct queue_file
{
    char           rtag_fname[64 + 1];   /* rtag file name */
    char           wtag_fname[64 + 1];   /* rtag file name */
    char           read_fname[64 + 1];   /* read file name */
    char           write_fname[64 + 1];  /* write file name */
    uint64_t       rtag_fid;             /* cur rtag file index */
    uint64_t       wtag_fid;             /* cur rtag file index */
    uint64_t       read_fid;             /* cur read file index */
    uint64_t       write_fid;            /* cur write file index */
}queue_file_t;

//向文件中写消息时是以msg_item_t为单位写入和读取的
//消息中分为两部分，一部分是消息头１２个字节，另外一部分就是消息体，消息体的长度在消息头中说明
typedef struct msg_item
{
    char           magic_num1;     /* magic number */
    char           magic_num2;     /* magic number */
    uint32_t       delay;          /* message delay */  //消息延迟时间，取出的时间减去存入时的时间
    uint16_t       crc16;          /* message body crc16 */ 
    uint32_t       len;            /* message body len */
    char           *msg;           /* message message boby */
}msg_item_t;

////////////////////////////////////////////////////////////////////////////////

int min(int a, int b); 
int max(int a, int b);

////////////////////////////////////////////////////////////////////////////////

int  get_page_size(void);
int  get_cur_timestamp(void);
int  get_storage_free(const char* path);
int  get_file_size(const char* path);
bool extend_file_size(const int fd, off_t length);
int  read_file(char* buffer, int size, const char* path);
void delete_file(const char *path);
long long int str_to_ll(const char* str);

int  is_num_str(const char *s);
bool is_dir(const char *path);
bool is_file(const char *path);
bool is_special_dir(const char *path);

////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif
#endif /* __MQ_UTIL_H__ */
