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

#include <stdio.h>
#include <inttypes.h>

#include "crc16.h"
#include "mq_util.h"
#include "mq_store_msg.h"
#include "mq_store_file.h"

/////////////////////////////////////////////////////////////////////////////////
/*
 * 函 数:mq_sm_db_parse_msg
 * 功 能:从msg指向的内存映射cur_pos处解析出一条消息保存到msg_item中
 * 返回值: msg 为空返回 MSG_CHECK_RET_MSG_ERR;
 *        当前内存已读位置　＋　MSG_HEAD_LEN 大于MAX_DB_FILE_SIZE则说明该文件已经读完，则返回MSG_CHECK_RET_LEN_BEY
 *        当前读的位置开始两个字节不是magic  code返回 MSG_CHECK_RET_MAG_NUM_ERR
 *        解析头部出错时返回  MSG_CHECK_RET_PARSE_ERR
 *        当前内存已读位置　+ MSG_HEAD_LEN + msg->len 大于MAX_DB_FILE_SIZE说明该文件已经读完，则返回  MSG_CHECK_RET_LEN_BEY
 *        crc读取错误返回 MSG_CHECK_RET_CRC_ERR
 *        正确 返回  MSG_CHECK_RET_OK
 */
int mq_sm_db_parse_msg(const char* msg, uint32_t cur_pos, msg_item_t* msg_item)
{
    uint16_t tmp_crc16;
    const char* msg_head;
    const char* msg_body;

    if (msg == NULL)
    {
        log_debug("Msg check error, Msg is NULL");
        return MSG_CHECK_RET_MSG_ERR;
    }

    /* Read end of file end, choose the next one */
    if (cur_pos + MSG_HEAD_LEN >= MAX_DB_FILE_SIZE)
    {
        log_debug("Msg check error, Message length beyond file");
        return MSG_CHECK_RET_LEN_BEY;
    }

    msg_head = msg + cur_pos;
    log_debug("Actual 1 [%02X]; Actual 2 [%02X]", msg_head[0], msg_head[1]);
    /* Find msg head, by magic nubmer */
    if(((unsigned char)msg_head[0] != MSG_HEAD_OF_FIRST_MAGIC_NUM) 
            || ((unsigned char)msg_head[1] != MSG_HEAD_OF_SECOND_MAGIC_NUM)) 
    {
        return MSG_CHECK_RET_MAG_NUM_ERR;
    }

    /* Parse mssage head */
    if(!mq_sm_db_parse_msg_head(msg_item, msg_head))
    {
        log_debug("Parse mssage head fail");
        return MSG_CHECK_RET_PARSE_ERR;
    }

    /* If read to file end pos, Choose the next one */
    if (cur_pos + msg_item->len + MSG_HEAD_LEN > MAX_DB_FILE_SIZE)
    {
        log_debug("Msg check error, Message length beyond file");
        return MSG_CHECK_RET_LEN_BEY;
    }

    /* Get msg */
    msg_body = msg_head + MSG_HEAD_LEN;
    //log_trace("Message body[%s]", asc_trace(msg_body, msg_item->len));//for test
    
    if ((mq_sm_db_build_msg_crc16(&tmp_crc16, msg_body, msg_item->len)))
    {
        log_debug("Cur msg crc[%d], dest msg crc[%d]", msg_item->crc16, tmp_crc16);
        if (msg_item->crc16 == tmp_crc16)
        {
            msg_item->msg = (char*)msg_body;
            return MSG_CHECK_RET_OK;
        }
    }
    log_info("Calculate msg's cre error");
    return MSG_CHECK_RET_CRC_ERR;
}
/*
 * 函 数:mq_sm_db_build_msg_crc16
 * 功 能:根据data　和len算出crc16校验值，保存到crc 中
 */
bool mq_sm_db_build_msg_crc16(uint16_t* crc, const char* data, int len)
{
    uint16_t tmp_crc16 = 0; 

    if (len < 0 || data == NULL || crc == NULL) 
    {
        log_debug("Build crc error, Invalid data");
        return false;
    }
    if (crc16_append(&tmp_crc16, (const void*)data, len))
    {
        *crc = tmp_crc16;
        return true;
    }
    return false;
}

/* Write DB head info to DB file */
/*
 * 函 数:mq_sm_db_write_file_head
 * 功 能:每次创建新的db文件之后，都要在新文件开始部分写一个头消息,这个头消息主要主用是用来占位的，当该文件写満之后，会再次调用该函数，在再次调用时会在头消息的占位的地方写入本文件一共写入了多少消息
 */
bool mq_sm_db_write_file_head(mq_queue_t *mq_queue)
{
    char db_file_head[DB_FILE_HEAD_LEN + 1];

    log_info("Write DB file head, Queue name [%s] index [%"PRIu64"]", 
            mq_queue->qname, mq_queue->cur_wdb.cur_index);

    memset(db_file_head, '\0', DB_FILE_HEAD_LEN);
    snprintf(db_file_head, DB_FILE_HEAD_LEN, "%01d%012"PRIu32,
            DB_FILE_VERSION, mq_queue->cur_wdb.opt_count);

    memcpy(mq_queue->cur_wdb.map_mem, db_file_head, DB_FILE_HEAD_LEN);			
    msync(mq_queue->cur_wdb.map_mem, DB_FILE_HEAD_LEN, MS_ASYNC);			

    return true;
}

/* Write mssage to DB file */
/*
 * 函 数:mq_sm_db_write_msg
 * 功 能:把msg_item消息写入到mq_queue队列中
 * 返回值:成功返回true,失败返回false
 * 
 * 步骤:1.检查文件剩余空间是否足够,如果不够则创建新的文件
 *   
 */
bool mq_sm_db_write_msg(mq_queue_t *mq_queue, msg_item_t *msg_item)
{
    char*     p;
    uint32_t  temp_write_pos;
    //1.检查文件剩余空间是否足够,如果不够则创建新的文件
    if (mq_queue->cur_wdb.pos + msg_item->len + MSG_HEAD_LEN > MAX_DB_FILE_SIZE)
    {
        log_debug("Current DB file write full; Get next DB file for write");
        /* Write current status to data file befor close it */
        //因为在文件创建时向文件写了个消息用于占位，所以在关闭文件之前会再次在文件头部点位的地方重写一条消息，记录当前文件总共写了多少条消息
        if (mq_queue->cur_wdb.map_mem != NULL){
            mq_sm_db_write_file_head(mq_queue);
        }
        
        pthread_mutex_lock(&(mq_queue->mutex));
        if (!get_next_write_file(mq_queue))
        {
            pthread_mutex_unlock(&(mq_queue->mutex));
            log_error("Get next DB file fail");
            return false;
        }
        pthread_mutex_unlock(&(mq_queue->mutex));
    }
    log_debug("Write msg begin!");
    temp_write_pos = mq_queue->cur_wdb.pos;
    p = mq_queue->cur_wdb.map_mem + temp_write_pos;

    //写入magic_num1
    memcpy(p, &(msg_item->magic_num1), MSG_HEAD_OF_ONE_MAGIC_NUM_LEN);
    p += MSG_HEAD_OF_ONE_MAGIC_NUM_LEN;
    //写入magic_num2
    memcpy(p, &(msg_item->magic_num2), MSG_HEAD_OF_ONE_MAGIC_NUM_LEN);
    p += MSG_HEAD_OF_ONE_MAGIC_NUM_LEN;
    //写入delay
    memcpy(p, &(msg_item->delay), MSG_HEAD_OF_DELAY_LEN);
    p += MSG_HEAD_OF_DELAY_LEN;
    //写入crc16
    memcpy(p, &(msg_item->crc16), MSG_HEAD_OF_CRC16_LEN);
    p += MSG_HEAD_OF_CRC16_LEN;
    //写入消息长度值
    memcpy(p, &(msg_item->len), MSG_HEAD_OF_MSGLEN_LEN);
    p += MSG_HEAD_OF_MSGLEN_LEN;
    //写入消息体
    memcpy(p, msg_item->msg, msg_item->len);
    //修改偏移指针
    mq_queue->cur_wdb.pos       += (msg_item->len + MSG_HEAD_LEN);
    //增加写入的次数
    mq_queue->cur_wdb.opt_count += 1;
    //增加写入的次数
    mq_queue->put_num           += 1;
    log_debug("Write msg seccuss!");

    return true;
}

bool mq_sm_db_parse_msg_head(msg_item_t *item, const char *msg_head)
{
    //item = (msg_item_t *)msg_head;
    const char *str;
    str = msg_head;

    memcpy(&item->magic_num1, str, MSG_HEAD_OF_ONE_MAGIC_NUM_LEN);
    str += MSG_HEAD_OF_ONE_MAGIC_NUM_LEN;
    memcpy(&item->magic_num2, str, MSG_HEAD_OF_ONE_MAGIC_NUM_LEN);
    str += MSG_HEAD_OF_ONE_MAGIC_NUM_LEN;
    memcpy(&item->delay, str, MSG_HEAD_OF_DELAY_LEN);
    str += MSG_HEAD_OF_DELAY_LEN;
    memcpy(&item->crc16, str, MSG_HEAD_OF_CRC16_LEN);
    str += MSG_HEAD_OF_CRC16_LEN;
    memcpy(&item->len, str, MSG_HEAD_OF_MSGLEN_LEN);

    log_debug("-------item magic_num1  [%02X]\n", item->magic_num1);
    log_debug("-------item magic_num2  [%02X]\n", item->magic_num2);
    log_debug("-------item delay       [%02X]\n", item->delay);
    log_debug("-------item crc         [%02X]\n", item->crc16);
    log_debug("-------item len         [%02X]\n", item->len);

    return true;
}

/* Ergodic DB file calculate mssage count */
uint32_t mq_sm_db_cal_msg_count(int fd, uint32_t end_pos)
{
    int          ret;
    int          db_count = 0;
    int          curr_file_pos = 0;
    char*        ergodic_mmap = NULL;
    msg_item_t   msg_item;


    log_debug("Ergodic data file msg count");

    ergodic_mmap = (char *)mmap(0, MAX_DB_FILE_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
    if (ergodic_mmap == MAP_FAILED)
    {
        log_info("Ergodic data file msg count error");
        return -1;
    }

    while(curr_file_pos < end_pos)
    {
        /* Get msg head, And parse it */
        ret = mq_sm_db_parse_msg(ergodic_mmap, curr_file_pos, &msg_item);
        if (ret == MSG_CHECK_RET_OK)
        {
            curr_file_pos += (MSG_HEAD_LEN + msg_item.len);
            db_count++;
            continue;
        }
        else if (ret == MSG_CHECK_RET_MAG_NUM_ERR)
        {
            curr_file_pos++;
            continue;
        }
        else if (ret == MSG_CHECK_RET_PARSE_ERR || ret == MSG_CHECK_RET_CRC_ERR)
        {
            curr_file_pos += 2; 
            continue;
        }
        else if (ret ==  MSG_CHECK_RET_MSG_ERR)
        {
            log_warn("DB file mmap is NULL");
            break;
        }
        else if (ret == MSG_CHECK_RET_LEN_BEY)
        {
            log_debug("Ergodic data file, Pos [%d] to go beyond the file", end_pos);
            curr_file_pos += 2; 
            continue;
        }
        else
        {
            curr_file_pos++; 
            continue;
        }
    }
    munmap(ergodic_mmap, MAX_DB_FILE_SIZE);
    log_debug("The DB file total msg [%d]", db_count);
    return db_count;
}
