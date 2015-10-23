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

#include <sys/statfs.h>
#include "mq_util.h"

////////////////////////////////////////////////////////////////////////////////

inline int min(int a, int b) {return (a >= b) ? b : a;}
inline int max(int a, int b) {return (a < b) ? b : a;}

////////////////////////////////////////////////////////////////////////////////

/* Get free disk space from data path */
int get_storage_free(const char* path)
{
    int         free_gb;
    uint64_t    free_byte;
    struct      statfs buf;

    statfs(path, &buf);
    free_byte = buf.f_bavail * buf.f_bsize;
    free_gb = free_byte / (1024 * 1024 * 1024);

    return free_gb;
}

/* Extend file size by specify length */
/*
 *函 数:extend_file_size
 *功 能:扩展文件的大小
 */
bool extend_file_size(const int fd, off_t length)
{  
    int    offset;
    int    file_size;    

    file_size = length;
    if (file_size < 0)
    {   
        log_debug("Resize file fail, invalid specify size");
        return false;
    }   

    if (ftruncate(fd, file_size) < 0)	//将fd指向的文件大小改为file_size
    {
        log_info("Fturncate file fail ,errno [%d] error message[%s]", 
                errno, strerror(errno));
    }

    offset = lseek(fd, -1, SEEK_END);
    if (offset < 0)  
    {        
        log_info("Resize file fail ,errno [%d] error message[%s]", 
                errno, strerror(errno));
        return false;
    }    

    write(fd, "0x00", 1); 
    return true;
}

int get_file_size(const char *path)
{  
    int    file_size = -1;      
    struct stat statbuff;  

    if(stat(path, &statbuff) < 0)
    {  
        return file_size;  
    } 
    else
    {  
        file_size = statbuff.st_size;  
        return file_size;  
    }  
}

/*
 *函 数:get_page_size
 *功 能:得到内存页的大小
 */
int get_page_size()
{
    int    pagesize;
    pagesize = getpagesize();
    return pagesize;
}

int get_cur_timestamp() 
{
    int    time_stemp;
    struct timeval tv; 

    gettimeofday(&tv, NULL);
    time_stemp = (int)tv.tv_sec; 
    return time_stemp;
}

/*
 * 函 数:read_file
 * 功 能:从path文件中读取size大小的内容到buffer中
 * 返回值:实际读取的字节数
 */
int read_file(char* buffer, int size, const char* path)
{
    int ret = -1; 
    int fd = open(path, O_RDONLY);
    if (fd == -1) 
    {   
        snprintf(buffer, size, "can not open file : %s, %d - %s",
                path, errno, strerror(errno));
    }   
    else
    {   
        ret = read(fd, buffer, size);
        close(fd);

        if (ret < 0)
        {   
            snprintf(buffer, size, "read file : \"%s\" error, %d - %s",
                    path, errno, strerror(errno));
        }   
    }   
    return ret;
}

/*
 *函 数:is_num_str
 *功 能:检查是否为数字字符串
 *参 数:
 *功 能:是返回true,不是返回false
 */
int is_num_str(const char *s)
{
    for(; *s; s++)
    {
        if(!isdigit(*s))	//检查是否为数字
        {
            break;
        }
    }
    return !*s;
}

/*
 *函 数:str_to_ll
 *功 能:字符串转换为long long 类型
 *参 数:
 *返回值:失败返回-1
 */
long long int str_to_ll(const char* str)
{
    int base = 10;
    long long int t_val;
    char *endptr;

    /* Check for various possible errors */
    if (str == NULL)
    {   
        return -1; 
    }   

    errno = 0;    /* To distinguish success/failure after call */
    t_val = strtoll(str, &endptr, base);
    if ((errno == ERANGE && (t_val == LONG_MAX || t_val == LONG_MIN))
            || (errno != 0 && t_val == 0)) 
    {   
        return -1; 
    }   
    if (endptr == str)
    {   
        return -1; 
    }   
    if (*endptr != '\0')    /* Not necessarily an error... */
    {   
        return -1; 
    }   
    /* If we got here, strtol() successfully parsed a number */
    return t_val;
}

/*
 *函 数:path
 *功 能:判断是否为文件夹
 *说 明:
 *返回值:是返回true,否返回false
 *说 明:
 */
bool is_dir(const char *path)
{
    struct stat statbuf;
    if(lstat(path, &statbuf) == 0)
    {
        return S_ISDIR(statbuf.st_mode) != 0;
    }
    return false;
}

/*
 * 函 数:is_file
 * 功 能:判断是否为文件
 */
bool is_file(const char *path)
{
    struct stat statbuf;
    if(lstat(path, &statbuf) == 0)
    {
        return S_ISREG(statbuf.st_mode) != 0;
    }
    return false;
}

/*
 *函 数:is_special_dir
 *功 能:判断path是否为后缀为'.'或'..'的特殊文件夹
 */
bool is_special_dir(const char *path)
{
    return strcmp(path, ".") == 0 || strcmp(path, "..") == 0;
}

/*
 *函 数:get_file_path
 *功 能:得到文件的绝对路径
 *参 数:path 文件的路径，file_name文件的名字,file_path用来保存path和file_name结合之后的绝对路径
 *返回值:
 *说 明:
 */
void get_file_path(const char *path, const char *file_name,  char *file_path)
{
    strcpy(file_path, path);
    if(file_path[strlen(path) - 1] != '/')
        strcat(file_path, "/");
    strcat(file_path, file_name);
}

/*
 *函 数:delete_file
 *功 能:删除文件和文件夹,如果path是文件夹的话就循环删除里面的文件和文件夹
 */
void delete_file(const char *path)
{
    DIR* dir;
    char file_path[PATH_MAX];
    struct dirent *dir_info;

    if(is_file(path))
    {
        remove(path);
        return;
    }
    if(is_dir(path))
    {
        if((dir = opendir(path)) == NULL)
        {
            return;
        }
        while((dir_info = readdir(dir)) != NULL)
        {
            get_file_path(path, dir_info->d_name, file_path);
            if(is_special_dir(dir_info->d_name))
            {
                continue;
            }
            delete_file(file_path);
            rmdir(file_path);
        }
        closedir(dir);
    }
    rmdir(path);
}
