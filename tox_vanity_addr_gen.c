/**
 * Tox Vanityaddress Generator
 * Copyright (C) 2020 Zoff <zoff@zoff.cc>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>

#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include <sodium/utils.h>

#include <tox/tox.h>



// ----------- version -----------
// ----------- version -----------
#define VERSION_MAJOR 0
#define VERSION_MINOR 99
#define VERSION_PATCH 0
static const char global_version_string[] = "0.99.0";
// ----------- version -----------
// ----------- version -----------

#define CURRENT_LOG_LEVEL 9 // 0 -> error, 1 -> warn, 2 -> info, 9 -> debug

#define CLEAR(x) memset(&(x), 0, sizeof(x))
#define c_sleep(x) usleep(1000*x)


const char *log_filename = "tox_vanity_addr_gen.log";
FILE *logfile = NULL;
int found_global = 0;


void dbg(int level, const char *fmt, ...)
{
    char *level_and_format = NULL;
    char *fmt_copy = NULL;

    if (fmt == NULL)
    {
        return;
    }

    if (strlen(fmt) < 1)
    {
        return;
    }

    if (!logfile)
    {
        return;
    }

    if ((level < 0) || (level > 9))
    {
        level = 0;
    }

    level_and_format = malloc(strlen(fmt) + 3);

    if (!level_and_format)
    {
        // fprintf(stderr, "free:000a\n");
        return;
    }

    fmt_copy = level_and_format + 2;
    strcpy(fmt_copy, fmt);
    level_and_format[1] = ':';

    if (level == 0)
    {
        level_and_format[0] = 'E';
    }
    else if (level == 1)
    {
        level_and_format[0] = 'W';
    }
    else if (level == 2)
    {
        level_and_format[0] = 'I';
    }
    else
    {
        level_and_format[0] = 'D';
    }

    if (level <= CURRENT_LOG_LEVEL)
    {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(logfile, level_and_format, ap);
        va_end(ap);
    }

    // fprintf(stderr, "free:001\n");
    if (level_and_format)
    {
        // fprintf(stderr, "free:001.a\n");
        free(level_and_format);
    }

    // fprintf(stderr, "free:002\n");
}

void get_my_toxid(Tox *tox, char *toxid_str)
{
    uint8_t *tox_id_bin = calloc(1, TOX_ADDRESS_SIZE);
    tox_self_get_address(tox, tox_id_bin);
    char *tox_id_hex_local = calloc(1, TOX_ADDRESS_SIZE * 2 + 1);
    sodium_bin2hex(tox_id_hex_local, (TOX_ADDRESS_SIZE * 2 + 1), tox_id_bin, TOX_ADDRESS_SIZE);

    for (size_t i = 0; i < (TOX_ADDRESS_SIZE * 2); i ++)
    {
        tox_id_hex_local[i] = toupper(tox_id_hex_local[i]);
    }

    snprintf(toxid_str, (size_t)(TOX_ADDRESS_SIZE * 2 + 1), "%s", (const char *)tox_id_hex_local);
}

void print_tox_id(char *tox_id_hex)
{
    fprintf(stderr, "-> %s\n", tox_id_hex);
}

int check_if_found(Tox *tox, char *wanted_address_string)
{
    char *tox_id_hex = (char *)calloc(1, TOX_ADDRESS_SIZE * 2 + 1);
    get_my_toxid(tox, tox_id_hex);

    // print_tox_id(tox_id_hex);
    // fprintf(stderr, "%s -- %s\n", tox_id_hex, wanted_address_string);

    if (strncmp(tox_id_hex, wanted_address_string, strlen(wanted_address_string)) == 0)
    {
        // fprintf(stderr, "** FOUND **\n");
        return 1;
    }
    else
    {
        return 0;
    }
}

time_t get_unix_time(void)
{
    return time(NULL);
}

void yieldcpu(uint32_t ms)
{
    usleep(1000 * ms);
}

void sigint_handler(int signo)
{
    if (signo == SIGINT)
    {
        printf("received SIGINT, pid=%d\n", getpid());
    }
}

void update_savedata_file(const Tox *tox, char *savedata_filename)
{
    size_t size = tox_get_savedata_size(tox);
    char *savedata = calloc(1, size);
    tox_get_savedata(tox, (uint8_t *)savedata);
    FILE *f = fopen(savedata_filename, "wb");
    fwrite(savedata, size, 1, f);
    fclose(f);
    free(savedata);
}

void *thread_find_address(void *data)
{
    char *wanted_address_string = (char *) data;
    pthread_t id = pthread_self();

    Tox *tox = NULL;
    struct Tox_Options options;
    uint64_t addr_per_sec_counter = 0;
    uint32_t seconds = (uint32_t)get_unix_time();
    int found = 0;
    while (found == 0)
    {
        tox_options_default(&options);
        tox = tox_new(&options, NULL);

        if (tox)
        {
            addr_per_sec_counter++;
            
            if (((uint32_t)get_unix_time() - seconds) >= 10)
            {
                fprintf(stderr, "Addresses per second: %d thread:%d\n",
                    (int32_t)( addr_per_sec_counter / ((uint32_t)get_unix_time() - seconds) ),
                    (uint32_t)id);
                seconds = (uint32_t)get_unix_time();
                addr_per_sec_counter = 0;
            }
            
            if (found_global == 0)
            {
                found = check_if_found(tox, wanted_address_string);
            
                if (found == 1)
                {
                    found_global = 1;
                    char *tox_id_hex = calloc(1, TOX_ADDRESS_SIZE * 2 + 1);
                    get_my_toxid(tox, tox_id_hex);
                    char *save_file_str = calloc(1, 1000);
                    snprintf(save_file_str, 1000, "toxsave_%s.dat", tox_id_hex);
                    update_savedata_file(tox, save_file_str);
                }
                
            }
            else
            {
                found = 1;
            }

            tox_kill(tox);
            tox = NULL;
        }
    }
    
    found_global = 1;

    return NULL;
}


int main(int argc, char *argv[])
{
    logfile = fopen(log_filename, "wb");
    setvbuf(logfile, NULL, _IONBF, 0);

    int cpu_cores = 1;
    int wanted_threads = -1;
    char *wanted_address_string = NULL;

    int opt;
    const char     *short_opt = "hva:t:";
    struct option   long_opt[] =
    {
        {"help",          no_argument,       NULL, 'h'},
        {"version",       no_argument,       NULL, 'v'},
        {NULL,            0,                 NULL,  0 }
    };

    while ((opt = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1)
    {
        switch (opt)
        {
            case -1:       /* no more arguments */
            case 0:        /* long options toggles */
                break;

            case 'a':
                wanted_address_string = calloc(1, 400);
                snprintf(wanted_address_string, 399, "%s", optarg);
                dbg(3, "Wanted Vanity Address: %s\n", wanted_address_string);
                break;

            case 't':
                wanted_threads = (uint32_t)atoi(optarg);
                dbg(3, "Using %d Threads\n", (int)wanted_threads);
                break;

            case 'v':
                printf("Version: %s\n", global_version_string);

                if (logfile)
                {
                    fclose(logfile);
                    logfile = NULL;
                }

                return (0);

            case 'h':
                printf("Usage: %s [OPTIONS]\n", argv[0]);
                printf("  -v, --version                        show version\n");
                printf("  -h, --help                           print this help and exit\n");
                printf("\n");

                if (logfile)
                {
                    fclose(logfile);
                    logfile = NULL;
                }

                return (0);

            case '?':
                fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);

                if (logfile)
                {
                    fclose(logfile);
                    logfile = NULL;
                }

                return (-2);

            default:
                fprintf(stderr, "%s: invalid option -- %c\n", argv[0], opt);
                fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);

                if (logfile)
                {
                    fclose(logfile);
                    logfile = NULL;
                }

                return (-2);
        }
    }

    cpu_cores = get_nprocs();
    dbg(9, "detected %d processors\n", cpu_cores);

    if (wanted_threads == -1)
    {
        wanted_threads = cpu_cores;
    }

    if (!wanted_address_string)
    {
        dbg(9, "No address given\n");
        fprintf(stderr, "No address given\n");
        if (logfile)
        {
            fclose(logfile);
            logfile = NULL;
        }

        return (-2);
    }

    if (strlen(wanted_address_string) < 1)
    {
        dbg(9, "No address given\n");
        fprintf(stderr, "No address given\n");
        if (logfile)
        {
            fclose(logfile);
            logfile = NULL;
        }

        return (-2);
    }


    found_global = 0;

    pthread_t tid[wanted_threads];

    int c = 0;
    for(c=0;c < wanted_threads;c++)
    {
        if (pthread_create(&(tid[c]), NULL, thread_find_address, (void *)wanted_address_string) != 0)
        {
            dbg(0, "Thread %d create failed\n", c);
        }
        else
        {
            pthread_setname_np(tid[c], "t_vanity");
            dbg(2, "Thread %d successfully created\n", c);
        }
    }

    while (found_global == 0)
    {
        yieldcpu(100);
    }




    if (wanted_address_string)
    {
        free(wanted_address_string);
    }

    if (logfile)
    {
        fclose(logfile);
        logfile = NULL;
    }

    return 0;
}

