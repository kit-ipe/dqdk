#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/mman.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>
#include <net/if.h>
#include <errno.h>

#include "dlog.h"
#include "ctypes.h"
#include "dqdk-sys.h"

char* sys_read_string(const char* path)
{
    char* buffer = calloc(1, STRING_BUFFER);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        dlog_error2("open", fd);
    }

    int ret = read(fd, buffer, STRING_BUFFER);
    if (ret < 0) {
        dlog_error2("read", ret);
    }

    close(fd);
    return buffer;
}

int sys_read_uint(const char* path)
{
    char buffer[INT_BUFFER] = { 0 };
    int ret = -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        puts(path);
        dlog_error2("open", fd);
        return ret;
    }

    ret = read(fd, &buffer, INT_BUFFER);
    if (ret < 0) {
        dlog_error2("read", ret);
        goto exit;
    }

    ret = atoi(buffer);

exit:
    close(fd);
    return ret;
}

int sys_write_int(const char* path, int value)
{
    char buffer[INT_BUFFER] = { 0 };
    int ret = -1;
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        puts(path);
        dlog_error2("open", fd);
        return ret;
    }

    sprintf(buffer, "%d\n", value);
    ret = write(fd, &buffer, strlen(buffer));
    if (ret < 0) {
        dlog_error2("write", ret);
        goto exit;
    }

exit:
    close(fd);
    return ret;
}

int nic_numa_node(const char* ifname)
{
    char ifnuma[PATH_MAX] = { 0 };
    snprintf(ifnuma, PATH_MAX, "/sys/class/net/%s/device/numa_node", ifname);

    // File not exists
    if (access(ifnuma, F_OK))
        return 0;
    return sys_read_uint(ifnuma);
}

// get NUMA node huge pages
char* get_numa_hugepages_path(int numanode, page_size_t pagesz)
{
    char* path = calloc(1, PATH_MAX);
    if (pagesz == PAGE_2MB)
        sprintf(path, "/sys/devices/system/node/node%d/hugepages/hugepages-2048kB/nr_hugepages", numanode);
    else if (pagesz == PAGE_1GB)
        sprintf(path, "/sys/devices/system/node/node%d/hugepages/hugepages-1048576kB/nr_hugepages", numanode);
    else {
        free(path);
        path = NULL;
    }

    return path;
}

static int read_hugepages(const char* path)
{
    return sys_read_uint(path);
}

static int reserve_hugepages(const char* path, int nb_hugepages)
{
    int ret = sys_write_int(path, nb_hugepages);
    if (ret < 0)
        return ret;

    int new_allocated = read_hugepages(path);

    if (nb_hugepages != new_allocated)
        dlog_infov("Requested %d huge pages, Allocated %d huge pages", nb_hugepages, new_allocated);

    return new_allocated;
}

int set_hugepages(int device_numanode, int howmany, page_size_t pagesz)
{
    char* path;
    int ret;

    if (device_numanode == -1) {
        switch (pagesz) {
        case PAGE_2MB:
            return reserve_hugepages(HUGETLB_PATH_2MB, howmany);

        case PAGE_1GB:
            return reserve_hugepages(HUGETLB_PATH_1GB, howmany);

        case PAGE_4KB:
        default:
            return -1;
        }
    }

    path = get_numa_hugepages_path(device_numanode, pagesz);
    ret = reserve_hugepages(path, howmany);
    free(path);
    return ret;
}

int get_hugepages(int device_numanode, page_size_t pagesz)
{
    int ret;
    char* path;

    if (device_numanode == -1) {
        switch (pagesz) {
        case PAGE_2MB:
            return read_hugepages(HUGETLB_PATH_2MB);

        case PAGE_1GB:
            return read_hugepages(HUGETLB_PATH_1GB);

        case PAGE_4KB:
        default:
            return -1;
        }
    }

    path = get_numa_hugepages_path(device_numanode, pagesz);
    ret = read_hugepages(path);
    free(path);
    return ret;
}

dqdk_always_inline u64 clock_nsecs(clockid_t clock)
{
    struct timespec ts;
    int ret = clock_gettime(clock, &ts);
    return ret == 0 ? (ts.tv_sec * 1000000000UL + ts.tv_nsec) : BAD_CLOCK;
}

dqdk_always_inline int clock_nsleep(u64 nsecs)
{
    struct timespec ts;
    ts.tv_sec = nsecs / 1000000000;
    ts.tv_nsec = nsecs % 1000000000;
    return clock_nanosleep(CLOCK_REALTIME, 0, &ts, NULL);
}

void nic_set_irq_affinity(int irq, int cpu)
{
    char irq_file[PATH_MAX] = { 0 };
    snprintf(irq_file, PATH_MAX, "/proc/irq/%d/smp_affinity_list", irq);
    sys_write_int(irq_file, cpu);
}

interrupts_t* nic_get_interrupts(char* irqstr, u32 nprocs)
{
    char cmd[4096] = { 0 };
    char *line = NULL, *cursor = NULL;
    FILE* fp = NULL;
    u32 idx = 0, current_irq, current_interrupts = 0, procs = 0;
    size_t linesz = 0;
    interrupts_t* intrpts = (interrupts_t*)calloc(1, sizeof(interrupts_t));
    intrpts->nbirqs = nprocs;
    intrpts->interrupts = (irq_interrupts_t*)calloc(nprocs, sizeof(irq_interrupts_t));

    snprintf(cmd, 4096, "grep -P \"%s\" /proc/interrupts", irqstr);
    fp = popen(cmd, "r");

    while (getline(&line, &linesz, fp) != -1 && idx != nprocs) {
        current_irq = strtol(line, &cursor, 10);
        while (procs != nprocs) {
            while (!isdigit(cursor[0]))
                ++cursor;

            current_interrupts += strtol(cursor, &cursor, 10);
            ++procs;
        }

        intrpts->interrupts[idx].irq = current_irq;
        intrpts->interrupts[idx].interrupts = current_interrupts;

        current_interrupts = 0;
        procs = 0;
        idx++;
    }

    if (line != NULL)
        free(line);

    if (fp != NULL)
        pclose(fp);

    return intrpts;
}

int is_smt()
{
    return sys_read_uint("/sys/devices/system/cpu/smt/active");
}

int cpu_smt_sibling(int cpu)
{
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu);
    char* siblings = sys_read_string(path);
    char* sibling;
    int isibling = -1;

    while ((sibling = strtok(siblings, ",")) != NULL) {
        if (atoi(sibling) != cpu) {
            isibling = atoi(sibling);
            goto exit;
        }
        siblings = NULL;
    }

exit:
    free(siblings);
    return isibling;
}

int dqdk_get_link_speed(const char* iface)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -1;

    struct ifreq ifr;
    struct ethtool_cmd edata = { 0 };

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    ifr.ifr_data = (caddr_t)&edata;

    edata.cmd = ETHTOOL_GSET;

    if (ioctl(sockfd, SIOCETHTOOL, &ifr) == -1) {
        close(sockfd);
        return -1;
    }

    close(sockfd);

    return (edata.speed_hi << 16) | edata.speed;
}

struct tm* getlocaltime(void)
{
    static struct tm zerotm = { .tm_year = 0, .tm_mon = -1, .tm_mday = 0, .tm_hour = 0, .tm_min = 0 };
    time_t tval = time(NULL);

    if (tval == ((time_t)-1))
        return &zerotm;

    return localtime(&tval);
}
