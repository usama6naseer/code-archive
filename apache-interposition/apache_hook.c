#define _GNU_SOURCE

#include <stdint.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/fcntl.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/time.h>
#include <glib.h>

// sudo chown -R usama:www-data /tmp/
// sudo chmod -R g+s /tmp/
// sudo /usr/sbin/apachectl -k stop
// sudo LD_PRELOAD=/home/usama/apache_ldp/apache_hook.so /usr/sbin/apachectl -k start

// Global variables
pthread_t WORKER;
int WORKER_FLAG = 0;
pthread_mutex_t WORKER_MUTEX;
pthread_mutex_t CLOSED_MUTEX;
GArray *ACCEPTED_SOCKETS_LIST;
GArray *CLOSED_SOCKETS_LIST;
GHashTable *FNAME_MAP;

unsigned long hash(unsigned char *str) {
    unsigned long hash = 5381;
    int c;
    while (c = *str++) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

double current_timestamp(struct timeval te) {
    gettimeofday(&te, NULL); // get current time
    double milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // caculate milliseconds
    return milliseconds;
}

void* worker();
void* worker() {
    int cn = 0;
    struct timeval te;
    // FILE *results;
    // results = fopen("/tmp/results.txt", "a");
    while (1) {
        cn = cn + 1;
        pthread_mutex_lock(&WORKER_MUTEX);
        int num_sockets = ACCEPTED_SOCKETS_LIST->len;
        pthread_mutex_unlock(&WORKER_MUTEX);
        if (num_sockets > 0) {
            time_t t = time(NULL);
            struct tm tm = *localtime(&t);
            // printf("now: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
            int index;
            for (index=0; index<num_sockets; index=index+1) {
                pthread_mutex_lock(&WORKER_MUTEX);
                int s = g_array_index(ACCEPTED_SOCKETS_LIST, int, index);
                pthread_mutex_unlock(&WORKER_MUTEX);

                // /*
                // get IP of peer
                socklen_t len;
                struct sockaddr_storage addr;
                char ipstr[INET6_ADDRSTRLEN];
                int port;
                len = sizeof addr;
                getpeername(s, (struct sockaddr*)&addr, &len);

                // deal with both IPv4 and IPv6:
                if (addr.ss_family == AF_INET) {
                    struct sockaddr_in *s = (struct sockaddr_in *)&addr;
                    port = ntohs(s->sin_port);
                    inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
                } else { // AF_INET6
                    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
                    port = ntohs(s->sin6_port);
                    inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
                }
                // FILE* f = fopen("/tmp/worker.txt","a");
                // fprintf(f, "num : %d\n", num_sockets);
                // fclose(f);
                // */

                FILE *results;
                char ip_port[24];
                sprintf(ip_port, "%s%u", ipstr, port);
                char fname[20];
                unsigned long hash_val = hash((unsigned char *) ip_port);
                sprintf(fname, "/tmp/%lu_stt.txt", hash_val);
                results = fopen(fname, "a");
                
                // TCP_INFO
                struct tcp_info info;
                int info_length = sizeof(info);
                if ( getsockopt(s, SOL_TCP, TCP_INFO, (void *) &info, (socklen_t *) &info_length ) == 0 ) {
                    if (info.tcpi_snd_cwnd > 0) {
                        fprintf(results, "ip# %s | port# %u | time# %f | ", ipstr, port, current_timestamp(te));
                        fprintf(results, "now# %d-%d-%d %d:%d:%d | ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
                        fprintf(results, "cwnd# %u | ", info.tcpi_snd_cwnd);
                        fprintf(results, " state# %u | ", info.tcpi_state);
                        fprintf(results, " rtt# %u | ", info.tcpi_rtt);
                        fprintf(results, " sacked# %u | ", info.tcpi_sacked);
                        fprintf(results, " unacked# %u | ", info.tcpi_unacked);
                        fprintf(results, " ssthresh# %u | ", info.tcpi_snd_ssthresh);
                        fprintf(results, " send_mss# %u | ", info.tcpi_snd_mss);
                        fprintf(results, " retransmits# %u | ", info.tcpi_retransmits);
                        fprintf(results, " lost# %u | ", info.tcpi_lost);
                        fprintf(results, " tcpi_last_data_sent# %u | ", info.tcpi_last_data_sent);
                        fprintf(results, " tcpi_last_ack_recv# %u | ", info.tcpi_last_ack_recv);
                        fprintf(results, " tcpi_total_retrans# %u", info.tcpi_total_retrans);
                        fprintf(results, "\n");
                    }
                }
                fclose(results);
                remove(fname);
                // pthread_mutex_lock(&CLOSED_MUTEX);
                // for (int i=0; i<CLOSED_SOCKETS_LIST->len; i=i+1) {
                //     if (s == g_array_index(CLOSED_SOCKETS_LIST, int, i)) {
                //         g_array_remove_index(CLOSED_SOCKETS_LIST, i);
                //         pthread_mutex_unlock(&CLOSED_MUTEX);
                        
                //         // char command[100];
                //         // sprintf(command, "sudo mv /tmp/%lu.txt /tmp/done/%lu.txt", hash_val, hash_val);
                //         // system("mv ");

                //         pthread_mutex_lock(&WORKER_MUTEX);
                //         for (int j=0; j<ACCEPTED_SOCKETS_LIST->len; j=j+1) {
                //             if (s == g_array_index(ACCEPTED_SOCKETS_LIST, int, j)) {
                //                 g_array_remove_index(CLOSED_SOCKETS_LIST, j);
                //             }
                //         }
                //         pthread_mutex_unlock(&WORKER_MUTEX);
                //     }
                // }
            }
        }
        usleep(1*1000);
    }
    return NULL;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    printf("\n\n%s\n\n", "*** OVERLOADED ACCEPT CALLED ***");
    // return sockfd;

    static int (*accept_real)(int, struct sockaddr *, socklen_t *)=NULL;
    if (!accept_real) {
        accept_real=dlsym(RTLD_NEXT,"accept");      
    }
    return accept_real(sockfd, addr, addrlen);
/*  
    if (WORKER_FLAG == 0) {
        WORKER_FLAG = 1;
        ACCEPTED_SOCKETS_LIST = g_array_new(FALSE, FALSE, sizeof(int));
        CLOSED_SOCKETS_LIST = g_array_new(FALSE, FALSE, sizeof(int));
        FNAME_MAP = g_hash_table_new(g_str_hash, g_str_equal);
        pthread_create(&WORKER, NULL, worker, NULL);
    }

    int ret = accept_real(sockfd, addr, addrlen);
    g_array_append_val(ACCEPTED_SOCKETS_LIST, ret);

    // setsockopt
    // FILE* tcpf = fopen("/tmp/tcp.txt","w");
    int TCP_CA_NAME_MAX = 16;
    char optval[TCP_CA_NAME_MAX];
    strcpy(optval, "reno");
    int optlen = strlen(optval);
    if (setsockopt(ret, IPPROTO_TCP, TCP_CONGESTION, optval, optlen) < 0) {
        // fprintf(tcpf, "TCP_CONGESTION set error.");
    }
    // else {
    //     fprintf(tcpf, "accept");
    // }
    // fclose(tcpf);
    return ret;
*/
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    printf("\n\n%s\n\n", "*** OVERLOADED ACCEPT 4 CALLED ***");

    static int (*accept4_real)(int, struct sockaddr *, socklen_t *, int)=NULL;
    if (!accept4_real) {
        accept4_real=dlsym(RTLD_NEXT,"accept4");      
    }
    return accept4_real(sockfd, addr, addrlen, flags);
/*
    if (WORKER_FLAG == 0) {
        WORKER_FLAG = 1;
        ACCEPTED_SOCKETS_LIST = g_array_new(FALSE, FALSE, sizeof(int));
        CLOSED_SOCKETS_LIST = g_array_new(FALSE, FALSE, sizeof(int));
        FNAME_MAP = g_hash_table_new(g_str_hash, g_str_equal);
        pthread_create(&WORKER, NULL, worker, NULL);
        // FILE *results;
        // results = fopen("/tmp/results.txt", "w");
        // fprintf(results, "\n");
        // fclose(results);
    }

    int ret = accept4_real(sockfd, addr, addrlen, flags);
    g_array_append_val(ACCEPTED_SOCKETS_LIST, ret);

    // setsockopt
    // FILE* tcpf = fopen("/tmp/tcp.txt","w");
    int TCP_CA_NAME_MAX = 16;
    char optval[TCP_CA_NAME_MAX];
    strcpy(optval, "reno");
    int optlen = strlen(optval);
    if (setsockopt(ret, IPPROTO_TCP, TCP_CONGESTION, optval, optlen) < 0) {
        // fprintf(tcpf, "TCP_CONGESTION set error.");
    }
    // else {
    //     fprintf(tcpf, "accept");
    // }
    // fclose(tcpf);
    // // getsockopt
    // char current_tcp[TCP_CA_NAME_MAX];
    // int current_optlen = sizeof(current_tcp);
    // if (getsockopt(ret, IPPROTO_TCP, TCP_CONGESTION, current_tcp, (socklen_t *) &current_optlen) < 0) {
    //     fprintf(tcpf, "TCP_CONGESTION get error.");
    // }
    // else {
    //     fprintf(tcpf, "TCP_CONGESTION: %s", current_tcp);
    // }
    // fclose(tcpf);

    // FILE *f = fopen("/tmp/close.txt","w");
    // fprintf(f, "%s\n", "start");
    // fclose(f);
    
    // f = fopen("/tmp/worker.txt","w");
    // fprintf(f, "%s\n", "start");
    // fclose(f);

    // FILE* clf = fopen("/tmp/close.txt","a");
    // fprintf(clf, "accept4 called for: %u\n", ret);
    // fclose(clf);
    return ret;

*/
}

void remove_from_accepted_sockets(int fd) {
    int i;
    for (i=0; i<ACCEPTED_SOCKETS_LIST->len; i=i+1) {
        if (fd == g_array_index(ACCEPTED_SOCKETS_LIST, int, i)) {
            // g_array_remove_index(ACCEPTED_SOCKETS_LIST, i);
            pthread_mutex_lock(&CLOSED_MUTEX);
            g_array_append_val(CLOSED_SOCKETS_LIST, fd);
            pthread_mutex_unlock(&CLOSED_MUTEX);
            break;
        }
    }
}

int close(int fd) {
    static int (*close_real)(int)=NULL;
    if (!close_real) {
        close_real=dlsym(RTLD_NEXT,"close");      
    }

    struct stat sb;
    fstat(fd, &sb);
    switch (sb.st_mode & S_IFMT) {
        case S_IFBLK:
            return close_real(fd);
        case S_IFCHR:
            return close_real(fd);
        case S_IFDIR:
            return close_real(fd);
        case S_IFIFO:
            return close_real(fd);
        case S_IFLNK:
            return close_real(fd);
        case S_IFREG:
            return close_real(fd);
        case S_IFSOCK:
            ;
            if (WORKER_FLAG == 1) {
                FILE* f = fopen("/tmp/close.txt","a");
                fprintf(f, "close called for: %u\n", fd);
                fclose(f);
                // remove_from_accepted_sockets(fd);
            }
            return close_real(fd);
        default:
            return close_real(fd);
    }
}
