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
#include <glib.h>
#include <sys/fcntl.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/time.h>

#include <inttypes.h>
// TO DOs
// loss needs to be after TLS
// 2 RTTS after TLS

// #################################################################################
// Global variables
int IP_VERSION; // IP version used -> ipv4
int IS_FIRST_SOCKET_CREATE = 1;
int IS_FIRST_SOCKET_CONNECT = 1;
int IS_FIRST_SOCKET_CLOSE = 1;
int SOCKET_FD;

char input_src_ip[100];
char input_dst_ip[100];
u_int16_t input_dst_port = 443;
char input_dst_host[100];


u_int16_t random_src_port=0;
int SEQ_NUM_GL = 0;
int ACK_NUM_GL = 0;
unsigned long SEQ_EXP; // f1ter
unsigned long SEQ_EXP_LAST;


int MTU = 1500;
int MSS;
int MSS_USE_FLAG = 1;
int TOTAL_RECV_ATTEMPTS = 10;
double EACH_RECV_TIMEOUT = 1*1000;

int LEFTOVER_FLAG = 0;
int LEFTOVER_BUFFER_SIZE = 0;
char *LEFTOVER_BUFFER;

int LEFTOVER_NXT_PKT_FLAG = 0;
int LEFTOVER_NXT_PKT_BUFFER_SIZE = 0;
char *LEFTOVER_NXT_PKT_BUFFER;

int SHORT_PKT_FLAG = 0;
int SHORT_PKT_SIZE = 0;
int SHORT_PKT_OFFSET_SIZE = 0;
int SHORT_PKT_SIZE_LEFT = 0;
char *SHORT_PKT_BUFFER;

GArray *SEQ_TO_ACK_ARRAY;
int ACK_THREAD_CREATED = 0;
pthread_mutex_t MUTEX_ACK_THREAD;
pthread_t ACK_THREAD_ID;
double ACK_THREAD_TIMEOUT;

int PKTS_RECEIVED_IN_TIMEOUT_WINDOW = 0;
GArray *PKT_TIMESTAMP_ARRAY;
struct timeval INI_TIME;

double LOSS_TIMEOUT = 1.0 * 1000 * 1000;
int LOSS_THRESHOLD;
int LOSS_EMULATION_START = 0;
int CONTINUE_AFTER_LOSS = 0;
int LAST_WINDOW = 0;
pthread_mutex_t MUTEX_LOSS_EMULATION_START;
double LOSS_EMULATION_START_TIME = 0.0;
int LOSS_EMULATION_OVER = 0;

int SSL_DONE = 0;

int LOG_READ = 0;
int LOG_WRITE = 1;

int ICW_FLAG = 0;
unsigned long LAST_ACK = 0;
unsigned long LAST_SEQ = 0;
int SEND_DUP_ACKS = 0;
int DUP_ACKS_SENT = -1;
double LAST_ACK_TS = 0.0;
int SEND_NO_ACK = 0; // ack for first pkt in new window start ets sent twice. this prevents the twice ack behavior.
unsigned long NEXT_EXPECTED_SEQ = 0;
unsigned long FIRST_PKT_LOST_SEQ = 0;
int FIRST_PKT_LOST_FLAG = 0;
unsigned long NEXT_CUMMULATIVE_SEQ = 0;
int FRTO_FLAG = 0;
int FRTO_STUCK_FLAG = 0;

int PACKET_NUMBER = 0;
int VARYING_RTT_FLAG = 1;
GArray *PACKETS_AFTER_LOSS;
int PACKET_NUMBER_AT_LOSS = 0;
int RTT_NUMBER = 0;
int RTT_NUMBER_AFTER_LOSS = 0;
int RTO_COUNT = 0;
unsigned long RTO_SEQ = 0;
unsigned long RTO_LAST_SEQ = -1;
int ACK_AFTER_LOSS = 0;
// double RTT_AFTER_SSL = 2.0;
// struct timeval TIME_WHEN_SSL_COMPLETES;
// int STOP_SEND_AFTER_SSL = 0;
double RTT_MEASURED = 0.0;
int CWND_AT_LOSS = 0;
int EMULATE_RTT_INCREASE = -1;
int SERVER_OBSERVED_MSS = 0;
int NUM_SOCKET_CALLED = 0;
// #################################################################################
// Custom function headers
char ** str_to_array(char *str);
unsigned short csum(unsigned short *ptr,int nbytes);
struct send_return send_pkt_ipv4(int s, char *src_ip, int src_port, char *dst_ip, int dst_port, int pkt_type, int ip_id, u_int32_t seq_num, u_int32_t ack_num, const char * data_buf, size_t data_len, int wait_flag);
int fin_connection();
ssize_t read_socket(int sockfd, void *buf, size_t count);
ssize_t write_socket(int sockfd, const void *buf, size_t len);
int validate_pkt(int s, struct tcphdr *rtcph, unsigned long ip_tot_len, int ip_hrd_len, char *remote_ip);
int process_pkt(char *buffer_to_be_returned, unsigned char *data, int buflen, unsigned short pkt_size, int offset, int len_socket);
void append_seq_to_ack_array(unsigned long seq_to_be_acked);
// void append_pkt_timestamp_array(struct pkt_timestamp ts);
void *send_ack_from_array_thread();
int pkt_within_next_turns(unsigned long seq_seen);

// #################################################################################
// Custom structs
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
struct send_return {
    int send_size;
    int send_sock;
    int send_data_len;
};
struct pkt_timestamp {
    unsigned long seq_num;
    double timestamp;
    int pkt_len;
};
// https://stackoverflow.com/questions/27630216/linux-c-raw-socket-tcp-handsake
struct tcpheaderOptions
{
    u_int16_t 
        tcph_mssOpt:8,
        tcph_mssLen:8;
    u_int16_t
        tcph_mss;
    // u_int16_t
    //     tcph_sack:8,
    //     tcph_sackLen:8;
    u_int16_t
        tcph_winOpt:8,
        tcph_winLen:8;
    u_int32_t
        tcph_win:8,
        tcph_winNOP:8,
        tcph_timeOpt:8,
        tcph_timeLen:8;
    u_int32_t tcph_time;
    u_int32_t tcph_timeEcho;
};

// #################################################################################
// Custom util functions
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
char ** str_to_array(char *str) {
    char **output = malloc(2*sizeof(char*));
    char *token;
    token = strtok(str, "-");
    int i = 0;
    while( token != NULL ) {
        token[strcspn(token, "\n")] = 0;
        output[i] = token;
        i = i+1;
        token = strtok(NULL, "-");
    }
    return output;
}

// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;     
    return(answer);
}

// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
struct send_return send_pkt_ipv4(int s, char *src_ip, int src_port, char *dst_ip, int dst_port, int pkt_type, int ip_id, u_int32_t seq_num, u_int32_t ack_num, const char * data_buf, size_t data_len, int wait_flag) {
    
    if (wait_flag == 1) {
        usleep(ACK_THREAD_TIMEOUT);
    }

    if (MSS_USE_FLAG == 1) {
        MSS_USE_FLAG = 0;
        //Datagram to represent the packet
        char datagram[4096] , source_ip[32] , *data , *pseudogram;
         
        //zero out the packet buffer
        memset (datagram, 0, 4096);
         
        //IP header
        struct iphdr *iph = (struct iphdr *) datagram;
         
        //TCP header
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
        struct tcpheaderOptions *TCPOptions = (struct tcpheaderOptions *) (datagram + sizeof (struct iphdr) + sizeof (struct tcphdr));

        struct sockaddr_in sin;
        struct pseudo_header psh;
         
        //Data part
        if (data_len > 0) {
            data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof (struct tcpheaderOptions);
            memcpy(data , data_buf, data_len);    
        }
             
        //some address resolution
        strcpy(source_ip , src_ip);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(dst_port);
        sin.sin_addr.s_addr = inet_addr (dst_ip);
         
        //Fill in the IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + sizeof(struct tcpheaderOptions) + data_len;
        iph->id = htonl (ip_id); //Id of this packet
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;      //Set to 0 before calculating checksum
        iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
        iph->daddr = sin.sin_addr.s_addr;
         
        //Ip checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
         
        //TCP Header
        tcph->source = htons (src_port);
        // tcph->dest = htons (80);
        tcph->dest = sin.sin_port;
        tcph->seq = htonl(seq_num);
        tcph->ack_seq = htonl(ack_num);
        // tcph->doff = 5;  //tcp header size
        tcph->doff = 10;  //tcp header size
        // SEQ_NUM_GL = seq_num + strlen(data_buf);
        // printf("\n**** send_pkt seq_num: %u ****\n", SEQ_NUM_GL);
        SEQ_NUM_GL = seq_num + data_len;
        // printf("**** send_pkt seq_num + data_len: %u ****\n\n", SEQ_NUM_GL);
        
        //Check pkt type eg. SYN, ACK etc
        switch (pkt_type) {
            case 1:  //SYN
                // printf("%s\n", "sending SYN packet");
                tcph->fin=0;
                tcph->syn=1;
                tcph->rst=0;
                tcph->psh=0;
                tcph->ack=0;
                tcph->urg=0;
                tcph->window = htons (65535);
                break;
             
            case 2:  //ACK
                // printf("%s\n", "sending ACK packet");
                tcph->fin=0;
                tcph->syn=0;
                tcph->rst=0;
                tcph->psh=0;
                tcph->ack=1;
                tcph->urg=0;
                tcph->window = htons (65535);
                break;

            case 3: //FIN
                // printf("%s\n", "sending FIN packet");
                tcph->fin=1;
                tcph->syn=0;
                tcph->rst=0;
                tcph->psh=0;
                tcph->ack=0;
                tcph->urg=0;
                tcph->window = htons (65535);
                break;

            case 4: //Data pkt
                // printf("%s\n", "sending Data packet");
                tcph->fin=0;
                tcph->syn=0;
                tcph->rst=0;
                tcph->psh=1;
                tcph->ack=1;
                tcph->urg=0;
                tcph->window = htons (65535);
                break;

            case 5:  //ACK
                // printf("%s\n", "sending ACK packet");
                tcph->fin=0;
                tcph->syn=0;
                tcph->rst=0;
                tcph->psh=0;
                tcph->ack=1;
                tcph->urg=0;
                tcph->window = htons (0);
                break;

            default:
                printf("%s\n", "wrong packet type specified");

        }
        // tcph->window = htons (65535); /* maximum allowed window size */
        tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
        tcph->urg_ptr = 0;

        // TCP options
        TCPOptions->tcph_mssOpt = 2;
        TCPOptions->tcph_mssLen = 4;
        TCPOptions->tcph_winOpt = 3;
        TCPOptions->tcph_winLen = 3;
        // TCPOptions->tcph_sack = 4;
        // TCPOptions->tcph_sackLen = 2;
        TCPOptions->tcph_win = 2;
        TCPOptions->tcph_winNOP = 1;
        TCPOptions->tcph_mss = htons(MSS);
        // TCPOptions->tcph_timeOpt = 8;
        // TCPOptions->tcph_timeLen = 10;
        // TCPOptions->tcph_time = 0xdb2b0d00;
         
        // Now the TCP checksum
        psh.source_address = inet_addr( source_ip );
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + sizeof(struct tcpheaderOptions) + data_len );
         
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + sizeof(struct tcpheaderOptions) + data_len;
        pseudogram = malloc(psize);
         
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        // memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + data_len);
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + sizeof(struct tcpheaderOptions) + data_len);
        // memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
        // memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr) , TCPOptions , sizeof(struct tcpheaderOptions) + data_len);
         
        tcph->check = csum( (unsigned short*) pseudogram , psize);
        free(pseudogram);
         
        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;
            
        static int (*real_setsockopt)(int, int, int, const void *, socklen_t)=NULL;
        if (!real_setsockopt) {
            real_setsockopt=dlsym(RTLD_NEXT,"setsockopt");      
        }
        if (real_setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }
        
        int sendto_res = sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));
        if (sendto_res < 0) {
            perror("sendto failed");
        }
        else {
            // printf ("sent packet length : %d\n" , iph->tot_len);
        }
        struct send_return ret = {sendto_res, s, data_len};
        return ret;
    }
    else {
        //Datagram to represent the packet
        char datagram[4096] , source_ip[32] , *data , *pseudogram; 
        //zero out the packet buffer
        memset (datagram, 0, 4096);
        //IP header
        struct iphdr *iph = (struct iphdr *) datagram;
        //TCP header
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));

        struct sockaddr_in sin;
        struct pseudo_header psh;
         
        //Data part
        if (data_len > 0) {
            data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
            memcpy(data , data_buf, data_len);    
        }
             
        //some address resolution
        strcpy(source_ip , src_ip);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(dst_port);
        sin.sin_addr.s_addr = inet_addr (dst_ip);
         
        //Fill in the IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len;
        iph->id = htonl (ip_id); //Id of this packet
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;      //Set to 0 before calculating checksum
        iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
        iph->daddr = sin.sin_addr.s_addr;
         
        //Ip checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
         
        //TCP Header
        tcph->source = htons (src_port);
        // tcph->dest = htons (80);
        tcph->dest = sin.sin_port;
        tcph->seq = htonl(seq_num);
        tcph->ack_seq = htonl(ack_num);
        tcph->doff = 5;  //tcp header size
        // tcph->doff = 10;  //tcp header size
        // SEQ_NUM_GL = seq_num + strlen(data_buf);
        // printf("\n**** send_pkt seq_num: %u ****\n", SEQ_NUM_GL);
        SEQ_NUM_GL = seq_num + data_len;
        // printf("**** send_pkt seq_num + data_len: %u ****\n\n", SEQ_NUM_GL);
        
        //Check pkt type eg. SYN, ACK etc
        switch (pkt_type) {
            case 1:  //SYN
                // printf("%s\n", "sending SYN packet");
                tcph->fin=0;
                tcph->syn=1;
                tcph->rst=0;
                tcph->psh=0;
                tcph->ack=0;
                tcph->urg=0;
                tcph->window = htons (65535);
                break;
             
            case 2:  //ACK
                // printf("%s\n", "sending ACK packet");
                tcph->fin=0;
                tcph->syn=0;
                tcph->rst=0;
                tcph->psh=0;
                tcph->ack=1;
                tcph->urg=0;
                tcph->window = htons (65535);
                break;

            case 3: //FIN
                // printf("%s\n", "sending FIN packet");
                tcph->fin=1;
                tcph->syn=0;
                tcph->rst=0;
                tcph->psh=0;
                tcph->ack=0;
                tcph->urg=0;
                tcph->window = htons (65535);
                break;

            case 4: //Data pkt
                // printf("%s\n", "sending Data packet");
                tcph->fin=0;
                tcph->syn=0;
                tcph->rst=0;
                tcph->psh=1;
                tcph->ack=1;
                tcph->urg=0;
                tcph->window = htons (65535);
                break;

            case 5:  //ACK
                // printf("%s\n", "sending ACK packet");
                tcph->fin=0;
                tcph->syn=0;
                tcph->rst=0;
                tcph->psh=0;
                tcph->ack=1;
                tcph->urg=0;
                tcph->window = htons (0);
                break;

            default:
                printf("%s\n", "wrong packet type specified");

        }
        // tcph->window = htons (65535); /* maximum allowed window size */
        tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
        tcph->urg_ptr = 0;

        // Now the TCP checksum
        psh.source_address = inet_addr( source_ip );
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + data_len );
         
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + data_len;
        pseudogram = malloc(psize);
         
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        // memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + data_len);
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + data_len);
        // memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
        // memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr) , TCPOptions , sizeof(struct tcpheaderOptions) + data_len);
         
        tcph->check = csum( (unsigned short*) pseudogram , psize);
        free(pseudogram);
         
        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;
            
        static int (*real_setsockopt)(int, int, int, const void *, socklen_t)=NULL;
        if (!real_setsockopt) {
            real_setsockopt=dlsym(RTLD_NEXT,"setsockopt");      
        }
        if (real_setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }

		PACKET_NUMBER = PACKET_NUMBER + 1;        
        if (PACKET_NUMBER >= 0) {
	        int sendto_res = sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));
	        if (sendto_res < 0) {
	            perror("sendto failed");
	        }
	        else {
	            // printf ("sent packet length : %d\n" , iph->tot_len);
	        }
	        struct send_return ret = {sendto_res, s, data_len};
	        return ret;
	    }
	    else {
	    	struct send_return ret = {0, s, 0};
	        return ret;	
	    }
	    /*
	    int sendto_res = sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));
        if (sendto_res < 0) {
            perror("sendto failed");
        }
        else {
            // printf ("sent packet length : %d\n" , iph->tot_len);
        }
        struct send_return ret = {sendto_res, s, data_len};
        return ret;
        */
    }
}

// #################################################################################
int fin_connection() {
    if (1) {
        printf("\n%s\n\n", "*** FIN_CONNECTION CALLED ***");
        if (IP_VERSION == AF_INET) {
            int sockfd = SOCKET_FD;
            time_t t;
            srand((unsigned) time(&t));
            int random_ip_id = rand() % 65535;
            
            struct send_return ret;
            ret = send_pkt_ipv4(sockfd, input_src_ip, random_src_port, input_dst_ip, input_dst_port, 3, random_ip_id, (u_int32_t) SEQ_NUM_GL, (u_int32_t) SEQ_EXP, NULL, 0, 1);
            SEQ_NUM_GL = SEQ_NUM_GL + 1;
            int s = ret.send_sock;
            printf("%s : %u\n", "fin first send_pkt sent bytes", ret.send_size);
            
            int correct_fin = 1;
            while(correct_fin == 1) {
            
                unsigned char *buffer = (unsigned char *) malloc(65535); //to receive data
                memset(buffer,0,65535);
                struct sockaddr saddr;
                int saddr_len = sizeof (saddr);
                 
                //Receive a network packet and copy in to buffer
                int buflen = recvfrom(s,buffer,65535,0,&saddr,(socklen_t *)&saddr_len);
                // printf("buflen: %u\n", buflen);
                if(buflen < 0) {
                    printf("error in reading recvfrom function\n");
                    return -1;
                }

                // ip header
                struct sockaddr_in source,dest;
                struct iphdr *riph = (struct iphdr*)(buffer);
                unsigned short riphdrlen = riph->ihl*4;

                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = riph->saddr;
                 
                memset(&dest, 0, sizeof(dest));
                dest.sin_addr.s_addr = riph->daddr;

                struct tcphdr *rtcph=(struct tcphdr*)(buffer + riphdrlen);

                printf("%s %s %u %u %u\n", input_dst_ip, inet_ntoa(source.sin_addr), input_dst_port, ntohs(rtcph->source), (unsigned int)rtcph->fin);
                if ((strcmp(input_dst_ip,inet_ntoa(source.sin_addr)) == 0) && input_dst_port == ntohs(rtcph->source)) {
                    if ((unsigned int)rtcph->fin == (unsigned int) 1) {
                        printf("%s\n", "CORRECT FIN FOUND");
                        SEQ_EXP = ntohl(rtcph->seq)+1;
                        correct_fin = 0;
                    }
                }
            }
            // sending ACK of SYN
            random_ip_id = rand() % 65535;
            ret = send_pkt_ipv4(sockfd, input_src_ip, random_src_port, input_dst_ip, input_dst_port, 2, random_ip_id, (u_int32_t) SEQ_NUM_GL, (u_int32_t) SEQ_EXP, NULL, 0, 1);
            s = ret.send_sock;
            printf("%s : %u\n", "fin second send_pkt sent bytes", ret.send_size);

            SEQ_NUM_GL = SEQ_NUM_GL + 1;
            ACK_NUM_GL = SEQ_EXP;
            
            printf("\n\n*** FIN_CONNECTION FINISHED ***\n\n");
            return 0;
        }
        else {
            printf("%s\n", "IPV6 NOT SUPPORTED");
            printf("\n\n*** FIN_CONNECTION FINISHED ***\n\n");
            return -1;
        }
    }
}

// #################################################################################
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    printf("\n\n%s\n", "*** OVERLOADED GETADDRINFO CALLED ***");
    int (*getaddrinfo_real)(const char *, const char *, const struct addrinfo *, struct addrinfo **)=NULL;
    if (!getaddrinfo_real) {
        getaddrinfo_real=dlsym(RTLD_NEXT,"getaddrinfo");      
    }
    
    struct addrinfo *new_hints = (struct addrinfo *) malloc(sizeof(struct addrinfo));
    memset (new_hints, 0, sizeof (struct addrinfo));
    new_hints->ai_family = AF_INET;
    new_hints->ai_socktype = hints->ai_socktype;
    new_hints->ai_flags = hints->ai_flags;
    new_hints->ai_protocol = hints->ai_protocol;
    new_hints->ai_addrlen = hints->ai_addrlen;
    new_hints->ai_addr = hints->ai_addr;
    new_hints->ai_canonname = hints->ai_canonname;
    new_hints->ai_next = hints->ai_next;
    
    int ret = getaddrinfo_real(node, service, new_hints, res);
    struct addrinfo *temp = *res;
    IP_VERSION = temp->ai_family;
    free(new_hints);
    return ret;
}


// #################################################################################
int socket(int domain, int type, int protocol) {
    printf("\n\n%s\n\n", "*** OVERLOADED SOCKET CALLED ***");
    static int (*socket_real)(int, int, int)=NULL;
    if (!socket_real) {
        socket_real=dlsym(RTLD_NEXT,"socket");      
    }
    NUM_SOCKET_CALLED = NUM_SOCKET_CALLED + 1;
    if (NUM_SOCKET_CALLED > 2) {
        exit(0);
    }

    if (IS_FIRST_SOCKET_CREATE == 1) {
        if (remove("/tmp/ssl_done.txt") == 0) {
	        printf("Deleted previous ssl_done.txt file successfully\n");        
	    }
	    else {
	        printf("No previous ssl_done.txt file exists\n");
	    }

	    if (remove("result/trace_count_cwnd.csv") == 0) {
	        printf("Deleted previous trace_count_cwnd.csv file successfully\n");        
	    }
	    else {
	        printf("No previous trace_count_cwnd.csv file exists\n");
	    }

        if (remove("result/frto.csv") == 0) {
            printf("Deleted previous frto.csv file successfully\n");        
        }
        else {
            printf("No previous frto.csv file exists\n");
        }

        if (remove("result/tcp_inferrence.csv") == 0) {
            printf("Deleted previous tcp_inferrence.csv file successfully\n");        
        }
        else {
            printf("No previous tcp_inferrence.csv file exists\n");
        }

        if (remove("result/rtt.csv") == 0) {
            printf("Deleted previous rtt.csv file successfully\n");        
        }
        else {
            printf("No previous rtt.csv file exists\n");
        }

        if (remove("result/server_mss.csv") == 0) {
            printf("Deleted previous server_mss.csv file successfully\n");        
        }
        else {
            printf("No previous server_mss.csv file exists\n");
        }

        if (remove("result/icw.csv") == 0) {
            printf("Deleted previous icw.csv file successfully\n");        
        }
        else {
            printf("No previous icw.csv file exists\n");
        }

        int s = socket_real(domain, type, protocol);
        s == -1 ? printf("failed to create FIRST socket \n") : printf("FIRST socket created successfully \n");
        IS_FIRST_SOCKET_CREATE = 0;
        return s;
    }
    else {
        // printf("%s\n\n", "#################################################################################");
        if (IP_VERSION == AF_INET) {
            printf("%s\n", "IPV4 SOCKET CREATED");
            int s = socket_real(AF_INET, SOCK_RAW, IPPROTO_TCP);
            s == -1 ? printf("failed to create socket \n") : printf("socket created successfully \n");
            return s;
        }
        else if (IP_VERSION == AF_INET6) {
            printf("%s\n", "IPV6 SOCKET CREATED");
            int s = socket_real(AF_INET6, SOCK_RAW, IPPROTO_RAW);
            s == -1 ? printf("failed to create socket \n") : printf("socket created successfully \n");
            return s;
        }
        return -1;
    }
}

// #################################################################################
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    printf("\n\n%s\n\n", "*** OVERLOADED BIND CALLED ***");
    static int (*bind_real)(int, const struct sockaddr *, socklen_t)=NULL;
    if (!bind_real) {
        bind_real=dlsym(RTLD_NEXT,"bind");      
    }
    return bind_real(sockfd, addr, addrlen);
}

// #################################################################################
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    printf("\n\n%s\n\n", "*** OVERLOADED ACCEPT CALLED ***");
    return sockfd;
}

// #################################################################################
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    while(1)
        printf("\n%s | %u\n\n", "*** OVERLOADED SETSOCKOPT CALLED ***", optname);
    return 0;
}

// #################################################################################
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    // while(1)
    //     printf("\n\n%s\n\n", "*** OVERLOADED GETPEERNAME CALLED ***");
    // return 0;
    struct sockaddr_in *ip4addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
    ip4addr->sin_family = AF_INET;
    ip4addr->sin_port = htons(input_dst_port);
    inet_pton(AF_INET, input_dst_ip, &ip4addr->sin_addr);
    addr->sa_family = AF_INET;
    memcpy(addr, ip4addr, sizeof *ip4addr);
    addrlen = (socklen_t *) sizeof *ip4addr;
    free(ip4addr);
    return 0;
}

// #################################################################################
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (IS_FIRST_SOCKET_CONNECT == 1) {
        printf("\n%s\n\n", "*** OVERLOADED FIRST CONNECT CALLED ***");

        int (*connect_real)(int, const struct sockaddr *, socklen_t)=NULL;
        if (!connect_real) {
            connect_real=dlsym(RTLD_NEXT,"connect");      
        }
        IS_FIRST_SOCKET_CONNECT = 0;
        return connect_real(sockfd, addr, addrlen);
    }
    else {
        printf("\n%s\n\n", "*** OVERLOADED SECOND CONNECT CALLED ***");

        LEFTOVER_BUFFER = (char *) malloc(65535);
        memset(LEFTOVER_BUFFER,0,65535);
        LEFTOVER_NXT_PKT_BUFFER = (char *) malloc(65535);
        memset(LEFTOVER_NXT_PKT_BUFFER,0,65535);
        SHORT_PKT_BUFFER = (char *) malloc(65535);
        memset(SHORT_PKT_BUFFER,0,65535);

        // ACK related
        SEQ_TO_ACK_ARRAY = g_array_new( FALSE, FALSE, sizeof(unsigned long));
        if (pthread_mutex_init(&MUTEX_ACK_THREAD, NULL) != 0) {
            printf("\n*** mutex init failed ***\n\n");
            return 1;
        }

        PKT_TIMESTAMP_ARRAY = g_array_new( FALSE, FALSE, sizeof(struct pkt_timestamp));
        PACKETS_AFTER_LOSS = g_array_new( FALSE, FALSE, sizeof(unsigned long));
        gettimeofday(&INI_TIME , NULL);


        if (IP_VERSION == AF_INET) {
            SOCKET_FD = sockfd;
            // gets IP from sockaddr
            if (addr->sa_family == AF_INET) {
                printf("%s: ", "IPV4 address");
                const struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr;
                char* ip4 = inet_ntoa(ipv4->sin_addr);
                strncpy(input_dst_ip,ip4,strlen(ip4));
                // input_dst_port = (u_int16_t) ipv4->sin_port;
            }
            else if (addr->sa_family == AF_INET6) {
                printf("%s: ", "IPV6 address");
                const struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addr;
                char ip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip6, sizeof(ip6));
                strncpy(input_dst_ip,ip6,strlen(ip6));
                // input_dst_port = ipv6->sin6_port;
            }
            printf("%s | address family: %u | with port: %u\n", input_dst_ip, IP_VERSION, input_dst_port);
                
            time_t t;
            srand((unsigned) time(&t));
            random_src_port = (u_int16_t) 1024 + rand() % 10000;
            int random_ip_id = rand() % 65535;
            int random_ini_seq = rand() % 4000000;

            FILE *ptr_file;
            char cwd[1024];
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                // printf("dir: %s\n", cwd);
            }
            else {
                perror("getcwd() error");
            }

            char fname_full[256];
            snprintf(fname_full, sizeof fname_full, "%s%s%s", cwd,"/","conf/session_conf.txt");
            ptr_file = fopen(fname_full, "r");

            char conf_content[1000];
            if (!ptr_file){
                printf("%s\n", "conf read unsuccessful");
                return 1;
            }
            while (fgets(conf_content,1000, ptr_file)!=NULL) {
                char **output = str_to_array(conf_content);
                if (strcmp(output[0],"srcip") == 0) {
                    strncpy(input_src_ip,output[1],strlen(output[1]));
                }
                // else if (strcmp(output[0],"dsthost") == 0) {
                    // strncpy(input_dst_host,output[1],strlen(output[1]));
                // }
                else if (strcmp(output[0],"dstport") == 0) {
                    input_dst_port = (u_int16_t) atoi(output[1]);
                }
                else if (strcmp(output[0],"timeout") == 0) {
                    ACK_THREAD_TIMEOUT = (int) atoi(output[1]) * 1000;
                }
                else if (strcmp(output[0],"toutwindow") == 0) {
                    LOSS_THRESHOLD = (int) atoi(output[1]);
                }
                else if (strcmp(output[0],"mss") == 0) {
                    MSS = (int) atoi(output[1]);
                }
                else if (strcmp(output[0],"mssuse") == 0) {
                    MSS_USE_FLAG = (int) atoi(output[1]);
                }
                else if (strcmp(output[0],"rttinc") == 0) {
                    EMULATE_RTT_INCREASE = (int) atoi(output[1]);
                }
            }
            fclose(ptr_file);
            // LOSS_THRESHOLD = LOSS_THRESHOLD - 1;
            LOSS_THRESHOLD = LOSS_THRESHOLD / 2;
            printf("--> SRC IP: %s\n", input_src_ip);
            printf("--> SRC PORT: %u\n", random_src_port);
            printf("--> DST IP: %s\n", input_dst_ip);
            printf("--> DST PORT: %u\n", input_dst_port);
            printf("--> ACK_THREAD_TIMEOUT: %f\n", ACK_THREAD_TIMEOUT);
            printf("--> LOSS_THRESHOLD: %u %u\n", LOSS_THRESHOLD + 1, LOSS_THRESHOLD);
            printf("--> MSS: %u\n", MSS);
            printf("--> MSS_USE_FLAG: %u\n", MSS_USE_FLAG);
            printf("--> EMULATE_RTT_INCREASE: %u\n", EMULATE_RTT_INCREASE);

            FILE *src_port_file = fopen("result/sport.csv","w");
            fprintf(src_port_file, "%u\n", random_src_port);
            fclose(src_port_file);

            printf("\ninitial seq num: %d\n", random_ini_seq);
            struct send_return ret;
            ret = send_pkt_ipv4(sockfd, input_src_ip, random_src_port, input_dst_ip, input_dst_port, 1, random_ip_id, (u_int32_t) random_ini_seq, (u_int32_t) 0, NULL, 0, 1);
            int s = ret.send_sock;
            printf("%s : %u\n", "recv first send_pkt sent bytes", ret.send_size);

            struct timeval before;
            gettimeofday(&before , NULL);

            
            int correct_synack = 1;
            while(correct_synack == 1) {
            
                unsigned char *buffer = (unsigned char *) malloc(65535); //to receive data
                memset(buffer,0,65535);
                struct sockaddr saddr;
                int saddr_len = sizeof (saddr);
                 
                //Receive a network packet and copy in to buffer
                int buflen = recvfrom(s,buffer,65535,0,&saddr,(socklen_t *)&saddr_len);
                // printf("buflen: %u\n", buflen);
                if(buflen < 0) {
                    printf("error in reading recvfrom function\n");
                    return -1;
                }

                // ip header
                struct sockaddr_in source,dest;
                struct iphdr *riph = (struct iphdr*)(buffer);
                unsigned short riphdrlen = riph->ihl*4;

                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = riph->saddr;
                 
                memset(&dest, 0, sizeof(dest));
                dest.sin_addr.s_addr = riph->daddr;

                struct tcphdr *rtcph=(struct tcphdr*)(buffer + riphdrlen);

                printf("%s %s %u %u \n", input_dst_ip, inet_ntoa(source.sin_addr), input_dst_port, ntohs(rtcph->source));
                if ((strcmp(input_dst_ip,inet_ntoa(source.sin_addr)) == 0) && input_dst_port == ntohs(rtcph->source)) {
                    printf("%s\n", "CORRECT SYN/ACK FOUND");
                    SEQ_EXP = ntohl(rtcph->seq)+1;
                    correct_synack = 0;
                }
                free(buffer);
            }
    
            struct timeval now;
            gettimeofday(&now , NULL);
            double current_time_thread = (now.tv_sec - before.tv_sec) + 1e-6 * (now.tv_usec - before.tv_usec);
            FILE *rtt_file = fopen("result/rtt.csv","w");
            fprintf(rtt_file, "%f\n", current_time_thread);
            fclose(rtt_file);

            // sending ACK of SYN
            // usleep(ACK_THREAD_TIMEOUT);
            random_ip_id = rand() % 65535;
            ret = send_pkt_ipv4(sockfd, input_src_ip, random_src_port, input_dst_ip, input_dst_port, 2, random_ip_id, (u_int32_t) random_ini_seq+1, (u_int32_t) SEQ_EXP, NULL, 0, 1);
            s = ret.send_sock;
            printf("%s : %u\n", "recv second send_pkt sent bytes", ret.send_size);

            SEQ_NUM_GL = random_ini_seq+1;
            ACK_NUM_GL = SEQ_EXP;
            
            printf("\n\n*** CONNECT FINISHED ***\n\n");

            // int fin_ret = fin_connection();
            // if (fin_ret == 0) {
            //     printf("%s\n", "*** FIN_CONNECTION SUCCESSFUL ***");
            // }
            return 0;
        }
        else {
            printf("%s\n", "IPV6 NOT SUPPORTED");
            printf("\n\n*** CONNECT FINISHED ***\n\n");
            return -1;
        }
    }
}

// #################################################################################
ssize_t read(int sockfd, void *buf, size_t count) {
    // printf("\n%s : %u   ", "*** OVERLOADED READ CALLED ***",(unsigned int)count);
    ssize_t (*read_real)(int, void *, size_t)=NULL;
    if (!read_real) {
        read_real=dlsym(RTLD_NEXT,"read");    
    }

    char return_buffer[count];
    int temp;
    // check file type
    struct stat sb;
    fstat(sockfd, &sb);
    // printf("%s", "FILE TYPE -----------> ");
    switch (sb.st_mode & S_IFMT) {
        case S_IFBLK:
            printf("block device\n");
            temp = read_real(sockfd, return_buffer, count);
            memcpy(buf, return_buffer, temp);
            return temp;
        case S_IFCHR:
            printf("character device\n");
            temp = read_real(sockfd, return_buffer, count);
            memcpy(buf, return_buffer, temp);
            return temp;
        case S_IFDIR:
            printf("directory\n");
            temp = read_real(sockfd, return_buffer, count);
            memcpy(buf, return_buffer, temp);
            return temp;
        case S_IFIFO:
            printf("FIFO/pipe\n");
            temp = read_real(sockfd, return_buffer, count);
            memcpy(buf, return_buffer, temp);
            return temp;
        case S_IFLNK:
            printf("symlink\n");
            temp = read_real(sockfd, return_buffer, count);
            memcpy(buf, return_buffer, temp);
            return temp;
        case S_IFREG:
            printf("regular file\n");
            temp = read_real(sockfd, return_buffer, count);
            memcpy(buf, return_buffer, temp);
            return temp;
        case S_IFSOCK:
            // printf("socket\n");
            temp = read_socket(sockfd, return_buffer, count);
            memcpy(buf, return_buffer, temp);
            return temp;
            // if (LOSS_EMULATION_START == 0) {
            //     memcpy(buf, return_buffer, temp);
            //     return temp;
            // }
            // else {
            //     return 0;
            // }
        default:
            printf("unknown?\n");
            temp = read_real(sockfd, return_buffer, count);
            memcpy(buf, return_buffer, temp);
            return temp;
    }    
}

ssize_t read_socket(int s, void *buf, size_t len) {
	if (LOG_READ == 1)
	    printf("\n%s len : %u | src_port : %u\n", "*** OVERLOADED SOCKET READ CALLED ***",(unsigned int)len, random_src_port);

    // // ACK thread creation
    // if (ACK_THREAD_CREATED == 0) {
    //     ACK_THREAD_CREATED = 1;
    //     printf("%s\n", "*** CREATING ACK THREAD ***");
    //     pthread_create(&ACK_THREAD_ID, NULL, send_ack_from_array_thread, NULL);
    // }
    // else {
    //     printf("%s\n", "ACK thread already present. No need for new thread.");
    // }

    // if (LOSS_EMULATION_START == 1 && CONTINUE_AFTER_LOSS == 0) {
    //     usleep(1*1000);
    //     return read_socket(s, buf, len);
    // }
    if (SHORT_PKT_FLAG == 1) {
    	if (LOG_READ == 1)
	        printf("%s | %s\n", "read_socket -> 1","entered SHORT_PKT_FLAG");

        // receive data
        unsigned char *buffer = (unsigned char *) malloc(MTU);
        memset(buffer,0,MTU);
        struct sockaddr saddr;
        int saddr_len = sizeof (saddr);
         
        // struct timeval begin , now;
        int buflen;
        int attempt_flag = 0;
        // gettimeofday(&begin , NULL);

        for (int attempt=0; attempt<TOTAL_RECV_ATTEMPTS; attempt=attempt+1) {
            // gettimeofday(&now , NULL);
            // double timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec);
            // printf("%u | %f\n", attempt,timediff);

            buflen = recvfrom(s,buffer,MTU,0,&saddr,(socklen_t *)&saddr_len);
            if(buflen < 0) {
                usleep(EACH_RECV_TIMEOUT);
            }
            else {
                // printf("%s\n", "data receive successful");
                attempt_flag = 1;
                break;
            }    
        }
        if (attempt_flag == 0) {
            // printf("error in reading recvfrom function\n");
            return 0;
        }

        // ip header
        struct sockaddr_in source,dest;
        struct iphdr *riph = (struct iphdr*)(SHORT_PKT_BUFFER);
        unsigned short riphdrlen = riph->ihl*4;

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = riph->saddr;
         
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = riph->daddr;

        struct tcphdr *rtcph=(struct tcphdr*)(SHORT_PKT_BUFFER + riphdrlen);

        // printf("IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)riph->ihl,((unsigned int)(riph->ihl))*4);
        // printf("IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(riph->tot_len));
        
        int val_res = validate_pkt(s, rtcph, ntohs(riph->tot_len), (int) riphdrlen, inet_ntoa(source.sin_addr));

        if (val_res == 1) {
            // printf("%s\n", "RECEIVED PKT IS ACK | READ TRYING AGAIN");
            free(buffer);
            return read_socket(s, buf, len);
        }
        else if (val_res == 2) {
            // printf("recvfrom returned: %d\n", buflen);
            unsigned char * data_in_buf = buffer;
            char buffer_to_be_returned[MTU];
            memset(buffer_to_be_returned,0,MTU);

            SHORT_PKT_FLAG = 0;
        
            int proc_res = process_pkt(buffer_to_be_returned, data_in_buf, buflen , SHORT_PKT_SIZE_LEFT, SHORT_PKT_OFFSET_SIZE, len);

            memcpy(buf, buffer_to_be_returned, proc_res);
            // printf("read_socket returned %u\n", proc_res);
            free(buffer);
            if (LOG_READ == 1)
	            printf("%s : %u\n", "bytes read sent back to kernel",buflen);
            return proc_res;
        }
        else if (val_res == 4) {
            // return 0;
            free(buffer);
            return read_socket(s, buf, len);
        }
        else if (val_res == -1) { // wrong seq num, try again
            // printf("%s\n", "read_socket trying again due to wrong seq num");
            free(buffer);
            return read_socket(s, buf, len);
        }
        else {
            // printf("%s\n", "received pkt is OTHER ************************");
            free(buffer);
            return -1;
        }
    }

    else if (LEFTOVER_FLAG == 0 && LEFTOVER_NXT_PKT_FLAG == 0) {
    	if (LOG_READ == 1)
	        printf("%s\n", "read_socket -> 2");
        
        // receive data
        unsigned char *buffer = (unsigned char *) malloc(MTU); //to receive data
        memset(buffer,0,MTU);
        struct sockaddr saddr;
        int saddr_len = sizeof (saddr);

        // printf("--> %u\n", 1);
         
        // struct timeval begin , now;
        int buflen;
        int attempt_flag = 0;
        // gettimeofday(&begin , NULL);
        // printf("--> %u\n", 2);

        for (int attempt=0; attempt<TOTAL_RECV_ATTEMPTS; attempt=attempt+1) {
        	// printf("--> %u\n", 3);
            // gettimeofday(&now , NULL);
            // double timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec);
            // printf("%u | %f\n", attempt,timediff);

            buflen = recvfrom(s,buffer,MTU,0,&saddr,(socklen_t *)&saddr_len);
            if(buflen < 0) {
                usleep(EACH_RECV_TIMEOUT);
            }
            else {
                // printf("%s\n", "data receive successful");
                attempt_flag = 1;
                break;
            }    
        }
        if (attempt_flag == 0) {
            // printf("error in reading recvfrom function\n");
            return 0;
        }
        // printf("--> %u\n", 4);

        // ip header
        struct sockaddr_in source,dest;
        struct iphdr *riph = (struct iphdr*)(buffer);
        unsigned short riphdrlen = riph->ihl*4;

        // printf("--> %u\n", 5);

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = riph->saddr;
         
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = riph->daddr;
        // printf("--> %u\n", 6);

        struct tcphdr *rtcph=(struct tcphdr*)(buffer + riphdrlen);

        // printf("IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)riph->ihl,((unsigned int)(riph->ihl))*4);
        // printf("IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(riph->tot_len));
        // printf("IP before validate_pkt: %s\n", inet_ntoa(source.sin_addr));        
        int val_res = validate_pkt(s, rtcph, ntohs(riph->tot_len), (int) riphdrlen, inet_ntoa(source.sin_addr));
        // printf("--> %u\n", 7);
        
        if (val_res == 1) {
        	// printf("--> %u\n", 8);
            // printf("%s\n", "RECEIVED PKT IS ACK | READ TRYING AGAIN");
            free(buffer);
            return read_socket(s, buf, len);
        }
        else if (val_res == 2) {
        	// printf("--> %u\n", 9);
            // printf("recvfrom returned: %d\n", buflen);
            unsigned char * data_in_buf = buffer + (unsigned int) riphdrlen + (unsigned int) rtcph->doff*4;
            char buffer_to_be_returned[MTU];
            memset(buffer_to_be_returned,0,MTU);
        
            int proc_res = process_pkt(buffer_to_be_returned, data_in_buf, buflen , ntohs(riph->tot_len), (int) riphdrlen + (int) rtcph->doff*4, len);

            if (SHORT_PKT_FLAG == 1) {
                memcpy(SHORT_PKT_BUFFER, buffer, (int) riphdrlen + (int) rtcph->doff*4);
            }

            memcpy(buf, buffer_to_be_returned, proc_res);
            // printf("read_socket returned %u \n", proc_res);
            // for (int i=0; i<proc_res; i=i+1) {
                // printf("%02X\n", ((char *) buf)[i]);
            // }
            free(buffer);
            if (LOG_READ == 1)
	            printf("%s : %u\n", "bytes read sent back to kernel",buflen);
            return proc_res;
        }
        else if (val_res == 4) {
        	// printf("--> %u\n", 10);
            // return 0;
            free(buffer);
            return read_socket(s, buf, len);
        }
        else if (val_res == -1) { // wrong seq num, try again
            // printf("%s\n", "read_socket trying again due to wrong seq num");
            // printf("--> %u\n", 11);
            free(buffer);
            return read_socket(s, buf, len);
        }
        else {
        	// printf("--> %u\n", 12);
            // printf("%s\n", "received pkt is OTHER ************************");
            free(buffer);
            return -1;
        }
    }
    else if (LEFTOVER_FLAG == 1) {
    	if (LOG_READ == 1)
	        printf("%s\n", "read_socket -> 3");
        // printf("%u %u\n", LEFTOVER_FLAG, LEFTOVER_BUFFER_SIZE);
        // there is already some data present from previous recv
        if (len >= LEFTOVER_BUFFER_SIZE) {
            // printf("3: %u\n", 1);
            memcpy(buf, LEFTOVER_BUFFER, LEFTOVER_BUFFER_SIZE);
            for (int i=0; i<LEFTOVER_BUFFER_SIZE; i=i+1) {
                LEFTOVER_BUFFER[i] = '\0';   
            }
            int temp = LEFTOVER_BUFFER_SIZE;
            LEFTOVER_BUFFER_SIZE = 0;
            LEFTOVER_FLAG = 0;
            // printf("%u %u\n", LEFTOVER_FLAG, LEFTOVER_BUFFER_SIZE);
            return temp;
        }
        else {
            // printf("3: %u\n", 2);
            memcpy(buf, LEFTOVER_BUFFER, len);
            for (int i=0; i<LEFTOVER_BUFFER_SIZE; i=i+1) {
                if (i < LEFTOVER_BUFFER_SIZE - len) {
                    LEFTOVER_BUFFER[i] = LEFTOVER_BUFFER[len+i];    
                }
                else {
                    LEFTOVER_BUFFER[i] = '\0';   
                }   
            }
            LEFTOVER_BUFFER_SIZE = LEFTOVER_BUFFER_SIZE - len;
            // printf("%u %u\n", LEFTOVER_FLAG, LEFTOVER_BUFFER_SIZE);
            return len;
        }
    }

    else if (LEFTOVER_NXT_PKT_FLAG == 1) {
    	if (LOG_READ == 1)
	        printf("%s\n", "read_socket -> 4");
        
        // receive data
        unsigned char *buffer = (unsigned char *) malloc(MTU); //to receive data
        memset(buffer,0,MTU);
        struct sockaddr saddr;
        int saddr_len = sizeof (saddr);
         
        // struct timeval begin , now;
        int buflen;
        int attempt_flag = 0;
        // gettimeofday(&begin , NULL);

        for (int attempt=0; attempt<TOTAL_RECV_ATTEMPTS; attempt=attempt+1) {
            // gettimeofday(&now , NULL);
            // double timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec);
            // printf("%u | %f\n", attempt,timediff);

            buflen = recvfrom(s,buffer,MTU,0,&saddr,(socklen_t *)&saddr_len);
            if(buflen < 0) {
                usleep(EACH_RECV_TIMEOUT);
            }
            else {
                // printf("%s\n", "data receive successful");
                attempt_flag = 1;
                break;
            }    
        }
        if (attempt_flag == 0) {
            // printf("error in reading recvfrom function\n");
            return 0;
        }

        // append nxt pkt data to buffer        
        char *temp = (char *) malloc(buflen);
        memcpy(temp, LEFTOVER_NXT_PKT_BUFFER, LEFTOVER_NXT_PKT_BUFFER_SIZE);
        memcpy(temp + LEFTOVER_NXT_PKT_BUFFER_SIZE, buffer, buflen);

        buflen = buflen + LEFTOVER_NXT_PKT_BUFFER_SIZE;
        for (int i=0; i<LEFTOVER_NXT_PKT_BUFFER_SIZE; i=i+1) {
            LEFTOVER_NXT_PKT_BUFFER[i] = '\0';   
        }
        LEFTOVER_NXT_PKT_FLAG = 0;
        LEFTOVER_NXT_PKT_BUFFER_SIZE = 0;

        // ip header
        struct sockaddr_in source,dest;
        struct iphdr *riph = (struct iphdr*)(buffer);
        unsigned short riphdrlen = riph->ihl*4;

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = riph->saddr;
         
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = riph->daddr;

        struct tcphdr *rtcph=(struct tcphdr*)(buffer + riphdrlen);

        // printf("IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)riph->ihl,((unsigned int)(riph->ihl))*4);
        // printf("IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(riph->tot_len));
        
        int val_res = validate_pkt(s, rtcph, ntohs(riph->tot_len), (int) riphdrlen, inet_ntoa(source.sin_addr));

        if (val_res == 1) {
            // printf("%s\n", "RECEIVED PKT IS ACK | READ TRYING AGAIN");
            free(buffer);
            free(temp);
            return read_socket(s, buf, len);
        }
        else if (val_res == 2) {
            // printf("recvfrom returned: %d\n", buflen);
            unsigned char * data_in_buf = buffer + (unsigned int) riphdrlen + (unsigned int) rtcph->doff*4;
            char buffer_to_be_returned[MTU];
            memset(buffer_to_be_returned,0,MTU);
        
            int proc_res = process_pkt(buffer_to_be_returned, data_in_buf, buflen , ntohs(riph->tot_len), (int) riphdrlen + (int) rtcph->doff*4, len);

            if (SHORT_PKT_FLAG == 1) {
                memcpy(SHORT_PKT_BUFFER, buffer, (int) riphdrlen + (int) rtcph->doff*4);
            }

            memcpy(buf, buffer_to_be_returned, proc_res);
            // printf("read_socket returned %u\n", proc_res);
            free(buffer);
            free(temp);
            if (LOG_READ == 1)
	            printf("%s : %u\n", "bytes read sent back to kernel",buflen);
            return proc_res;
        }
        else if (val_res == 4) {
            // return 0;
            free(buffer);
            free(temp);
            return read_socket(s, buf, len);
        }
        else if (val_res == -1) { // wrong seq num, try again
            // printf("%s\n", "read_socket trying again due to wrong seq num");
            free(buffer);
            free(temp);
            return read_socket(s, buf, len);
        }
        else {
            // printf("%s\n", "received pkt is OTHER ************************");
            free(buffer);
            free(temp);
            return -1;
        }
    }
    else {
        printf("**************************************************************\n");
        printf("**************************************************************\n");
        printf("read_socket: SHORT PKT RETURNED\n");
        printf("**************************************************************\n");
        printf("**************************************************************\n");
        return -1;
    }
}

int process_pkt(char *buffer_to_be_returned, unsigned char *data, int buflen, unsigned short pkt_size, int offset, int len_socket) {
    // printf("PROCESS_PKT -> buflen: %u | pkt_size: %u | offset: %u | len_socket: %u\n", buflen, pkt_size, offset, len_socket);
    if (buflen == pkt_size) { // pkt_size-offset == buflen-offset
        // printf("process_pkt: %u\n", 1);
        if (len_socket >= pkt_size-offset) {
            // printf("process_pkt: %u\n", 11);
            memcpy(buffer_to_be_returned, data, pkt_size - offset);
            return pkt_size - offset;
        }
        // else if (len_socket < pkt_size-offset) {
        else {
            // printf("process_pkt: %u\n", 12);
            memcpy(buffer_to_be_returned, data, len_socket);
            LEFTOVER_FLAG = 1;
            LEFTOVER_BUFFER_SIZE = pkt_size - offset - len_socket;
            memcpy(LEFTOVER_BUFFER, data + len_socket, LEFTOVER_BUFFER_SIZE);
            return len_socket;
        }
    }
    else if (buflen > pkt_size) {
        // printf("process_pkt: %u\n", 2);
        if (len_socket >= pkt_size-offset) {
            // printf("process_pkt: %u\n", 21);
            memcpy(buffer_to_be_returned, data, pkt_size - offset);

            LEFTOVER_NXT_PKT_FLAG = 1;
            LEFTOVER_NXT_PKT_BUFFER_SIZE = buflen - pkt_size;
            memcpy(LEFTOVER_NXT_PKT_BUFFER, data + pkt_size - offset, LEFTOVER_NXT_PKT_BUFFER_SIZE);
            return pkt_size - offset;
        }
        // else if (len_socket < pkt_size-offset) {
        else {
            // printf("process_pkt: %u\n", 22);
            memcpy(buffer_to_be_returned, data, len_socket);

            LEFTOVER_FLAG = 1;
            LEFTOVER_BUFFER_SIZE = pkt_size - offset - len_socket;
            memcpy(LEFTOVER_BUFFER, data + len_socket, LEFTOVER_BUFFER_SIZE);
            
            LEFTOVER_NXT_PKT_FLAG = 1;
            LEFTOVER_NXT_PKT_BUFFER_SIZE = buflen - pkt_size;
            memcpy(LEFTOVER_NXT_PKT_BUFFER, data + pkt_size - offset, LEFTOVER_NXT_PKT_BUFFER_SIZE); 
            return len_socket;
        }
    }
    else {
        // printf("process_pkt: %u\n", 3);
        SHORT_PKT_FLAG = 1;
        SHORT_PKT_SIZE = pkt_size;
        SHORT_PKT_OFFSET_SIZE = offset;
        SHORT_PKT_SIZE_LEFT = pkt_size - buflen;
        
        memcpy(buffer_to_be_returned, data, buflen-offset);
        return buflen-offset;
    }
}

int pkt_within_next_turns(unsigned long seq_seen) {
    if ((seq_seen > SEQ_EXP) && (seq_seen < (unsigned long) (10*MSS) + SEQ_EXP)) {
        printf("%s\n", "#############################################################################");
        printf("%s\n", "#############################################################################");
        printf("%lu %lu %lu\n",SEQ_EXP, seq_seen, (unsigned long) (10*MSS) + SEQ_EXP);
        printf("%s\n", "#############################################################################");
        printf("%s\n", "#############################################################################");
        return 1;
    }
    else {
        return 0;
    }
}

int validate_pkt(int s, struct tcphdr *rtcph, unsigned long ip_tot_len, int ip_hrd_len, char *remote_ip) {
    // printf("PACKET VALIDATION -> observed seq num: %u | expected seq num: %lu | last expected seq num: %lu\n", ntohl(rtcph->seq),SEQ_EXP,SEQ_EXP_LAST);
    // printf("validate_pkt: %u | %u | %s\n", rtcph->source, rtcph->dest, remote_ip);
    // printf("%" PRIu16 "\n",rtcph->dest);
    // if (strcmp(input_dst_ip,inet_ntoa(source.sin_addr)) == 0) && input_dst_port == ntohs(rtcph->source) {
    if (strcmp(input_dst_ip, remote_ip) == 0) {
        if (SHORT_PKT_FLAG == 1) {
            printf("%s\n", "entered SEQ_EXP_LAST");
            if (ntohl(rtcph->seq) ==  SEQ_EXP_LAST) {
                int if_pkt_contains_data;
                // printf("start: %lu\n", ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4));
                if (ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4) > 0) {
                    if_pkt_contains_data = 1;
                }
                else if(ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4) == 0) {
                    if_pkt_contains_data = 0;
                }

                if (if_pkt_contains_data == 1 || ((unsigned int)rtcph->ack == (unsigned int) 1 && (unsigned int)rtcph->psh == (unsigned int) 1)) {
                    // printf("received data pkt: ack %u psh %u is_size>0? %u\n",(unsigned int)rtcph->ack,(unsigned int)rtcph->psh,if_pkt_contains_data);
                    // printf("%s\n", "no ACK sent or SEQ_EXP changed");
                    return 2; // for data
                }
                else if ((unsigned int)rtcph->ack == (unsigned int) 1) {
                    // printf("%s\n", "received ack pkt: ack 1");
                    return 1; // for ack   
                }
                else {
                    return 3; //for other types
                }
            }
            else {
                return -1; // wrong seq num
            }

        }
        // else if (ntohl(rtcph->seq) ==  SEQ_EXP || pkt_within_next_turns(ntohl(rtcph->seq)) == 1) {
        // else if (ntohl(rtcph->seq) ==  SEQ_EXP) {
        else if (1) {
            // pthread_mutex_lock(&MUTEX_LOSS_EMULATION_START);
            // if (LOSS_EMULATION_START == 0 || CONTINUE_AFTER_LOSS == 1) {
            if (1) {
                // pthread_mutex_unlock(&MUTEX_LOSS_EMULATION_START);

                int if_pkt_contains_data;
                // printf("start: %lu\n", ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4));
                if (ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4) > 0) {
                    if_pkt_contains_data = 1;
                }
                else if(ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4) == 0) {
                    if_pkt_contains_data = 0;
                }

                if (if_pkt_contains_data == 1 || ((unsigned int)rtcph->ack == (unsigned int) 1 && (unsigned int)rtcph->psh == (unsigned int) 1)) {
                    // printf("received data pkt: ack %u psh %u is_size>0? %u\n",(unsigned int)rtcph->ack,(unsigned int)rtcph->psh,if_pkt_contains_data);
                    
                    /*
                    // ACK thread creation
                    if (ACK_THREAD_CREATED == 0) {
                        ACK_THREAD_CREATED = 1;
                        printf("%s\n", "*** CREATING ACK THREAD ***");
                        pthread_create(&ACK_THREAD_ID, NULL, send_ack_from_array_thread, NULL);
                    }
                    else {
                        // printf("%s\n", "ACK thread already present. No need for new thread.");
                    }
                    */

                    struct timeval now;
                    gettimeofday(&now , NULL);
                    double timediff = (now.tv_sec - INI_TIME.tv_sec) + 1e-6 * (now.tv_usec - INI_TIME.tv_usec);         

                    unsigned long seq_to_be_acked = ntohl(rtcph->seq) + (unsigned long) (ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4));
                    // PKTS_RECEIVED_IN_TIMEOUT_WINDOW = PKTS_RECEIVED_IN_TIMEOUT_WINDOW + 1;
                    struct pkt_timestamp ts = {seq_to_be_acked, timediff, (int) ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4)};

                    // printf("pkt_timestamp stats: %lu | %f\n", ts.seq_num, ts.timestamp);
                    // append_pkt_timestamp_array(ts);
                    pthread_mutex_lock(&MUTEX_ACK_THREAD);
                    g_array_append_val(PKT_TIMESTAMP_ARRAY, ts);
                    pthread_mutex_unlock(&MUTEX_ACK_THREAD);
                    // printf("Added %lu to PKT_TIMESTAMP_ARRAY | time : %f\n", ts.seq_num, ts.timestamp);

                    // ACK thread creation
                    if (ACK_THREAD_CREATED == 0) {
                        ACK_THREAD_CREATED = 1;
                        printf("%s\n", "*** CREATING ACK THREAD ***");
                        pthread_create(&ACK_THREAD_ID, NULL, send_ack_from_array_thread, NULL);
                    }

                    // if (LOSS_EMULATION_START == 1 && CONTINUE_AFTER_LOSS == 0) {
                    	// usleep(3*1000*1000);
                    	// CONTINUE_AFTER_LOSS = 1;
                    // }

                    if (ntohl(rtcph->seq) ==  SEQ_EXP) {
                        if ((int) ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4) > SERVER_OBSERVED_MSS) {
                            SERVER_OBSERVED_MSS = (int) ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4);
                            FILE *mss_file = fopen("result/server_mss.csv", "w");
                            fprintf(mss_file, "%u\n", SERVER_OBSERVED_MSS);
                            fclose(mss_file);
                        }
    	                SEQ_EXP_LAST = SEQ_EXP;
    	                SEQ_EXP = ntohl(rtcph->seq) + (unsigned long) (ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4));                	
                    	return 2; // for data
                    }
                    else {
                    	return 4;
                    }
                 
                 //    SEQ_EXP_LAST = SEQ_EXP;
                 //    SEQ_EXP = ntohl(rtcph->seq) + (unsigned long) (ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4));                	
                	// return 2; // for data
                }
                else if ((unsigned int)rtcph->ack == (unsigned int) 1) {
                    // printf("%s\n", "received ack pkt: ack 1");
                    return 1; // for ack   
                }
                else {
                    return -1; //for other types
                }
            }
            else {
                // LOSS_EMULATION_START is 1
                printf("%s\n", "###################################################");
                printf("%s\n", "###################################################");
                printf("LOSS_EMULATION_START: %u\n", LOSS_EMULATION_START);
                printf("%s\n", "###################################################");
                printf("%s\n", "###################################################");
                // pthread_mutex_unlock(&MUTEX_LOSS_EMULATION_START);
                // usleep(3000*1000);
                // CONTINUE_AFTER_LOSS = 1;
                SEND_DUP_ACKS = 1;
                // struct pkt_timestamp ts = {LAST_ACK, LAST_ACK_TS, (int) ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4)};

                struct timeval now;
                gettimeofday(&now , NULL);
                double timediff = (now.tv_sec - INI_TIME.tv_sec) + 1e-6 * (now.tv_usec - INI_TIME.tv_usec);
                struct pkt_timestamp ts = {LAST_ACK, timediff, (int) ip_tot_len - (ip_hrd_len + (int) rtcph->doff*4)};

                pthread_mutex_lock(&MUTEX_ACK_THREAD);
                g_array_append_val(PKT_TIMESTAMP_ARRAY, ts);
                pthread_mutex_unlock(&MUTEX_ACK_THREAD);
                
                return 4;
            }
        }
        else {
        	printf("%s\n", "###################################################");
            printf("%s\n", "###################################################");
            printf("WRONG SEQ NUM: %u | %lu\n", ntohl(rtcph->seq), SEQ_EXP);
            printf("%s\n", "###################################################");
            printf("%s\n", "###################################################");
            return -1; // wrong seq num
        }
    }
    else {
        // printf("IP not equal: %s | %s\n", input_dst_ip, remote_ip);
        return -1;    
    }
}

void append_seq_to_ack_array(unsigned long seq_to_be_acked) {
    pthread_mutex_lock(&MUTEX_ACK_THREAD);
    g_array_append_val(SEQ_TO_ACK_ARRAY, seq_to_be_acked);
    pthread_mutex_unlock(&MUTEX_ACK_THREAD);

    printf("Added %lu to SEQ_TO_ACK_ARRAY | len : %u\n", seq_to_be_acked, SEQ_TO_ACK_ARRAY->len);
}

int packets_after_loss_contains(unsigned long pkt, int len) {
    if (LOSS_EMULATION_START == 1 && RTT_NUMBER_AFTER_LOSS > 10) {
    	if (PACKETS_AFTER_LOSS->len > 0 && PACKET_NUMBER > PACKET_NUMBER_AT_LOSS + 2) {
    	    for (int i=0; i<PACKETS_AFTER_LOSS->len; i=i+1) {
    	        unsigned long temp = g_array_index(PACKETS_AFTER_LOSS, unsigned long, i);
    	        // printf("PACKETS_AFTER_LOSS: %lu | %lu\n",temp, pkt);
    	        if (temp + len == pkt) {
    	        	g_array_remove_index(PACKETS_AFTER_LOSS, i);
    	        	return 1;
    	        }
    	    }
    	}
    }
	return 0;
}

void print_packets() {
    for (int i=0; i<PKT_TIMESTAMP_ARRAY->len; i=i+1) {
        struct pkt_timestamp temp_pkt_timestamp = g_array_index(PKT_TIMESTAMP_ARRAY, struct pkt_timestamp, i);
        printf("%u: %lu | %f", i, temp_pkt_timestamp.seq_num, temp_pkt_timestamp.timestamp);
        printf("%s", "\n");
    }
    printf("\n");
}

void *send_ack_from_array_thread() {

    int wcount = 1;
    int window_size = 0;
    double start_time = 0.0;
    double ack_thread_timeout_sec = ACK_THREAD_TIMEOUT/1000000;
    time_t t;
    srand((unsigned) time(&t));
    int random_ip_id = rand() % 65535;
    int prev_rtt = 0;

    while (wcount >= 0) {
        wcount = wcount + 1;
        struct timeval now;
        gettimeofday(&now , NULL);
        double current_time_thread = (now.tv_sec - INI_TIME.tv_sec) + 1e-6 * (now.tv_usec - INI_TIME.tv_usec);

        int temp_size;
        pthread_mutex_lock(&MUTEX_ACK_THREAD);
        temp_size = PKT_TIMESTAMP_ARRAY->len;
        pthread_mutex_unlock(&MUTEX_ACK_THREAD);

        if (EMULATE_RTT_INCREASE == 1 && LOSS_EMULATION_START == 1 && RTT_NUMBER_AFTER_LOSS > prev_rtt) {
            prev_rtt = RTT_NUMBER_AFTER_LOSS;
            // ack_thread_timeout_sec = (ACK_THREAD_TIMEOUT + 50*1000) / 1000000;
            ack_thread_timeout_sec = ack_thread_timeout_sec + (10.0 / 1000.0);
            printf("************ %s : %f ************\n", "new RTT", ack_thread_timeout_sec);
        }
        
        if (temp_size > 0) {
            for (int i=0; i<temp_size; i=i+1) {
    
                // loss induction
                if (LAST_WINDOW >= LOSS_THRESHOLD && LOSS_THRESHOLD != -1) {
                    LOSS_THRESHOLD = -1;
                    LOSS_EMULATION_START = 1;
                    printf("--->  LOSS LOSS_EMULATION_START  <---\n");
                }

                if (temp_size > 0) {
                    struct pkt_timestamp temp_pkt_timestamp;
                    pthread_mutex_lock(&MUTEX_ACK_THREAD);
                    temp_pkt_timestamp = g_array_index(PKT_TIMESTAMP_ARRAY, struct pkt_timestamp, 0);
                    pthread_mutex_unlock(&MUTEX_ACK_THREAD);

                    if (start_time == 0.0) {
                        start_time = temp_pkt_timestamp.timestamp;
                    }
                    
                    if (current_time_thread >= temp_pkt_timestamp.timestamp + ack_thread_timeout_sec) {                        
                        if (temp_pkt_timestamp.timestamp <= start_time + ack_thread_timeout_sec) {
                            window_size = window_size + 1;
                            // print_packets();
                            pthread_mutex_lock(&MUTEX_ACK_THREAD);
	                        g_array_remove_index(PKT_TIMESTAMP_ARRAY, 0);
	                        pthread_mutex_unlock(&MUTEX_ACK_THREAD);
                        }
                        else {
                            LAST_WINDOW = window_size;
                            if (RTT_NUMBER_AFTER_LOSS >= 8 && LAST_WINDOW < 5) {
                                FRTO_STUCK_FLAG = 1;
                            }
                            RTT_NUMBER = RTT_NUMBER + 1;
                            if (LOSS_EMULATION_START == 1) {
                                RTT_NUMBER_AFTER_LOSS = RTT_NUMBER_AFTER_LOSS + 1;
                            }

                            if (ICW_FLAG == 0) {
                            	ICW_FLAG = 1;
                            	FILE *icw_value_f = fopen("result/icw.csv", "w");
	                            fprintf(icw_value_f, "%u\n", window_size);
	                            fclose(icw_value_f);
                            }
                            if (LOSS_EMULATION_START == 1 && CWND_AT_LOSS == 0) {
                                CWND_AT_LOSS = LAST_WINDOW;
                            }
                            if (LOSS_EMULATION_START == 1 && ACK_AFTER_LOSS > 0 && ACK_AFTER_LOSS <= 5 && LAST_WINDOW >= CWND_AT_LOSS) {
                                FILE *tcp_file = fopen("result/tcp_inferrence.csv", "w");
                                fprintf(tcp_file, "%s\n", 'FAST');
                                fclose(tcp_file);
                            }

                            printf("\n%s | %u | %s | %u \n\n", ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" , LAST_WINDOW, "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", random_src_port);
                            FILE *icw_trace_count_file = fopen("result/trace_count_cwnd.csv", "a");
                            fprintf(icw_trace_count_file, "%u\n", window_size);
                            fclose(icw_trace_count_file);

                            if (SSL_DONE == 0) {
                                FILE * file;
                                file = fopen("/tmp/ssl_done.txt", "r");
                                if (file) {
                                    printf("%s\n", "exists");
                                    fclose(file);
                                    SSL_DONE = 1;

                                    FILE *icw_trace_count_file = fopen("result/trace_count_cwnd.csv", "a");
                                    fprintf(icw_trace_count_file, "%u\n", 999999);
                                    fclose(icw_trace_count_file);
                                }
                            }                            
                            window_size = 0;
                            start_time = temp_pkt_timestamp.timestamp;
                            SEND_NO_ACK = 1;
                        }

                        /*// no ACK will be sent after timeout
                        if (LOSS_EMULATION_START == 1) {
                        	SEND_NO_ACK = 1;
                        }*/

		                if (1) {
                            // if (SEND_NO_ACK == 0 && RTO_COUNT != 1) {
                            if (SEND_NO_ACK == 0) {

                                // if (LOSS_EMULATION_START == 1 && RTO_LAST_SEQ != -1 && RTT_NUMBER_AFTER_LOSS <= 3) {
                                if (LOSS_EMULATION_START == 1 && RTO_LAST_SEQ != -1 && ACK_AFTER_LOSS >= 1) {
                                    if (temp_pkt_timestamp.seq_num > RTO_LAST_SEQ) {
                                        FRTO_FLAG = 1;
                                        FILE *frto_file = fopen("result/frto.csv", "w");
                                        fprintf(frto_file, "%u\n", 1);
                                        fclose(frto_file);
                                    }
                                }
                            
    	                        if (LOSS_EMULATION_START == 1 && LOSS_EMULATION_START_TIME == 0.0) {
    	                        	LOSS_EMULATION_START_TIME = temp_pkt_timestamp.timestamp;
    	                        	RTO_COUNT = 1;
    	                        	RTO_SEQ = temp_pkt_timestamp.seq_num;
    	                        	printf("1: %u | %lu | %lu --> SEQ: %lu\n", RTO_COUNT, RTO_SEQ, temp_pkt_timestamp.seq_num, temp_pkt_timestamp.seq_num-temp_pkt_timestamp.pkt_len);
    	                        }
    	                        else if (LOSS_EMULATION_START == 1 && RTO_COUNT > 0 && temp_pkt_timestamp.seq_num == RTO_SEQ) {
    	                        	RTO_COUNT = RTO_COUNT + 1;
    	                        }

	                            if (LOSS_EMULATION_START == 1 && temp_pkt_timestamp.timestamp <= LOSS_EMULATION_START_TIME + ack_thread_timeout_sec) {
		                        	DUP_ACKS_SENT = DUP_ACKS_SENT + 1;
                                    RTO_LAST_SEQ = temp_pkt_timestamp.seq_num;
		                        }
		                        else {
                                    if (0) {
                                    // if (LOSS_EMULATION_START == 1 && RTO_COUNT == 2) {
                                        // Do nothing
                                    }
                                    else {
                                        if (NEXT_EXPECTED_SEQ == 0 || temp_pkt_timestamp.seq_num == NEXT_EXPECTED_SEQ + temp_pkt_timestamp.pkt_len || packets_after_loss_contains(temp_pkt_timestamp.seq_num, temp_pkt_timestamp.pkt_len) == 1) {
    				                    // if (NEXT_EXPECTED_SEQ == 0 || temp_pkt_timestamp.seq_num == NEXT_EXPECTED_SEQ + temp_pkt_timestamp.pkt_len) {
                                            NEXT_EXPECTED_SEQ = temp_pkt_timestamp.seq_num;

                                            random_ip_id = random_ip_id + 1;
                                            if (LOSS_EMULATION_START == 1) {
                                                ACK_AFTER_LOSS = ACK_AFTER_LOSS + 1;
                                            }
                                            struct send_return ret = send_pkt_ipv4(SOCKET_FD, input_src_ip, random_src_port, input_dst_ip, input_dst_port, 2, random_ip_id, (u_int32_t) SEQ_NUM_GL, (u_int32_t) temp_pkt_timestamp.seq_num, NULL, 0, 0);
                                            ACK_NUM_GL = temp_pkt_timestamp.seq_num;
                                            LAST_SEQ = SEQ_NUM_GL;
                                            LAST_ACK = temp_pkt_timestamp.seq_num;
                                            LAST_ACK_TS = temp_pkt_timestamp.timestamp;
    				                    }
    				                    else {
    				                    	if (DUP_ACKS_SENT > -1 && temp_pkt_timestamp.seq_num > LAST_ACK) {
    				                    		random_ip_id = random_ip_id + 1;
                                                if (LOSS_EMULATION_START == 1) {
                                                    ACK_AFTER_LOSS = ACK_AFTER_LOSS + 1;
                                                }
    				                    		struct send_return ret = send_pkt_ipv4(SOCKET_FD, input_src_ip, random_src_port, input_dst_ip, input_dst_port, 2, random_ip_id, (u_int32_t) LAST_SEQ, (u_int32_t) LAST_ACK, NULL, 0, 0);
    				                    		if (LOSS_EMULATION_START == 1 && temp_pkt_timestamp.seq_num > NEXT_EXPECTED_SEQ + temp_pkt_timestamp.pkt_len) {
    				                    			if (PACKETS_AFTER_LOSS->len == 0) {
    				                    				PACKET_NUMBER_AT_LOSS = PACKET_NUMBER;
    				                    			}
    				                    			g_array_append_val(PACKETS_AFTER_LOSS, temp_pkt_timestamp.seq_num);
                                                    // printf("Adding to PACKETS_AFTER_LOSS: %lu\n", temp_pkt_timestamp.seq_num);
    				                    		}
    				                    	}
    				                    }
                                    }
		                        }
		                    }
		                    else {
		                    	SEND_NO_ACK = 0;
		                    }
		                }
                    }
                    else {
                        break;
                    }
                }
            }
        }
        else {
            // usleep(1000);
        }
    }    
    return NULL;
}

// #################################################################################
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    // printf("\n%s | %u\n\n", "*** OVERLOADED SEND CALLED ***", (unsigned int) len);

    ssize_t (*send_real)(int, const void *, size_t, int)=NULL;
    if (!send_real) {
        send_real=dlsym(RTLD_NEXT,"send");      
    }
    return send_real(sockfd, buf, len, flags);
}

ssize_t write(int sockfd, const void *buf, size_t count) {
    // printf("\n%s | %u\n\n", "*** OVERLOADED WRITE CALLED ***", (unsigned int) count);

    ssize_t (*write_real)(int, const void *, size_t)=NULL;
    if (!write_real) {
        write_real=dlsym(RTLD_NEXT,"write");      
    }
    
    // check file type
    struct stat sb;
    fstat(sockfd, &sb);
    // printf("%s", "FILE TYPE -----------> ");
    switch (sb.st_mode & S_IFMT) {
        case S_IFBLK:
            // printf("block device\n");
            return write_real(sockfd, buf, count);
        case S_IFCHR:
            // printf("character device\n");
            return write_real(sockfd, buf, count);
        case S_IFDIR:
            // printf("directory\n");
            return write_real(sockfd, buf, count);
        case S_IFIFO:
            // printf("FIFO/pipe\n");
            return write_real(sockfd, buf, count);
        case S_IFLNK:
            // printf("symlink\n");
            return write_real(sockfd, buf, count);
        case S_IFREG:
            // printf("regular file\n");
            return write_real(sockfd, buf, count);
        case S_IFSOCK:
            // printf("socket\n");
            return write_socket(sockfd, buf, count);
        default:
            // printf("unknown?\n");
            return write_real(sockfd, buf, count);
    }
}

ssize_t write_socket(int sockfd, const void *buf, size_t len) {
	if (LOG_WRITE == 1)
    	printf("\n%s | %u\n", "*** OVERLOADED SOCKET WRITE CALLED ***", (unsigned int) len);
    // printf("SOCKET LEN: %u\n", (unsigned int) len);

    time_t t;
    srand((unsigned) time(&t));
    int random_ip_id = rand() % 65535;
    
    struct send_return ret = send_pkt_ipv4(sockfd, input_src_ip, random_src_port, input_dst_ip, input_dst_port, 4, random_ip_id, (u_int32_t) SEQ_NUM_GL, (u_int32_t) ACK_NUM_GL, (const char *) buf, len, 1);
    
    if (ret.send_size < 0) {
    	if (LOG_WRITE == 1)
	        printf("sendto not successful\n");
        return -1;        
    }
    else {
    	if (LOG_WRITE == 1)
	        printf("sendto successful | sent: %u %u\n", ret.send_size, ret.send_data_len);   
    }
    // printf("\n\n*** SOCKET WRITE FINISHED ***\n\n");
    return (ssize_t) ret.send_data_len;    
}

// #################################################################################
// int close(int fd) {
//     printf("\n%s\n\n", "*** OVERLOADED CLOSE CALLED ***");
//     if (IS_FIRST_SOCKET_CLOSE == 1) {
//         IS_FIRST_SOCKET_CLOSE = 0;
//         static int (*close_real)(int)=NULL;
//         if (!close_real) {
//             close_real=dlsym(RTLD_NEXT,"close");      
//         }
//         return close_real(fd);
//     }
//     else {
//         free(LEFTOVER_BUFFER);
//         free(LEFTOVER_NXT_PKT_BUFFER);
//         free(SHORT_PKT_BUFFER);
//         return 0;        
//     }
// }