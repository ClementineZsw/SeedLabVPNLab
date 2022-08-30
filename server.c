#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <netdb.h>
#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

struct sockaddr_in peerAddr;

int createTunDevice() {
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
	
	tunfd = open("/dev/net/tun", O_RDWR);
	ioctl(tunfd, TUNSETIFF, &ifr);       
	
	return tunfd;
}

int initUDPServer() {
    int sockfd;
    struct sockaddr_in server;
    char buff[100];

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;                 
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_NUMBER);        

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(sockfd, (struct sockaddr*) &server, sizeof(server)); 

    // Wait for the VPN client to "connect".
    bzero(buff, 100);
    int peerAddrLen = sizeof(struct sockaddr_in);
    int len = recvfrom(sockfd, buff, 100, 0,                  
                (struct sockaddr *) &peerAddr, &peerAddrLen);

    printf("Connected with the client: %s\n", buff);
    return sockfd;
}
int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (PORT_NUMBER);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    // char buff[100];
    // bzero(buff, 100);
    // int peerAddrLen = sizeof(struct sockaddr_in);
    // int len = recvfrom(listen_sock, buff, 100, 0,                  
    //             (struct sockaddr *) &peerAddr, &peerAddrLen);
    
    return listen_sock;
}
void tunSelected(SSL *ssl,int tunfd){
    int  len;
    char buff[BUFF_SIZE];

    printf("Server: Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    //sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
    //                sizeof(peerAddr));
    SSL_write(ssl, buff, len);
}

void socketSelected (SSL *ssl,int tunfd){
    int  len;
    char buff[BUFF_SIZE];

    printf("Server: Got a packet from the client tunnel\n");

    bzero(buff, BUFF_SIZE);
    //len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    len = SSL_read (ssl, buff, sizeof(buff) - 1);
    write(tunfd, buff, len);

}
int main (int argc, char * argv[]) {
	int tunfd, sockfd;

	tunfd  = createTunDevice();
    system("ip addr add 192.168.78.100/24 dev tun0");
	system("ip link set dev tun0 up ");
	system("ip route add 192.168.53.0/24 dev tun0 via 192.168.78.100");
    //--------------------------about ssl-----------------------------
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;

    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    // Step 1: SSL context initialization
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    printf("finish set_verify\n");
    // Step 2: Set up the server certificate and private key
    SSL_CTX_use_certificate_file(ctx, "./cert_server/server.crt", SSL_FILETYPE_PEM);
    printf("finish certificate\n");
    SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server.key", SSL_FILETYPE_PEM);
    printf("finish PrivateKey_file\n");
    // Step 3: Create a new SSL structure for a connection
    ssl = SSL_new (ctx);


    struct sockaddr_in sa_client;
    size_t client_len;
    int listen_sock = setupTCPServer();
    printf("finish setupTCPServer\n");

	
    while(1){
        sockfd = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
        printf("accept one client\n");
        if (fork() == 0) { // The child process
            close (listen_sock);
            SSL_set_fd (ssl, sockfd);
            int err = SSL_accept (ssl);
            CHK_SSL(err);
            printf ("SSL connection established!\n");
        

            // Enter the main loop
            while (1) {
                fd_set readFDSet;
                
                FD_ZERO(&readFDSet);
                FD_SET(sockfd, &readFDSet);
                FD_SET(tunfd, &readFDSet);
                select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
                
                if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(ssl, tunfd);
                if (FD_ISSET(sockfd, &readFDSet)) socketSelected(ssl, tunfd);
            }
            close(sockfd);
            return 0;
        } else { // The parent process
            close(sockfd);
        }
        
    }



    
}
