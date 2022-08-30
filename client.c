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
#include <shadow.h>
#include <crypt.h>
#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "./ca_client" 
#define SERVER_IP "10.0.2.8" 
struct sockaddr_in peerAddr;

int login(char *user, char *passwd)
{
	struct spwd *pw;
	char *epasswd;
	pw = getspnam(user);
	if (pw == NULL) {
		return -1;
	}
	printf("Login name: %s\n", pw->sp_namp);
	printf("Passwd : %s\n", pw->sp_pwdp);
	epasswd = crypt(passwd, pw->sp_pwdp);
	if (strcmp(epasswd, pw->sp_pwdp)) {
		return -1;
	}
	return 1;
}
int createTunDevice() {
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
	
	tunfd = open("/dev/net/tun", O_RDWR);
	ioctl(tunfd, TUNSETIFF, &ifr);       
	
	return tunfd;
}

int connectToUDPServer(){
    int sockfd;
    char *hello="Hello";

    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(PORT_NUMBER);
    peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Send a hello message to "connect" with the VPN server
    sendto(sockfd, hello, strlen(hello), 0,
                (struct sockaddr *) &peerAddr, sizeof(peerAddr));

    return sockfd;
}
int setupTCPClient()
{
    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(PORT_NUMBER);
    peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

   struct sockaddr_in server_addr;

   // Get the IP address from hostname
   struct hostent* hp = gethostbyname("www.bank32.com");

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
   server_addr.sin_port   = htons (55555);
   server_addr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr,
           sizeof(server_addr));
    // char *hello="Hello";
    // sendto(sockfd, hello, strlen(hello), 0,
    //             (struct sockaddr *) &peerAddr, sizeof(peerAddr));
   return sockfd;
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
	printf("Error setting the verify locations. \n");
	exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}
void tunSelected(SSL *ssl,int tunfd, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    printf("Server: Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    //sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
    //                sizeof(peerAddr));
    SSL_write(ssl, buff, len);
}

void socketSelected (SSL *ssl,int tunfd, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    printf("Server: Got a packet from the client tunnel\n");

    bzero(buff, BUFF_SIZE);
    //len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    len = SSL_read (ssl, buff, sizeof(buff) - 1);
    write(tunfd, buff, len);

}
int main (int argc, char * argv[]) {

    char* user;
    char* password;
    int r = login(argv[1], argv[2]);
    printf("Result: %d\n", r);
    // int r = login(user, password);

    if(r!=1){
        printf("login failed\n");
        return 0;
    }
    char* tunip = argv[3];
    // printf("input tun ip:");
    // scanf("%s\n",tunip);
    // char* command1 = "ip addr add ";
    // strcat(command1, tunip);
	// printf("cmd1: %s\n", command1);
    // fflush(stdout);
    // strcat(command1, "/24 dev tun0");
    char command1[100], command2[100], command3[100];
    sprintf(command1, "ip addr add %s/24 dev tun0", tunip);
    sprintf(command2, "ip route add 192.168.60.0/24 dev tun0 via %s", tunip);
    sprintf(command3, "ip route add 192.168.78.0/24 dev tun0 via %s", tunip);
    printf("cmd1: %s\n", command1);
    printf("cmd2: %s\n", command2);
    printf("cmd3: %s\n", command3);
    fflush(stdout);
	int tunfd, sockfd;

	tunfd  = createTunDevice();
    printf("finish setupTCPClient\n");
	system(command1);
	system("ip link set dev tun0 up ");
	system(command2);
	system(command3);


    /*----------------TLS initialization ----------------*/
    char *hostname = "www.bank32.com";
    SSL *ssl   = setupTLSClient(hostname);printf("abc");

    /*----------------Create a TCP connection ---------------*/
    sockfd = setupTCPClient();printf("abc");


    /*----------------TLS handshake ---------------------*/
    SSL_set_fd(ssl, sockfd);printf("***");
    int err = SSL_connect(ssl);printf("###"); CHK_SSL(err);printf("!!!");
    printf("SSL connection is successful\n");
    printf ("SSL connection using %s\n", SSL_get_cipher(ssl));printf("abc");

    /*----------------Send/Receive data --------------------*/
    char sendBuf[200];
    char *hello="Hello";
    sprintf(sendBuf, "Hello");
    SSL_write(ssl, sendBuf, strlen(sendBuf));


	// Enter the main loop
	while (1) {
		fd_set readFDSet;
		
		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
		
		if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(ssl, tunfd, sockfd);
		if (FD_ISSET(sockfd, &readFDSet)) socketSelected(ssl, tunfd, sockfd);
	}
}
