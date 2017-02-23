//Written to build an IPv4 Server

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

//Port to connect to
#define PORT "1337"
#define MAXPAY 255
#define MAXBUFLEN 1275 //5 packets worth of data
#define STARTID 0xffff
#define ENDID 0xffff
#define DATA 0xfff1
#define ACK 0xfff2
#define REJECT 0xfff3

//Define packet structures
typedef struct datapack {
    unsigned short startid;
    unsigned char clientid;
    unsigned short data;
    unsigned char segnum;
    unsigned char len;
    unsigned char payload[MAXPAY];
    unsigned short endid;
    struct datapack *next;
}datapack;

typedef struct ackpack {
    unsigned short startid;
    unsigned char clientid;
    unsigned short ack;
    unsigned char segnum;
    unsigned short endid;
}ackpack;

typedef struct rejpack {
    unsigned short startid;
    unsigned char clientid;
    unsigned short reject;
    unsigned short subc;
    unsigned char segnum;
    unsigned short endid;
}rejpack;

//Buffer definitions
typedef struct databuf {
    void *data;
    int next;
    size_t size;
}databuf;

//Function Definitions
void *get_addr(struct sockaddr *sa);
int deserialize_data(datapack *data, char buffer[]);
databuf *new_ackbuf();
databuf *new_rejbuf();
int ack(char client, char segnum, int sockfd, struct sockaddr_in theiraddr);
int rej(char client,char segnum, char sub, int sockfd, struct sockaddr_in theiraddr);
void serialize_ack(ackpack pack, databuf *b);
void serialize_short(short x, databuf *b);
void serialize_char(char x, databuf *b);

int main(void)
{
    //Variable declarations
    int sockfd, hostp;
    struct addrinfo hints, *servinfo, *p; //Each is a separate struct. Hints is constant for network. Servinfo is address of server. *p is for buffer
    int ex1; //extra variable for error check
    int numbytes;
    struct sockaddr_storage their_addr;
    struct sockaddr_in clientaddr;
    unsigned char buf[MAXBUFLEN];
    socklen_t addr_len;
    char s[INET_ADDRSTRLEN];
    datapack *out = malloc(sizeof(datapack));
    int count = 0;


    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_DGRAM; //UDP
    hints.ai_flags = AI_PASSIVE; //current computer IP

    //Error Checking to ensure network setup is correct and server matches.
    if((ex1 = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ex1));
        return 1;
    }

    //Create the socket on the server side
    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("Listener Socket Error");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("Listener Binding Error");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "Listener failed to bind to socket.\n");
        return 2;
    }

    //release memory for server info (only needed for error checking)
    freeaddrinfo(servinfo);

    //LOOP START


    while(count < 3)
    {
        //Start 'listening'
        printf("Listener waiting to receive...\n");


        addr_len = sizeof(clientaddr);
        //Receive something and ensure it is something
        if((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1, 0, (struct sockaddr *)&clientaddr, &addr_len)) == -1)
        {
            perror("Nothing received");
            exit(1);
        }




        //Print who sent the data (here 127.0.0.1 because it is the localhost machine)
        printf("listener: got packet from %s\n",
               inet_ntop(clientaddr.sin_family, get_addr((struct sockaddr *)&clientaddr), s, sizeof(s)));
        printf("Address family %d\n", clientaddr.sin_family);

        //Print how long the packet is
        printf("listener: packet is %d bytes long\n", numbytes);
        buf[numbytes] = '\0';

        //Setup for deserialization
        int check = deserialize_data(out,buf);
        if(check == 1){
            printf("Packet Error in Field: %d\n",check);
            rej(out->clientid,out->segnum,check,sockfd,clientaddr);
            break;
        }else if(check == 2){
            printf("Packet Error in Field: %d\n",check);
            rej(out->clientid,out->segnum,check,sockfd,clientaddr);
            break;
        }else if(check == 5){
            printf("Packet Error in Field: %d\n",check);
            rej(out->clientid,out->segnum,check,sockfd,clientaddr);
            break;
        }else if(check == 7){
            printf("Packet Error in Field: %d\n",check);
            rej(out->clientid,out->segnum,check,sockfd,clientaddr);
            break;
        }

        //Check error in segment number
        if(out->segnum != count+1){
            printf("Packet Error in Field 4\n");
            rej(out->clientid,out->segnum,4,sockfd,clientaddr);
            break;
        };


        //Check packet values by eye. Printed in decimal
        printf("start: %d\n",out->startid);
        printf("client: %d\n",out->clientid);
        printf("data: %d\n",out->data);
        printf("Segnum: %d\n",out->segnum);
        printf("len: %d\n",out->len);
        printf("end: %d\n",out->endid);


        ack(out->clientid,out->segnum,sockfd,clientaddr);

        count++;
        memset(out->payload,0,sizeof(out->payload));

        //LOOP END

    }


    //close the socket
    close(sockfd);
    return 0;

}

//gets an address to use
void *get_addr(struct sockaddr *sa)
{
    //returns address of the socket
    return &(((struct sockaddr_in*)sa)->sin_addr);
}

//Gets data out of the packet and error checks to ensure packet follows proper structure.
int deserialize_data(datapack *pack, char buffer[])
{
    int end = ENDID;
    int i = 0;
    int ex1;
    //Error checking line
    //printf("buff[2] = %d buff[5] = %d\n",(u_char) buffer[2],(u_char) buffer[5]);

    //Checks that the first two bytes are ff. Due to adding overflows in chars, adding both would result in 0xfffe
    if((u_char) buffer[0] == 0xff && (u_char) buffer[1] == 0xff){
        pack->startid = STARTID;
    }
    else{
        pack->startid = buffer[0] + buffer[1];
        if(pack->startid != STARTID){
            return 1;
        }
    }
    //Clientid kept for later checks. Single packet are not able to be checked.
    pack->clientid = buffer[2];

    //Checks for correct DATA field in the packet
    if(((u_char) buffer[3] == 0xf1 && (u_char) buffer[4] == 0xff)
            || ((u_char) buffer[3] == 0xff && (u_char) buffer[4] == 0xff1)){
        pack->data = DATA;
    }
    else{
        pack->data = buffer[4] + buffer[3];
        if(pack->data != DATA){
            return 3;
        }
    }

    //Checks segment number. To ensure proper scope, must error check order outside of this function
    pack->segnum = buffer[5];

    //Checks the length of the data.
    pack->len = buffer[6];

    //Get the payload
    while(i<MAXPAY){
        pack->payload[i] = buffer[7+i];
        printf("pack.payload[i] %c\n",pack->payload[i]);
        i++;
    };

    //Check payload length
    ex1 = pack->len;
    if(pack->payload[ex1] != '\0'){
        return 5;
    }


    //Check the ENNDID
    if((u_char) buffer[8+MAXPAY] == 0xff && (u_char) buffer[9+MAXPAY] == 0xff){
        pack->endid = ENDID;
    }
    else{
        pack->endid = buffer[8+MAXPAY] + buffer[9+MAXPAY];
        if(pack->endid != end){
            return 7;
        }
    }

    printf("completed deserialize");
    return 0;

};

//buffer initilizations
databuf *new_ackbuf(){
    databuf *b = malloc(sizeof(ackpack)*2);

    b->data = malloc(sizeof(ackpack));
    b->size = sizeof(ackpack);
    b->next = 0;

    return b;
};

databuf *new_rejbuf(){
    databuf *b = malloc(sizeof(rejpack)*2);

    b->data = malloc(sizeof(rejpack));
    b->size = sizeof(rejpack);
    b->next = 0;
}

int ack(char client, char segnum, int sockfd, struct sockaddr_in theiraddr){

    ackpack *pack = malloc(sizeof(ackpack));
    databuf *packbuff = new_ackbuf();
    int numbytes;
    int addr_len = sizeof(theiraddr);

    pack->startid = STARTID;
    pack->clientid = client;
    pack->ack = ACK;
    pack->segnum = segnum;
    pack->endid = ENDID;
    serialize_ack(*pack, packbuff);


    numbytes = sendto(sockfd, packbuff->data, packbuff->size, 0, (struct sockaddr *)&theiraddr, addr_len);
    if(numbytes == -1)
    {
        perror("Ack Failed\n");
        exit(1);
    } else{
        printf("Ack Sent\n");
    }
    free(pack);
    free(packbuff);

};

int rej(char client,char segnum, char sub, int sockfd, struct sockaddr_in theiraddr) {

    rejpack *pack = malloc(sizeof(rejpack));
    databuf *packbuff = new_rejbuf();
    int numbytes;
    int addr_len = sizeof(theiraddr);

    pack->startid = STARTID;
    pack->clientid = client;
    pack->reject = REJECT;
    pack->subc = sub;
    pack->segnum = segnum;
    pack->endid = ENDID;

    serialize_rej(*pack,packbuff);
    numbytes = sendto(sockfd, packbuff->data, packbuff->size, 0, (struct sockaddr *)&theiraddr, addr_len);
    if(numbytes == -1)
    {
        perror("Rej Failed\n");
        exit(1);
    } else{
        printf("Rej Sent\n");
    }
    free(pack);
    free(packbuff);
};

void serialize_ack(ackpack pack, databuf *b){
    serialize_short(pack.startid,b);
    serialize_char(pack.clientid,b);
    serialize_short(pack.ack,b);
    serialize_char(pack.segnum,b);
    serialize_short(pack.endid,b);
};

void serialize_rej(rejpack pack, databuf *b){
    serialize_short(pack.startid,b);
    serialize_char(pack.clientid,b);
    serialize_short(pack.reject,b);
    serialize_short(pack.subc,b);
    serialize_char(pack.segnum,b);
    serialize_short(pack.endid,b);

};

void serialize_short(short x, databuf *b){
    memcpy(((char *)b->data) + b->next, &x, sizeof(short));
    b->next += sizeof(short);
};
void serialize_char(char x, databuf *b){
    memcpy(((char *)b->data)+ b->next,&x,sizeof(char));
    b->next += sizeof(char);
};