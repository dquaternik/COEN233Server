//Written to build an IPv4 Network Permission Verification Server

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
#define MAXPAY 5
#define MAXBUFLEN 15 //packets worth of data
#define STARTID 0xffff
#define ENDID 0xffff
#define ACCPER 0xfff8
#define NPAID 0xfff9
#define DNE 0xfffa
#define PAID 0xfffb


//Define packet structures
typedef struct packet {
    unsigned short startid;
    unsigned char clientid;
    unsigned short mess;
    unsigned char segnum;
    unsigned char len;
    unsigned char tech;
    unsigned int ssnum;
    unsigned short endid;
} packet;

typedef struct dbpack {
    unsigned int ssnum;
    unsigned char tech;
    unsigned char paid;
}dbpack;


//Buffer definition
typedef struct databuf {
    void *data;
    int next;
    size_t size;
}packbuff;

//Function Definitions
void *get_addr(struct sockaddr *sa);
packet *create_pack(unsigned short mess, unsigned char client, unsigned char tec, unsigned int ssn);
int deserialize(packet *pack, char buffer[]);
void serialize_pack(packet pack, packbuff *b);
void serialize_short(short x, packbuff *b);
void serialize_char(char x, packbuff *b);
void serialize_int(int x, packbuff *b);
packbuff *new_buffer();
int checkdb(FILE *db,unsigned int ssn,unsigned char tech);
void deserialize_db(dbpack *db,char buf[]);

int main(void)
{
    //Variable declarations
    int sockfd, hostp;
    struct addrinfo hints, *servinfo, *p; //Each is a separate struct. Hints is constant for network. Servinfo is address of server. *p is for buffer
    int ex1, check; //extra variable for error check
    int numbytes;
    struct sockaddr_storage their_addr;
    struct sockaddr_in clientaddr;
    unsigned char buf[MAXBUFLEN];
    socklen_t addr_len;
    char s[INET_ADDRSTRLEN];
    packet *out = malloc(sizeof(packet));
    packet *resp;
    packbuff *respbuf = new_buffer();


    /*
     *
     * CREATE DATABASE FILE HERE
     *
     */
    FILE *db;

    db = fopen("C:\\Users\\Devon\\CLionProjects\\PA2Serv\\database.txt","r");
    if(db == NULL){
        perror("Database Error");
        exit(-1);
    }


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
    check = deserialize(out,buf);

    //Check packet values by eye. Printed in decimal
    printf("start: %u\n",out->startid);
    printf("client: %u\n",out->clientid);
    printf("Message: %u\n",out->mess);
    printf("Segnum: %u\n",out->segnum);
    printf("len: %u\n",out->len);
    printf("tech: %u\n",out->tech);
    printf("SSNUM: %u\n",out->ssnum);
    printf("end: %d\n",out->endid);


    if(check != 0){
        perror("Error in received packet");
        exit(-check);
    }

    //Check error in segment number
    if(out->segnum != 1){
        printf("Packet Segnum Error\n");

    };




    //Check the database, returns a value of PAID, NPAID, DNE, or -1 for general error
    check = checkdb(db,out->ssnum,out->tech);
    printf("check: %d\n",check);
    //create response packet based on database check
    resp = create_pack((unsigned short)check,out->clientid,out->tech,out->ssnum);
    serialize_pack(*resp,respbuf);

    //send the response
    numbytes = sendto(sockfd, respbuf->data, respbuf->size, 0, (struct sockaddr *)&clientaddr, addr_len);
    if(numbytes == -1)
    {
        perror("Ack Failed\n");
        exit(1);
    } else{
        printf("Ack Sent\n");
    }

    //close the socket
    close(sockfd);
    return 0;

};


//gets an address to use
void *get_addr(struct sockaddr *sa)
{
    //returns address of the socket
    return &(((struct sockaddr_in*)sa)->sin_addr);
}

//Gets data out of the packet and error checks to ensure packet follows proper structure.
int deserialize(packet *pack, char buffer[]){
    int end = ENDID;
    int ex1;
    char buf1[MAXPAY];

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

    //Checks message field for Acc_Per, Paid, Not Paid, or Does Not Exist
    if((u_char) buffer[3] == 0xff && (u_char) buffer[4] == 0xf8
       || (u_char) buffer[3] == 0xf8 && (u_char) buffer[4] == 0xff){

        pack->mess = ACCPER;

    } else if((u_char) buffer[3] == 0xff && (u_char) buffer[4] == 0xf9
              || (u_char) buffer[3] == 0xf9 && (u_char) buffer[4] == 0xff){

        pack->mess = NPAID;

    } else if((u_char) buffer[3] == 0xff && (u_char) buffer[4] == 0xfa
              || (u_char) buffer[3] == 0xfa && (u_char) buffer[4] == 0xff){

        pack->mess = DNE;

    }else if((u_char) buffer[3] == 0xff && (u_char) buffer[4] == 0xfb
             || (u_char) buffer[3] == 0xfb && (u_char) buffer[4] == 0xff){

        pack->mess = PAID;

    } else {

        pack->mess = buffer[3] + buffer[4];
    }

    //Checks segment number. To ensure proper scope, must error check order outside of this function
    pack->segnum = buffer[5];

    //Checks the length of the data.
    pack->len = buffer[6];

    //Get the payload
    pack->tech = buffer[7];

    pack->ssnum = (u_char) buffer[11];
    pack->ssnum <<= 8;
    pack->ssnum |= (u_char) buffer[10];
    pack->ssnum <<= 8;
    pack->ssnum |= (u_char) buffer[9];
    pack->ssnum <<= 8;
    pack->ssnum |= (u_char) buffer[8];

    //Check payload length
    ex1 = sizeof(pack->tech)+sizeof(pack->ssnum);
    if(pack->len != ex1){
        return 5;
    }


    //Check the ENNDID
    if((u_char) buffer[12] == 0xff && (u_char) buffer[13] == 0xff){
        pack->endid = ENDID;
    }
    else{
        pack->endid = buffer[12] + buffer[13];
        if(pack->endid != end){
            return 7;
        }
    }

    printf("completed deserialize\n");
    return 0;

};

//buffer initilization
packbuff *new_buffer(){
    packbuff *b = malloc(sizeof(packet)*2);

    b->data = malloc(sizeof(packet));
    b->size = sizeof(packet);
    b->next = 0;

    return b;
};


//Create response packet
packet *create_pack(unsigned short mess, unsigned char client, unsigned char tec, unsigned int ssn) {
    int nsegs = 1; //Only need 1 segment, this is only a verification server
    packet *sendpack = malloc(sizeof(packet));

    //initialize all the constant data
    sendpack->startid = STARTID;
    sendpack->clientid = client;
    sendpack->mess = mess;
    sendpack->segnum = nsegs;
    sendpack->len = MAXPAY;

    //insert payload into the packet
    sendpack->tech = tec;
    sendpack->ssnum = ssn;

    //Insert endid
    sendpack->endid = ENDID;

    return sendpack;
}

//Serialize packet
void serialize_pack(packet pack, packbuff *b){
    serialize_short(pack.startid,b);
    serialize_char(pack.clientid,b);
    serialize_short(pack.mess,b);
    serialize_char(pack.segnum,b);
    serialize_char(pack.len,b);
    serialize_char(pack.tech,b);
    serialize_int(pack.ssnum,b);
    serialize_short(pack.endid,b);

};


//Serialize by data size
void serialize_short(short x, packbuff *b) {
    memcpy(((char *)b->data) + b->next, &x, sizeof(short));
    b->next += sizeof(short);
};


void serialize_char(char x, packbuff *b) {
    //reserve(b,sizeof(char));
    memcpy(((char *)b->data)+ b->next,&x,sizeof(char));
    b->next += sizeof(char);
};

void serialize_int(int x, packbuff *b){
    memcpy(((char *)b->data) + b->next, &x,sizeof(int));
    b->next += sizeof(int);
};

//Check the database if subscriber exists, if their technology is allowed, and if they're paid
int checkdb(FILE *db,unsigned int ssn,unsigned char tech){
    int check = 0;
    int buflen = 0;
    char *buf=NULL;
    dbpack *dbln = malloc(sizeof(dbpack));

    //check db line by line to get ssn
    while(check != -1){
        check = getline(&buf,&buflen,db);
        printf("line: %s\n",buf);
        deserialize_db(dbln,buf);
        printf("dbln->ssnum = %u\n",dbln->ssnum);
        if(dbln->ssnum == ssn){
            break;
        }
    }

    if(dbln->ssnum != ssn){
        return DNE;
    }if(dbln->tech != tech){
        return -1;
    }if(dbln->paid == 1){
        return PAID;
    }else {
        return NPAID;
    }

};

//deserialize the buffer into a dbln packet
void deserialize_db(dbpack *db,char buf[]){

    char ex[11];
    for(int i = 0; i<10;i++){
        ex[i] = buf[i];
    }
    ex[10] = '\0';

    db->ssnum = atoi(ex);
    printf("db.ssnum: %u\n",db->ssnum);


    db->tech = buf[12]-'0';
    printf("db.tech: %u\n",db->tech);
    db->paid = buf[14]-'0';
    printf("db.paid: %u\n",db->paid);

};