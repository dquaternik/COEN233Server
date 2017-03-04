//IPv4 client that requests from verification server. Server responds and this interprets the message
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>


#define SERVER "1337" //Server Port
#define CLIENTID 0x45  //client id number
#define SSNUM 0xf3847f35 //Source subscriber number
#define TECH 04

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

//create buffers
typedef struct databuf {
    void *data;
    int next;
    size_t size;
}packbuff;


//Function definitions
packet *create_pack(short mess, unsigned char client, unsigned char tec, unsigned int ssn);
void serialize_pack(packet pack, packbuff *b);
void serialize_short(short x, packbuff *b);
void serialize_char(char x, packbuff *b);
void serialize_int(int x, packbuff *b);
packbuff *new_buffer();
int deserialize(packet *pack, char buffer[]);

//Takes in an ip address (localhost for client on same computer) and string to send.
int main(){
    //variable initializations
    struct addrinfo hints, *servinfo, *p;
    int sockfd, check, rv, numbytes, res;
    struct sockaddr_in their_addr;
    packbuff *b = new_buffer();
    unsigned char buf1[MAXBUFLEN];
    struct pollfd fd;
    int count1 = 0;
    packet *recv = malloc(sizeof(packet));

    //Create Verfication Message
    packet *send = create_pack(ACCPER,CLIENTID,TECH,SSNUM);

    //Serialize the packet to send
    serialize_pack(*send,b);

    //Setup hints for network
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    //Make sure your and server networks are the same and you have the correct address.
    if ((rv = getaddrinfo("localhost", SERVER, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    //Create a socket with the required parameters.
    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("Socket error\n");
            continue;
        }
        break;
    }

    //Setup polling
    fd.fd = sockfd;
    fd.events = POLLIN;

    //error check the socket was created properly
    if (p == NULL)
    {
        fprintf(stderr, "Socket not created\n");
        return 2;
    }

    //send the packet to the server
    numbytes = sendto(sockfd, b->data, b->size, 0, p->ai_addr, p->ai_addrlen);
    if (numbytes == -1)
    {
        perror("Sendto error\n");
        exit(1);
    }

    //wait for result from server (This is ack_timer)
    while(count1 < 2){
        res = poll(&fd,1,3000);
        if(res == 0) {
            //timeout
            //resend + increment count
            numbytes = sendto(sockfd, b->data, b->size, 0, p->ai_addr, p->ai_addrlen);
            if (numbytes == -1)
            {
                perror("Sendto error\n");
                exit(1);
            }
            count1++;

        }
        else if(res == -1) {
            //error
            perror("poll error\n");
            return res;

        } else {
            //Receive the result packet
            socklen_t len = sizeof(their_addr);
            int numbytes = recvfrom(sockfd,buf1,MAXBUFLEN-1, 0,&their_addr, &len);
            if(numbytes == -1){
                perror("Response reception error\n");
                exit(1);
            }
            break;
        };
    }

    //Deserialize the data and interpret what to do
    check = deserialize(recv,buf1);
    if(check == 1){
        perror("Missing Start ID\n");
        exit(1);
    }else if(check == 5){
        perror("Length does not match payload\n");
        exit(5);
    }else if(check == 7){
        perror("Missing End ID\n");
        exit(7);
    };

    //free memory from server info after sending and close the socket and turn off client
    
    printf("talker: sent %d bytes to %s\n",numbytes, "localhost");
    

    //interpret message and free the received data then close out
    if(recv->mess == NPAID){
        perror("Subscriber has not paid\n");
        return -1;
    } else if(recv->mess == DNE){
        perror("Subscriber does not exist\n");
        free(recv);
        return -2;
    }else if(recv->mess == PAID){
        printf("Verification Success\n");
        return 0;
    }else if(recv->mess == 4){
        printf("Tech level not allowed");
        return -4;
    } else {
        perror("Error reading data, please try again later\n");
        return -3;
    }
};


//databuffer initilization
packbuff *new_buffer(){
    packbuff *b = malloc(sizeof(packet)*2);

    b->data = malloc(sizeof(packet));
    b->size = sizeof(packet);
    b->next = 0;

    return b;
};

//Create access permission packet
packet *create_pack(short mess, unsigned char client, unsigned char tec, unsigned int ssn) {
    const int nsegs = 1; //only need 1 packet to verify paid
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

    printf("start: %d\n",sendpack->startid);
    printf("client: %d\n",sendpack->clientid);
    printf("Message: %d\n",sendpack->mess);
    printf("Segnum: %d\n",sendpack->segnum);
    printf("len: %d\n",sendpack->len);
    printf("tech: %d\n",sendpack->tech);
    printf("SSNUM: %u\n",sendpack->ssnum);
    printf("end: %d\n",sendpack->endid);

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
    memcpy(((char *)b->data)+ b->next,&x,sizeof(char));
    b->next += sizeof(char);
};

void serialize_int(int x, packbuff *b){
    memcpy(((char *)b->data) + b->next, &x,sizeof(int));
    b->next += sizeof(int);
};

//Deserialize PAID,NPAID, or DNE
int deserialize(packet *pack, char buffer[]){
    int end = ENDID;
    int ex1;

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
    pack->ssnum = buffer[8] + buffer[9] + buffer[10] +buffer[11];

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

};//

