// how to build
// g++ packet-stat.cpp -o packet-stat -lpcap
// I referenced https://github.com/ExploitSori/packet-stat/blob/main/main.cpp.

#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <map>

using namespace std;

typedef struct s{
    int sendCnt;
    int sendBytes;

    int recvCnt;
    int recvBytes;
}s;

int main(int argc, char* argv[]){
    pcap_t *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *data;
    std::map<std::string,s*> m;
    
    if(argc!=2){
        cout<<"usage : "<<argv[0]<<" test.pcap\n";
    } else{
        packet = pcap_open_offline(argv[1],errbuf);
        while(int returnValue = pcap_next_ex(packet,&header,&data)>=0){
            struct ip *ipv4;
            ipv4=(struct ip*)(data+14);
            std::string src(inet_ntoa(ipv4->ip_src));
            std::string dst(inet_ntoa(ipv4->ip_dst));

            if(m.find(src)==m.end()){
                s* tmp_send = (s*)malloc(sizeof(s));
                tmp_send->sendCnt=1;
                tmp_send->sendBytes=header->len;

                tmp_send->recvCnt=0;
                tmp_send->recvBytes=0;
                m.insert(pair<std::string,s*>(src,tmp_send));
            } else{
                m[src]->sendCnt+=1;
                m[src]->sendBytes+=header->len;
            }

            if(m.find(dst)==m.end()){
                s* tmp_recv = (s*)malloc(sizeof(s));
                tmp_recv->sendCnt=0;
                tmp_recv->sendBytes=0;

                tmp_recv->recvCnt=1;
                tmp_recv->recvBytes=header->len;
                m.insert(pair<std::string,s*>(dst,tmp_recv));
            } else{
                m[dst]->recvCnt+=1;
                m[dst]->recvBytes+=header->len;
            }
        }
    
        cout<<"IP\t\t|"<<"Send Packet\t|"<<"Send Bytes\t|"<<"Recv Packet\t|"<<"Recv Bytes\t|\n"; 
        for(auto &i : m){
            cout<<i.first<<"\t|"<<i.second->sendCnt<<"\t\t|"<<i.second->sendBytes<<"\t\t|"<<i.second->recvCnt<<"\t\t|"<<i.second->recvBytes<<"\t\t|\n";
        }

        pcap_close(packet);
    }

    return 0;
}