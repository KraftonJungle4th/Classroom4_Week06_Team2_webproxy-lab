/* IP socket adress 구조체 */
#include "csapp.h"

void fragments()
{
    int clientfd; // 클라이언트 파일 디스크립터

    /* $begin socketcall */
    clientfd = Socket(AF_INET, SOCK_STREAM, 0); // Socket 래퍼 사용하여 소캣 생성 후, 클라이언트 파일 디스크립터에 할당
    /* $end socketcall */

    clientfd = clientfd; /* keep gcc happy */ //?

    /* $begin inaddr */
    /* IP address structure */
    struct in_addr
    {                    // 인터넷 주소 구조체
        uint32_t s_addr; // 네트워크 바이트 순서(빅 엔디안)로 저장된 IP 주소, 함수로 변환을 사용하여 일관된 데이터 형식을 유지하게 함
    };
    /* $end inaddr */

    /* $begin addrinfo */
    struct addrinfo
    {
        int ai_flags;             // 입력 플래그에 대한 힌트, 추가 옵션을 지정한다고 함
        int ai_family;            // 주소 패밀리 지정(IPv4, IPv6)
        int ai_socktype;          // 소켓 타입 지정, TCP 혹은 UDP
        int ai_protocol;          // 프로토콜 지칭, 대부분의 경우 기본 프로토콜을 사용하기 때문에 0으로 사용
        char *ai_canonname;       // 요청된 호스트의 정규화된 이름, 위에서 플래그를 설정했을 때만 살정됨
        size_t ai_addrlen;        // ai_addr이 가리키는 주소의 크기를 바이트 단위로 저장
        struct sockaddr *ai_addr; // 실제 주소를 담고 있는 'sockaddr'을 가리키는 포인터
        struct addrinfo *ai_next; // 같은 호스트와 서비스에 대해 다음 addrinfo 구조체의 연결 리스트 주소를 가리킴
    };
    /* $end addrinfo */

    /* $begin sockaddr */
    /* internet을 위해 사용되는 IP socket address 구조체 */
    struct sockaddr_in
    {
        uint16_t sin_family;       // 프로토콜 패밀리를 지정함. IPv4의 경우 AF_INET
        uint16_t sin_port;         // 포트 번호를 네트워크 바이트 순서인 빅 엔디안으로 지정
        struct in_addr sin_addr;   // in_addr 구조체를 사용해서 ip 주소를 네트워크 바이트 순서로 저장
        unsigned char sin_zero[8]; // 밑의 sock_addr과 크기에 맞추기 위한 패딩
    };

    /* connect, bind, accept 등에 사용될 범용적인 socket address 구조체 */
    struct sockaddr
    {
        uint16_t sa_family; // 프로토콜 패밀리를 지정함.
        char sa_data[14];   // 실제 주소 데이터. 형식과 내용은 sa_family에 의해 결정됨.
    };
    /* $end sockaddr */
}