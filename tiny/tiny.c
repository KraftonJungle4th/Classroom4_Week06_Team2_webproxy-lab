/* $begin tinymain */
/*
 * tiny.c - GET 메서드를 사용하여 정적 및 동적 콘텐츠를 제공하는 간단한 반복형 HTTP/1.0 웹 서버입니다.
 */
#include "csapp.h"

void doit(int fd);
void read_requesthdrs(rio_t *rp);
int parse_uri(char *uri, char *filename, char *cgiargs);
void serve_static(int fd, char *filename, int filesize);
void get_filetype(char *filename, char *filetype);
void serve_dynamic(int fd, char *filename, char *cgiargs);
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg);

/* main - 서버의 메인 함수로, 리스닝 소켓을 열고,
 *         클라이언트로부터의 연결 요청을 무한히 대기함.
 */
int main(int argc, char **argv) // argc - 명령줄에 들어온 인자 개수를 저장함, argv - 명령줄 인자를 가리키는 포인터 배열. 포트 번호를 인자로 받음
{
  int listenfd, connfd;                  // 리스닝 소켓 파일 디스크립터, 연결 소켓 파일 디스크립터
  char hostname[MAXLINE], port[MAXLINE]; // hostname과 port를 char형 배열로 받아옴
  socklen_t clientlen;                   // 클라이언트 주소 길이를 저장할 변수
  struct sockaddr_storage clientaddr;    // sockaddr_storage 구조체를 이용하여 clientaddr 저장

  listenfd = Open_listenfd(argv[1]); // Open_listenfd 래퍼를 호출하여 지정된 포트에서 연결 요청을 기다리도록 리스닝 소켓을 엶.

  /* 커맨드 라인에 올바른 인자 수가 들어왔는지 확인 */
  if (argc != 2) // 포트 번호 하나만을 받으므로, 인자의 개수는 {파일이름} {포트번호} 두개여야 함
  {
    fprintf(stderr, "usage: %s <port>\n", argv[0]); // 올바른 사용법을 알려주고 종료함
    exit(1);
  }

  while (1) // 무한 루프를 통해 연결 요청을 계속해서 받음
  {
    clientlen = sizeof(clientaddr);                                                 // client_addr구조체의 크기 저장
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);                       // Accept를 통해 새로운 연결 소켓 생성
    Getnameinfo((SA *)&clientaddr, clientlen, hostname, MAXLINE, port, MAXLINE, 0); // Getnameinfo를 통해 클라이언트에게 전송하기 위한 클라이언트의 호스트 이름과 포트 번호를 가져옴
    printf("Accepted connection from (%s, %s)\n", hostname, port);                  // 클라이언트의 호스트 이름과 포트 번호를 출력
    doit(connfd);                                                                   // connfd를 통해 HTTP 처리
    Close(connfd);                                                                  // 처리가 완료되면 연결 connfd를 종료시킴
  }
}
/* $end tinymain */

/*
 * doit - 한 개의 HTTP 요청/응답 트랜잭션을 처리함.
 */
/* $begin doit */
void doit(int fd) // 연결을 나타내는 디스크립터
{
  int is_static;                                                      // 요청이 정적인 콘텐츠인지, 동적인 콘텐츠인지 나타내는 플래그
  struct stat sbuf;                                                   // 파일의 정보(파일 크기, 수정 날짜, 권한)를 sbuf에 저장. 이를 통해 파일이 정적인지 실행 가능한지 판단함.
  char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE]; // 클라이언트로부터 받은 전체 요청 저장.
  char filename[MAXLINE], cgiargs[MAXLINE];                           // filename - 클라이언트가 요청한 파일의 이름 저장. cgiargs - 동적 콘텐츠 요청시 스크립트에 전달될 인자 저장
  rio_t rio;                                                          // 버퍼 입력 함수를 위한 변수 선언

  /* 클라이언트로부터 요청 라인과 요청 헤더를 읽어들임 */
  Rio_readinitb(&rio, fd);                       // Rio 읽기 작업 위해 버퍼 초기화
  Rio_readlineb(&rio, buf, MAXLINE);             // Rio 읽기 작업 수행, 한 줄을 읽어옴
  sscanf(buf, "%s %s %s", method, uri, version); // sscanf - 데이터를 읽어서 변수에 저장
  if (strcasecmp(method, "GET"))                 // 메서드가 GET인지 확인
  {
    clienterror(fd, method, "501", "Not Implemented", // 클라이언트에게 에러 전달
                "Tiny does not implement this method");
    return;
  }
  read_requesthdrs(&rio); // 헤더를 읽긴 하지만 별다른 조치를 취하지 않음

  /* GET 요청으로부터 온 uri를 파싱함 */
  is_static = parse_uri(uri, filename, cgiargs); // uri 파싱하여 정적 콘텐츠인지 동적 콘텐츠인지 결정
  if (stat(filename, &sbuf) < 0)                 // 파일이름을 버퍼에 저장(stat buffer)
  {
    clienterror(fd, filename, "404", "Not found",
                "Tiny couldn't find this file");
    return;
  }

  if (is_static)
  {                                                            /* 정적 컨텐츠 서비스 */
    if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) // sbuf.st_mode가 일반 파일인지 검사, S_IRUSR -  파일 소유자가 읽기 권한을 갖고 있는지 검사
    {
      clienterror(fd, filename, "403", "Forbidden", // 둘 중 하나라도 조건 걸리면 403 반환
                  "Tiny couldn't read the file");
      return;
    }
    serve_static(fd, filename, sbuf.st_size); // 정적 파일 제공
  }
  else
  {                                                            /* 동적 컨텐츠 서비스 */
    if (!(S_ISREG(sbuf.st_mode)) || !(S_IXUSR & sbuf.st_mode)) // sbuf.st_mode가 일반 파일인지 검사, S_IRUSR -  파일 소유자가 읽기 권한을 갖고 있는지 검사
    {
      clienterror(fd, filename, "403", "Forbidden", // 위에 조건에 걸리면 CGI 프로그램 구동 불가, 403 반환
                  "Tiny couldn't run the CGI program");
      return;
    }
    serve_dynamic(fd, filename, cgiargs); // 동적 파일 제공
  }
}
/* $end doit */

/*
 * read_requesthdrs - HTTP 요청 헤더를 읽고, 파싱함
 */
/* $begin read_requesthdrs */
void read_requesthdrs(rio_t *rp)
{
  char buf[MAXLINE]; // MAXLINE 길이의 문자열 배열 buf 선언

  Rio_readlineb(rp, buf, MAXLINE); // rp를 통해 한 줄을 읽어 buf에 저장
  while (strcmp(buf, "\r\n"))
  { // 빈 줄을 만날 때까지 읽음
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
  }
  return;
}
/* $end read_requesthdrs */

/*
 * parse_uri - URI를 파일 이름과 CGI의 인자로 파싱함
 *             0 반환 - 동적 콘텐츠임을 의미
 *             1 반환 - 정적 콘텐츠임을 의미
 */
/* $begin parse_uri */
int parse_uri(char *uri, char *filename, char *cgiargs)
{
  char *ptr;
  
  if (!strstr(uri, "cgi-bin")) /* 정적 콘텐츠 */
  {
    strcpy(cgiargs, "");
    strcpy(filename, ".");

    // .html 파일 요청을 처리
    if (strstr(uri, ".html"))
    {
      strcat(filename, uri);
    }
    else if (uri[strlen(uri) - 1] == '/')
    {
      // URI에 .html이 포함되어 있는 경우
      strcat(filename, "home.html");
    }
    else
    {
      // 다른 정적 콘텐츠 요청 처리
      strcat(filename, uri);
    }

    return 1;
  }

  /* 동적 컨텐츠 */
  ptr = index(uri, '?');

  if (ptr)
  {
    strcpy(cgiargs, ptr + 1);
    *ptr = '\0';
  }
  else
  {
    strcpy(cgiargs, "");
  }

  strcpy(filename, ".");
  strcat(filename, uri);

  return 0;
}
/* $end parse_uri */

/*
 * serve_static - 클라이언트에게 파일을 복사하여 제공
 */
/* $begin serve_static */
void serve_static(int fd, char *filename, int filesize)
{
  int srcfd;
  char *srcp, filetype[MAXLINE], buf[MAXBUF];

  /* 클라이언트에게 응답 헤더 전송 */
  get_filetype(filename, filetype);
  sprintf(buf, "HTTP/1.0 200 OK\r\n");
  sprintf(buf, "%sServer: Tiny Web Server\r\n", buf);
  sprintf(buf, "%sConnection: close\r\n", buf);
  sprintf(buf, "%sContent-length: %d\r\n", buf, filesize);
  sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, filetype);
  Rio_writen(fd, buf, strlen(buf));
  printf("Response headers:\n"); // 응답 헤더를 출력
  printf("%s", buf);

  /* 클라이언트에게 응답 본문(body) 전송 */
  srcfd = Open(filename, O_RDONLY, 0);
  srcp = Mmap(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
  Close(srcfd);
  Rio_writen(fd, srcp, filesize);
  Munmap(srcp, filesize);
}

/*
 * get_filetype - 파일 이름에서 파일 타입을 도출해내는 함수
 */
void get_filetype(char *filename, char *filetype)
{
  if (strstr(filename, ".html"))
    strcpy(filetype, "text/html");
  else if (strstr(filename, ".gif"))
    strcpy(filetype, "image/gif");
  else if (strstr(filename, ".jpg"))
    strcpy(filetype, "image/jpeg");
  else
    strcpy(filetype, "text/plain");
}
/* $end serve_static */

/*
 * serve_dynamic - 클라이언트를 대신하여 CGI 프로그램을 실행하는 함수
 */
/* $begin serve_dynamic */
void serve_dynamic(int fd, char *filename, char *cgiargs)
{
  char buf[MAXLINE], *emptylist[] = {NULL};

  /* Return first part of HTTP response */
  sprintf(buf, "HTTP/1.0 200 OK\r\n");
  Rio_writen(fd, buf, strlen(buf));
  sprintf(buf, "Server: Tiny Web Server\r\n");
  Rio_writen(fd, buf, strlen(buf));

  if (Fork() == 0)
  { // 자식 프로세스 생성
    // 실제 서버는 모든 CGI 변수를 여기에 설정.
    setenv("QUERY_STRING", cgiargs, 1);
    Dup2(fd, STDOUT_FILENO);              // 표준 출력을 연결 소켓으로 리다이렉트
    Execve(filename, emptylist, environ); // CGI 프로그램 실행
  }
  Wait(NULL); // 부모 프로세스는 자식 프로세스가 종료될 때까지 기다림
}
/* $end serve_dynamic */

/*
 * clienterror - 클라이언트에게 에러 메세지 반환
 */
/* $begin clienterror */
void clienterror(int fd, char *cause, char *errnum, // fd - connfd, cause - 원인, errnum - HTTP 오류 번호
                 char *shortmsg, char *longmsg)     // shortmsg - 짧은 메세지, longmsg - 긴 메세지
{
  char buf[MAXLINE], body[MAXBUF];

  /* HTTP 응답 본문 생성 */
  sprintf(body, "<html><title>Tiny Error</title>");
  sprintf(body, "%s<body bgcolor="
                "ffffff"
                ">\r\n",
          body);
  sprintf(body, "%s%s: %s\r\n", body, errnum, shortmsg);
  sprintf(body, "%s<p>%s: %s\r\n", body, longmsg, cause);
  sprintf(body, "%s<hr><em>The Tiny Web server</em>\r\n", body);

  /* HTTP 응답 헤더 출력 */
  sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
  Rio_writen(fd, buf, strlen(buf)); // buf에 저장된 문자열을 클라이언트에 전송
  sprintf(buf, "Content-type: text/html\r\n");
  Rio_writen(fd, buf, strlen(buf)); // buf에 저장된 문자열을 클라이언트에 전송
  sprintf(buf, "Content-length: %d\r\n\r\n", (int)strlen(body));
  Rio_writen(fd, buf, strlen(buf));   // buf에 저장된 문자열을 클라이언트에 전송
  Rio_writen(fd, body, strlen(body)); // HTML 형식의 body 본문을 클라이언트에게 전송
}
/* $end clienterror */