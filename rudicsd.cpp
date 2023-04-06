// Copyright (C) 2007-2023 Geoff Shilling, Jason Gobat
// Copyright (C) 2006, 2007 Dana Swift
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pty.h>
#include <utmp.h>
#include <stdarg.h>
#include <syslog.h>
#include <dirent.h>
#include <sys/select.h>
#include <time.h>
#include <sys/utsname.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include "poll.h"

// STL list-based queues are used as FIFOs in rudicsd()
using namespace std;
#include <list>
#include <queue>

#define LEADER "Iridium RUDICS server [SwiftWare]"
#define VERSION "$Revision: 0.3 $ $Date: 2006/05/21 17:31:08 $"

// typedefs to improve readibility
typedef void sighandler(int);

// prototypes for functions with external linkage
sighandler *signal(int signo, sighandler *func);

// prototypes for functions with static linkage
static void cleanup(int);
static int  ClientAuthorization(void);
static void login(void);
static void metachar(unsigned char c,utsname *uts);
static void PrintUsage(void);
static void rudicsd(int mfd, int pid);
static void sigalrm(int signo);
static void sigchld(int signo);
static void sighup(int signo);
static void syserr(const char *fmt, ...);
static void sysmsg(const char *fmt, ...);
static int find_child(int ppid, char *child_name);

// static data objects
static const char *logincmd = "/bin/login";
static const char *progname = "rudicsd";
static char tty[PATH_MAX];
static time_t To=0L;
static time_t RudicsdTimeout=900L;
static bool RudicsLog=true;
static struct sockaddr_in host;
static char hostaddr[128];

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * $Id: rudicsd.cpp,v 0.3 2006/05/21 17:31:08 swift Exp swift $
 *~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Copyright (C) 2006, 2007 Dana Swift
 * Copyright (C) 2007 Geoff Shilling, Jason Gobat
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * RCS Log:
 *
 * $Log: rudicsd.cpp,v $
 * Revision 0.3  2006/05/21 17:31:08  swift
 * Version that is ready for start of systematic automated tests.
 *
 * Revision 0.2  2006/05/20 17:25:32  swift
 * Added command line arguments for facilitate logging and orphan-killing.
 *
 * Revision 0.1  2006/05/16 23:02:34  swift
 * Basic core that works.
 * 
*========================================================================*/
/* Server for Iridium RUDICS connections                                  */
/*========================================================================*/
int main(int argc, char **argv)
{
    int mfd; pid_t pid;
    int opt;
    char *notifier;
    
    notifier = NULL;
    
    // record the daemon name for syslog entries
    if (argv[0]) progname=argv[0];
    // circulate through the command line arguements
    for (opterr=0; (opt=getopt(argc,argv,"?hit:n:"))!=EOF;)
    {
      printf("opt (%d)\n", opt);
      switch (opt)
        {
            // check for usage query
        case '?': case 'h': {PrintUsage(); break;}
            
            // inhibit syslog-ing to /var/log/rudics.log
        case 'i': {RudicsLog=false; break;}
            
            // specify the timeout for the iridium orphan killer
        case 't':
        {
            // convert the specified timeout from minutes to seconds
            RudicsdTimeout=atol(optarg)*60L;
            
            // condition the lower end of the timeout
            if (RudicsdTimeout<600L) RudicsdTimeout=600L;
            
            // condition the upper end of the timeout
            else if (RudicsdTimeout>3600L) RudicsdTimeout=3600L;
            
            break;
        }
        
        // specify a program to run to send notification that call is online
        case 'n':
        {
            notifier = strdup(optarg);	     
            break;
        }

	// -1 - no more arguments
	case -1:
	  break;
        
        // write the usage string to the syslogx
        default: {RudicsLog=false; syserr("usage: %s -? -h -i -t[Min] -n [progname] \n",progname);}
        }
    }

    if (notifier) {
        system(notifier);
    }
    sysmsg("Starting up");
    
    // alarm signal kills orphan rudics connections
    signal(SIGALRM,sigalrm); alarm(RudicsdTimeout);
    
    signal(SIGHUP,sighup);

    // attempt to detect subterfuge by the client-host
    if (ClientAuthorization()>0)
    {
        // clean up after the login shell terminates
        signal(SIGCHLD,sigchld); 

        // establish a pseudo-tty linkage between rudics server and login-shell
        switch ((pid=forkpty(&mfd,tty,NULL,NULL)))
        {
            // handle the case where no pseudo-ttys were available
        case -1: syserr("forkpty() failed.");

           // the child process becomes the login shell
        case  0: login();

            // the parent process is the rudics server
        default: rudicsd(mfd, pid);
        }
    } else {
      sysmsg("Failed ClientAuthorization");
    }
   
    return EXIT_FAILURE;
}

/*------------------------------------------------------------------------*/
/* function to clean-up before shutting down the rudics server            */
/*------------------------------------------------------------------------*/
static void cleanup(int exit_code)
{
    // set a pointer to the tty (ignore the path segment)
    char *p = tty + sizeof(_PATH_DEV) - 1;

    sysmsg("Starting cleanup");

    // add the entry to the wtmp database 
    if (logout(p)) logwtmp(p,"","");

    // reset owner & modes of the slave
    chmod(tty,0600); chown(tty,0,0);

    // reset owner & modes of the master
    *p='p'; chmod(tty,0666); chown(tty,0,0);

    // get the current time
    time_t T=time(NULL);

    // make a syslog entry
    sysmsg("Rudics daemon shutdown[%s]: UnixEpoch: %lds "
           "Duration: %0.0fs",hostaddr,T,difftime(T,To));

    exit(exit_code);
}

/*------------------------------------------------------------------------*/
/* authorization sieve for client connections to the rudics server        */
/*------------------------------------------------------------------------*/
int ClientAuthorization(void)
{
    int status=1;

    // disable rudics logging until after authorization is complete
    bool logstate=RudicsLog; RudicsLog=false;

    // initialize the dotted-quad host address
    strncpy(hostaddr,"???.???.???.???",sizeof(hostaddr)-1);

    // get the length of the sockaddr_in object
    socklen_t hostlen=sizeof(host);
      
    // get the IP address of the propective client
    if (getpeername(0,(struct sockaddr *)&host,&hostlen)<0)
    {
        // note the error in the syslogs
        sysmsg("getpeername() failed[errno=%d]: %s\n",
               errno,strerror(errno));

        // indicate authorization failure
        status=0; 
    }

    // convert the 32-bit address to dotted-quad notation
    else {strncpy(hostaddr,inet_ntoa(host.sin_addr),sizeof(hostaddr)-1);}

    // reset rudics syslog-ing
    RudicsLog=logstate;

    return status;
}

/*------------------------------------------------------------------------*/
/* forked (child) process to handle login and shell                       */
/*------------------------------------------------------------------------*/
void login(void)
{
    int c; FILE *fd;
    //const char *login_prompt = "login: ";
    struct pollfd fdset;

    // get host information
    struct utsname uts; uname(&uts);

    // get the host name 
    char host[128]; gethostname(host,sizeof(host)-1); host[sizeof(host)-1]=0;

   
    // open the system info file
    if ((fd=fopen("/etc/issue", "r")))
    {
        // read system info from /etc/issue 
        while ((c=getc(fd)) != EOF)
        {
            // check for metacharacters 
            if (c == '\\') metachar(getc(fd),&uts);

            // write system info
            else putchar(c);
        }
        fclose (fd);
    }

    // set for minimal terminal processing
    putenv((char *)"TERM=linux");

    // close all nonstandard descriptors 
    for (int i=getdtablesize()-1; i>2; i--) close(i);

    // It has been reported that over the iridium link, there is often a newline character in the input stream
    // that causes the first input to the login command to be missed.  This is an attemt to remove that problem.
    while(1) {
        memset((void*)&fdset, 0, sizeof(fdset));    
        fdset.fd = STDIN_FILENO;
        fdset.events = POLLIN;
        poll(&fdset, 1, 0);
        if(fdset.revents & POLLIN) {
            int ch = getchar();
            sysmsg("Waiting input:%d", ch);
        } else {
            break;
        }
    }

    sysmsg("%s: launching %s",ptsname(STDIN_FILENO),logincmd);
   
    // execute the login command 
    execl(logincmd,logincmd,(char *)NULL);

    // login failed - make a syslog entry
    sysmsg("%s: can't exec %s: %s",ptsname(STDIN_FILENO),logincmd,strerror(errno));

    // kill the child
    exit(EXIT_FAILURE);
}

/*------------------------------------------------------------------------*/
/* function to process metacharacters from /etc/issue                     */
/*------------------------------------------------------------------------*/
static void metachar(unsigned char c,utsname *uts)
{
    switch (c)
    {
    case 's': {printf("%s",uts->sysname); break;}
    case 'n': {printf("%s",uts->nodename);break;}
    case 'r': {printf("%s",uts->release); break;}
    case 'v': {printf("%s",uts->version); break;}
    case 'm': {printf("%s",uts->machine); break;}
    case 'o': {printf("%s",uts->domainname); break;}
    case 'd':
    case 't':
    {
        time_t cur_time;
        struct tm *tm;
        time(&cur_time);
        tm = localtime(&cur_time);
        if (c == 'd') printf("%d-%02d-%02d", 1900 + tm->tm_year,tm->tm_mon + 1, tm->tm_mday);
        else printf("%02d:%02d:%02d", tm->tm_hour,tm->tm_min, tm->tm_sec);
        break;
    }

    case 'l': {printf("%s",ptsname(STDIN_FILENO)); break;}
    case 'u':
    case 'U':
    {
        int users = 0;
        struct utmp *ut;
        setutent();
        while ((ut = getutent())) {if (ut->ut_type == USER_PROCESS) users++;}
        endutent ();
        printf ("%d", users);
        if (c == 'U') printf(" user%s", users == 1 ? "" : "s");
        break;
    }
    default: putchar(c);
    }
}

/*------------------------------------------------------------------------*/
/* function to print the usage string                                     */
/*------------------------------------------------------------------------*/
static void PrintUsage(void)
{
    printf("%s\n%s\n",LEADER,VERSION);
    printf("usage: %s -h -? -i -t[Min]\n",progname);
    printf("        -h, -?   Print this usage summary.\n");
    printf("            -i   Inhibit syslog entries in /var/log/rudics.log.\n");
    printf("                 Note: this option inhibits an log output.\n");
    printf("       -t[Min]   This option implements a financial safety valve that\n"
           "                    will kill the RUDICS server after a specified number\n"
           "                    of minutes so that orphaned Iridium connections won't\n"
           "                    remain connected indefinitely.  The argument to this\n"
           "                    option represents the maximum number of minutes allowed\n"
           "                    for the connection.  The argument must be in the range\n"
           "                    of 5-60 minutes and the default value is 15 minutes.\n\n");
    exit(0);
}

/*------------------------------------------------------------------------*/
/* forked (parent) process to manage traffic between client and shell     */
/*------------------------------------------------------------------------*/
void rudicsd(int mfd, int child_pid)
{
    char byte,buf[1024]; int n=1; const int rfd=0;
    int save_errno; int save_ret;

    // enable nonblocking mode for stdio and the pseudo-tty
    ioctl(rfd,FIONBIO,&n); ioctl(mfd,FIONBIO,&n);

    // create 2 FIFOs to buffer the IO
    queue<char,list<char> > RemToLoc,LocToRem;

    sysmsg("Built %s %s", __DATE__, __TIME__);

    // make a syslog entry that a rudics connection is initated 
    To=time(NULL); sysmsg("Rudics connection initiated[%s]:  "
                          "UnixEpoch: %lds",hostaddr,To);
   
    while (1)
    {
        // initialize the controlling file-descriptor bits
        fd_set rbits,wbits; FD_ZERO(&rbits); FD_ZERO(&wbits);

        // these conditionals keep the FIFOs from becoming larger than 1024 bytes
        if (!RemToLoc.empty()) FD_SET(mfd,&wbits); else FD_SET(rfd,&rbits);
        if (!LocToRem.empty()) FD_SET(rfd,&wbits); else FD_SET(mfd,&rbits);

        // multiplexed input model
        switch (select(mfd+1,&rbits,&wbits,NULL,NULL))
        {
            // exceptional conditions
        case -1:
        {
            // ignore the error if select() was interrupted
            if (errno==EINTR) continue;

            // log the execption and crash out
            syserr("Exceptional condition [%d] encountered: %s\n",
                   errno,strerror(errno));
        }

        // this shouldn't happen because select() uses a blocking model
        case  0: {sleep(5); continue;}

        default:
        {
            // check if input is ready at the socket
            if (FD_ISSET(rfd,&rbits))
            {
                // read from the socket into the buffer
                n=read(rfd,buf,sizeof(buf));

                // check if no bytes were available
                if (n<0 && errno==EWOULDBLOCK) continue;

                // check for exceptions
                // Get more fine grained here: 0 is end of file
                // Negative is error - EAGAIN was seen once - retry?
                if (n<=0) {
                    save_errno = errno;
                    save_ret = n;
                    goto SOCKET_READ_ERROR;
                    break;
                }

                // add the bytes to the FIFO
                for (int i=0; i<n; i++) RemToLoc.push(buf[i]);

                // indicate that bytes should be written to the pseudo-tty
                FD_SET(mfd,&wbits);
            }

            // check condition for writing to the pseudo-tty
            if (FD_ISSET(mfd,&wbits))
            {
                // attempt to write the whole FIFO
                while (!RemToLoc.empty())
                {
                    // get the next byte from the FIFO
                    byte = RemToLoc.front();

                    // write the byte to the pseudo-tty
                    if (write(mfd,&byte,1)>0) {RemToLoc.pop();} else break;
                }
            }
            
            // check condition for reading from the pseudo-tty
            if (FD_ISSET(mfd,&rbits))
            {
                // read from the pseudo-tty into the buffer
                n=read(mfd,buf,sizeof(buf));
               
                // check if no bytes were available
                if (n<0 && errno==EWOULDBLOCK) continue;

                // check for exceptions
                if (n<=0) break;

                // add the bytes to the FIFO
                for (int i=0; i<n; i++) LocToRem.push(buf[i]);

                // indicate that bytes should be written to the socket
                FD_SET(rfd,&wbits);
            }

            // check condition for writing to the socket
            if (FD_ISSET(rfd,&wbits))
            {
                // attempt to write the whole FIFO
                while (!LocToRem.empty())
                {
                    // get the next byte from the FIFO
                    byte = LocToRem.front();

                    // write the byte to the socket
                    if (write(rfd,&byte,1)>0) LocToRem.pop(); else break;
                }
            }
        }
        }
    }

SOCKET_READ_ERROR:
    time_t T=time(NULL);

    sysmsg("Rudics connection terminated[%s] %s errno (%d) %s : UnixEpoch: %lds"
           " Duration: %0.0fs",
           hostaddr, save_ret < 0 ? "Socket error" : "Socket closed",
           save_errno,strerror(save_errno),T,difftime(T,To));

    int shell_pid; 
    char shell_name[64];
    int status;
    int ret_val;
    
    if((shell_pid = find_child(child_pid, shell_name)) < 0) {
        sysmsg("Could not find pid for shell from %d", child_pid);
    } else {
        sysmsg("Sending SIGHUP to shell %d (%s)", shell_pid, shell_name);

        // Comment from when we signaled the login, not shell process
        // As a general note, in response to the SIGHUP, a bash shell will not 
        // run the .bash_logout script here, while tcsh will run .logout
      
        if(kill(shell_pid, SIGHUP) < 0) {
            sysmsg("Error sending sighup to shell pid %d errno (%d) %s",
                   shell_pid, errno, strerror(errno));
        } else {
             // Wait for the child to shutdown
             errno = 0;
             ret_val = wait(&status);
        
             //     Probably unneeded
             // In theory, we should never get here.
             sysmsg("Child %d wait over (0x%x) (%d) errno (%d) %s", 
                    shell_pid, status, ret_val, errno, strerror(errno));
        }
    }

    // Signal the login process - should never get here, unless the 
    // search for the login shell fails
    sysmsg("Sending sighup to child (login process) pid %d", shell_pid);
    kill(child_pid, SIGHUP);
   
    // Wait for the child to shutdown
    ret_val = wait(&status);
    
    // The following code is never executed as the exit(0) in the bottom
    // of the cleanup() in the SIGCHLD signal handler is executed 
    // before we return here.  
    //
    // This code is left in place for 1) historical reference and 
    // 2) if for some reason we did get here, the code below would be sensible.

    sysmsg("Child %d wait over (0x%x) (%d)", child_pid, status, ret_val);

    // ignore SIGCHLD signals
    signal(SIGCHLD,SIG_IGN);

    // shutdown, clean-up and kill the server
    cleanup(0);
}

/*------------------------------------------------------------------------*/
/* interrupt handler to kill orphaned iridium connections                 */
/*------------------------------------------------------------------------*/
static void sighup(int signo)
{
    // make a syslog entry and crash out
    syserr("WARNING - SIGHUP sent");
}

/*------------------------------------------------------------------------*/
/* interrupt handler to kill orphaned iridium connections                 */
/*------------------------------------------------------------------------*/
static void sigalrm(int signo)
{
    // make a syslog entry and crash out
    syserr("WARNING - timeout reached - terminating (orphan?)"
           "iridium connection.\n");
}

/*------------------------------------------------------------------------*/
/* interrupt handler to clean-up after the shell exists                   */
/*------------------------------------------------------------------------*/
static void sigchld(int signo)
{
    // clean up after the child committed suicide
    int status; wait(&status);

    sysmsg("Child signaled: %s (%d)", strsignal(signo), signo);

    // shutdown, clean-up and kill the server
    cleanup(0);
}

/*------------------------------------------------------------------------*/
/* simple interface to a complicated interrupt configuration apparatus    */
/*------------------------------------------------------------------------*/
sighandler *signal(int signo, sighandler *func)
{
    struct sigaction act, oact;
    act.sa_handler=func;
    sigemptyset(&act.sa_mask);
    act.sa_flags=0;
    if (sigaction(signo,&act,&oact)<0) return SIG_ERR;
    return oact.sa_handler;
}

/*------------------------------------------------------------------------*/
/* output error messages via the syslog facility                          */
/*------------------------------------------------------------------------*/
static void syserr(const char *fmt, ...)
{
    va_list va_alist;

    if (RudicsLog)
    {
        va_start(va_alist, fmt);
        openlog(progname, LOG_PID, LOG_LOCAL0);
        vsyslog(LOG_ERR, fmt, va_alist);
        closelog();
        va_end(va_alist);
    }
    // Shutdown, clean up and kill the server
    cleanup(EXIT_FAILURE);
}

/*------------------------------------------------------------------------*/
/* output error messages via the syslog facility                          */
/*------------------------------------------------------------------------*/
static void sysmsg(const char *fmt, ...)
{
    va_list va_alist;
 
    if (RudicsLog)
    {
        va_start(va_alist, fmt);
        openlog(progname, LOG_PID, LOG_LOCAL0);
        vsyslog(LOG_ERR, fmt, va_alist);
        closelog();
        va_end(va_alist);
    } 
}

static int 
find_child(int ppid, char *child_name)
{
    DIR           *d;
    struct dirent *dir;
    d = opendir("/proc");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            int pid;
            char *endptr;

            pid = strtol(dir->d_name, &endptr, 10);
            if(*endptr == '\0') {
                char dir_buffer[64];
                int t_ppid;
                FILE *fi;

                sprintf(dir_buffer, "/proc/%d/stat", pid);
                    
                if((fi = fopen(dir_buffer, "r")) != NULL) {
                    if(fscanf(fi, "%*d %s %*c %d", child_name, &t_ppid) == 2) {
                        if(t_ppid == ppid) {
                            return pid;
                        }
                        //printf("%d %d %s\n", pid, t_ppid, parent_name);
                    } else {
                        fprintf(stderr, "Could not process %s\n", dir_buffer);
                    }
                    fclose(fi);
                }
            }
        }
        closedir(d);
    }
    return -1;
}
