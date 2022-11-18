#include "tema_svc.c"
#include "tema.h"

int main(int argc, char *argv[])
{
    SVCXPRT *transp = NULL;
    int sock;
    int proto = 0;
    struct sockaddr_in saddr;
    int asize = sizeof(saddr);

    if (getsockname(0, (struct sockaddr *)&saddr, &asize) == 0)
    {
        int ssize = sizeof(int);

        if (saddr.sin_family != AF_INET)
            exit(1);
        if (getsockopt(0, SOL_SOCKET, SO_TYPE,
                       (char *)&_rpcfdtype, &ssize) == -1)
            exit(1);
        sock = 0;
        _rpcpmstart = 1;
        proto = 0;
        openlog("tema", LOG_PID, LOG_DAEMON);
    }
    else
    {
#ifndef RPC_SVC_FG
        int size;
        int pid, i;

        pid = fork();
        if (pid < 0)
        {
            perror("cannot fork");
            exit(1);
        }
        if (pid)
            exit(0);
        size = getdtablesize();
        for (i = 0; i < size; i++)
            (void)close(i);
        i = open("/dev/console", 2);
        (void)dup2(i, 1);
        (void)dup2(i, 2);
        i = open("/dev/tty", 2);
        if (i >= 0)
        {
            (void)ioctl(i, TIOCNOTTY, (char *)NULL);
            (void)close(i);
        }
        openlog("tema", LOG_PID, LOG_DAEMON);
#endif
        sock = RPC_ANYSOCK;
        (void)pmap_unset(AUTH_PROG, AUTH_VERS);
    }

    if ((_rpcfdtype == 0) || (_rpcfdtype == SOCK_DGRAM))
    {
        transp = svcudp_create(sock);
        if (transp == NULL)
        {
            _msgout("cannot create udp service.");
            exit(1);
        }
        if (!_rpcpmstart)
            proto = IPPROTO_UDP;
        if (!svc_register(transp, AUTH_PROG, AUTH_VERS, auth_prog_1, proto))
        {
            _msgout("unable to register (AUTH_PROG, AUTH_VERS, udp).");
            exit(1);
        }
    }

    if ((_rpcfdtype == 0) || (_rpcfdtype == SOCK_STREAM))
    {
        if (_rpcpmstart)
            transp = svcfd_create(sock, 0, 0);
        else
            transp = svctcp_create(sock, 0, 0);
        if (transp == NULL)
        {
            _msgout("cannot create tcp service.");
            exit(1);
        }
        if (!_rpcpmstart)
            proto = IPPROTO_TCP;
        if (!svc_register(transp, AUTH_PROG, AUTH_VERS, auth_prog_1, proto))
        {
            _msgout("unable to register (AUTH_PROG, AUTH_VERS, tcp).");
            exit(1);
        }
    }

    if (transp == (SVCXPRT *)NULL)
    {
        _msgout("could not create a handle");
        exit(1);
    }
    if (_rpcpmstart)
    {
        (void)signal(SIGALRM, (SIG_PF)closedown);
        (void)alarm(_RPCSVC_CLOSEDOWN);
    }
    svc_run();
    _msgout("svc_run returned");
    exit(1);
    /* NOTREACHED */
}
