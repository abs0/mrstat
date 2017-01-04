/*
 * $Id: mrstat.c,v 1.20 2003/06/06 17:04:26 abs Exp $
 *
 * mrstat: (c) 1996, 1999, 2003, 2009 DKBrownlee (abs@mono.org).
 * May be freely distributed.
 * Track load, uptime, and number of users on specified hosts.
 * No warranty, implied or otherwise. Stick no bills. Suggestions welcome.
 *
 */

#define	VERSION		"1.20"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <rpc/rpc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>

#include <rpcsvc/rnusers.h>	/* Version 2 */
#include <rpcsvc/rstat.h>

typedef struct
	{
	const		char *name;
	struct in_addr	addr;
	} host_t;

typedef struct
	{
	int		users_on,
			full,
			max_users_on;
	u_long		av_users_count;	/*  *10 */
	u_long		stats_count;
	long		avenrun[2];
	struct timeval	boottime,
			first_response,
			last_response;
	} stats_t;

typedef struct
	{
	CLIENT		*uclnt,
			*sclnt;
	host_t		host_internal,
			host_external;
	const char	*error;	/* Never malloced */
	stats_t		stats;
	char		outputline[90];
	} machine_t;

#define TIMEOUT		15

int	main(int argc, char **argv);
void	mach_check(machine_t *mach);
int	mach_check_telnet(machine_t *mach);
void	mach_disconnect(machine_t *mach);
void	mach_error(machine_t *mach, const char *error);
int	mach_host_lookup(machine_t *mach, host_t *host);
int	mach_host_set(machine_t *m, host_t *h, const char *na, const char *dom);
void	mach_outputline(machine_t *mach);
int	mach_sethosts(machine_t *mach, const char *name);
void	machlist_free(machine_t *mach, size_t entries);

FILE	*open_tmpfile(char *tmpstr, const char *filename);
void	read_hostfile(const char *hostfile, machine_t **machptr, size_t *end);
void	sig_alrm(void);
int	sortlistcmp(const void *a, const void *b);
const char *tm_etime(struct timeval tm);
void	usage(const char *error);

char	*domain;
char	*external_domain;
char	*hostfiletag;

int main(int argc, char **argv)
    {
    char	tmpstr[MAXPATHLEN];
    FILE	*outfds;
    machine_t	*mach = 0,
		**sortlist = 0;
    stats_t	total;
    char	*outfile = 0,
		*upfile = 0,
		*hostfile = 0;
    time_t	now,
		start;
    int		peak_total_users = 0;
    int		sortend = 0,
		i = 0;
    size_t	end = 0;
    unsigned	interval = 0;

    int ch;

    while ((ch = getopt(argc, argv, "d:e:f:hi:o:u:t:")) != -1)
	switch (ch)
	    {
            case 'd':
		domain = optarg;
		break;
            case 'e':
		external_domain = optarg;
		break;
            case 'f':
		hostfile = optarg;
		break;
            case 'i':
		if ((interval = atoi(optarg))<1)
		    usage("-i interval must be >=1");
		break;
            case 'o':
		outfile = optarg;
		break;
            case 'u':
		upfile = optarg;
		break;
            case 't':
		hostfiletag = optarg;
		break;
            default:
		usage(0);
	    }
    argc -= optind;
    argv += optind;

    if (argc == 0 && !hostfile)
	usage("No hosts given");
    if (hostfiletag && !hostfile)
	usage("Cannot specify -t without -f");
    if (argc && hostfile)
	usage("Cannot mix -f with hosts on command line");
    signal(SIGALRM, (void(*)(int))sig_alrm);

    if (! hostfile)
	{
	end = argc;
	mach = calloc(sizeof(machine_t), end);
	if (!mach)
	    errx(1, "Insufficient memory to allocate machine list");
	for (i = 0 ; i<end ; ++i)
	    if (mach_sethosts(&mach[i], argv[i]))
		errx(1, "Insufficient memory to allocate hostnames");
	}

    time(&start);
    do  {
	if (hostfile)
	    read_hostfile(hostfile, &mach, &end);
	if (sortend != end)
	    {
	    if (sortlist)
		free(sortlist);
	    sortlist = malloc(sizeof(machine_t *)*end);
	    if (!sortlist)
		errx(1, "Insufficient memory to allocate machine sortlist");
	    sortend = end;
	    }

	memset(&total, 0, sizeof(total));
	for (i = 0 ; i<end ; ++i)
	    {
	    mach_check(&mach[i]);
	    if (mach[i].error == 0)
		{
		total.users_on += mach[i].stats.users_on;
		if (mach[i].stats.stats_count )
		    total.av_users_count += 10 * mach[i].stats.av_users_count /
					mach[i].stats.stats_count;
		}
	    if (total.users_on > peak_total_users)
		peak_total_users = total.users_on;
	    total.max_users_on = peak_total_users;
	    mach_outputline(&mach[i]);
	    }
	time(&now);
	if (outfile)
	    outfds = open_tmpfile(tmpstr, outfile);
	else
	    outfds = stdout;

	for (i = 0 ; i<end ; ++i)
	    sortlist[i] = &mach[i];
	qsort(sortlist, end, sizeof(machine_t *), sortlistcmp);

	fputs(
"\t    Hostname  IP-address      Uptime      Load  ...\tUsers Peak  Avg\n",
								outfds);
	for (i = 0 ; i<end ; ++i)
	    fputs(sortlist[i]->outputline, outfds);
	fprintf(outfds, "%20.20s -  ", ctime(&start));
	fprintf(outfds, "%20.20s\t\t  Totals  %3d %3d %3ld.%1ld\n", ctime(&now),
		    total.users_on, total.max_users_on,
		    total.av_users_count/10,
		    total.av_users_count%10);
	if (outfile)
	    {
	    (void)fclose(outfds);
	    if (rename(tmpstr, outfile))
		err(1, "Unable to rename(%s, %s)", tmpstr, outfile);
	    }
	else
	    fflush(outfds);

	if (upfile)
	    {
	    outfds = open_tmpfile(tmpstr, upfile);
	    for (i = 0 ; i<end ; ++i)
		{
		if (! sortlist[i]->error && ! sortlist[i]->stats.full)
		    fprintf(outfds, "%s %s\n",
				sortlist[i]->host_external.name,
				inet_ntoa(sortlist[i]->host_external.addr));
		}
	    fclose(outfds);
	    if (rename(tmpstr, upfile))
		err(1, "Unable to rename(%s, %s)", tmpstr, upfile);
	    }

	sleep(interval);
	}while( interval );
    return 0;
    }

void mach_check(machine_t *mach)
    {
    struct utmpidlearr	rnusr; 
    struct statstime	statsp;
    struct timeval	timeout;
    int			users_on;

    if (mach_host_lookup(mach, &mach->host_internal))
	return;
    if (mach_host_lookup(mach, &mach->host_external))
	return;

    if (mach_check_telnet(mach))
	return;

    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    memset(&statsp, 0, sizeof(statsp));
    if (mach->sclnt == 0 )
	mach->sclnt = clnt_create(mach->host_internal.name, RSTATPROG,
							RSTATVERS_TIME, "udp");
    if (mach->sclnt == 0 || clnt_call(mach->sclnt, RSTATPROC_STATS, xdr_void,
			NULL, xdr_statstime, &statsp, timeout) != RPC_SUCCESS)
	{
	mach_error(mach, "Running, but no rstat");
	return;
	}
    mach->stats.avenrun[0] = (statsp.avenrun[0]*3+7)/8;
    mach->stats.avenrun[1] = (statsp.avenrun[2]*3+7)/8;
    mach->stats.boottime.tv_sec = statsp.boottime.tv_sec;
    mach->stats.boottime.tv_usec = statsp.boottime.tv_usec;
    clnt_freeres(mach->sclnt, xdr_statstime, (char *)&statsp);

    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    memset(&rnusr, 0, sizeof(rnusr));
    if (mach->uclnt == 0 )
	mach->uclnt = clnt_create(mach->host_internal.name,
						(const rpcprog_t)RUSERSPROG,
						RUSERSVERS_IDLE, "udp");
    if (mach->uclnt == 0 || clnt_call(mach->uclnt,
			(const rpcproc_t)RUSERSPROC_NAMES, xdr_void,
			NULL, xdr_utmpidlearr, &rnusr, timeout) != RPC_SUCCESS)
	{
	mach_error(mach, "Running, but no rnusers");
	return;
	}
    users_on = rnusr.uia_cnt;
    clnt_freeres(mach->uclnt, xdr_utmpidlearr, (char *)&rnusr);

    if (mach->error)	/* Transitioning from error to OK */
	{
	mach->error = 0;
	memset(&mach->stats, 0, sizeof(stats_t));
	gettimeofday(&mach->stats.first_response, 0);
	}
    mach->stats.users_on = users_on;
    if (users_on > mach->stats.max_users_on )
	mach->stats.max_users_on = users_on;
    mach->stats.av_users_count += users_on;
    ++mach->stats.stats_count;
    gettimeofday(&mach->stats.last_response, 0);
    }

int mach_check_telnet(machine_t *mach)
    {
    char		buf[256];
    struct sockaddr_in	saddr;
    int			sock;
    int			val;
    struct pollfd	validfd;

    memset(&saddr, 0, sizeof(saddr));
    memcpy(&saddr.sin_addr, &mach->host_internal.addr,
					    sizeof(mach->host_internal.addr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(23);	/* Telnet connection */

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
	mach_error(mach, "Unable to open socket");
	return -1;
	}

    alarm(4);
    if (connect(sock, (struct sockaddr *)&saddr, (socklen_t)sizeof(saddr)) )
	{
	shutdown(sock, 2);
	(void)close(sock);
	mach_error(mach, "No response");
	return -1;
	}

    val = fcntl(sock, F_GETFL, 0);
    (void)fcntl(sock, F_SETFL, val|O_NDELAY);

#define POLL_EVENTS (POLLRDNORM|POLLERR|POLLHUP|POLLNVAL)

    validfd.fd = sock;
    validfd.events = POLL_EVENTS;

    if (poll(&validfd, 1, INFTIM) != 1 ||
	    (val = read(sock, buf, sizeof(buf))) <= 0 || buf[0] != (char)-1)
	mach->stats.full = 1;
    else
	mach->stats.full = 0;
    alarm(0);
    (void)shutdown(sock, 2);
    (void)close(sock);
    return 0;
    }

void mach_disconnect(machine_t *mach)
    {
    if (mach->sclnt)
	{
	clnt_destroy(mach->sclnt);
	mach->sclnt = 0;
	}
    if (mach->uclnt)
	{
	clnt_destroy(mach->uclnt);
	mach->uclnt = 0;
	}
    }

void mach_error(machine_t *mach, const char *error)
    {
    mach_disconnect(mach);
    mach->error = error;
    }

int mach_host_lookup(machine_t *mach, host_t *host)
    {
    struct hostent	*host_ent;

    if ((host_ent = gethostbyname(host->name)) == 0)
	{
	mach_error(mach, "Unable to resolve hostname");
	return -1;
	}
    memcpy(&host->addr, host_ent->h_addr, (size_t)host_ent->h_length);
    return 0;
    }

int mach_host_set(machine_t *mach, host_t *host, const char *name,
							const char *domain)
    {
    char	*newname;

    if (domain && ! strchr(name, '.'))
	{
	newname = malloc(strlen(name) + strlen(domain) + 2);
	if (newname)
	    sprintf(newname, "%s.%s", name, domain);
	}
    else
	newname = strdup(name);
    host->name = newname;
    return newname ?0 :-1;
    }

void mach_outputline(machine_t *mach)
    {
    sprintf(mach->outputline, "%20.20s  ", mach->host_external.name);
    if (mach->error)
	sprintf(strchr(mach->outputline, 0), "*** DOWN ***    %-9.9s   (%s)\n",
			tm_etime(mach->stats.last_response), mach->error);
    else
	sprintf(strchr(mach->outputline, 0),
"%-15.15s %-9.9s   %2ld.%02ld %2ld.%02ld   %5d %3d %3ld.%1ld\n",
		mach->stats.full?"*** BUSY ***"
				:inet_ntoa(mach->host_external.addr),
		tm_etime(mach->stats.boottime),
		mach->stats.avenrun[0]/100, mach->stats.avenrun[0]%100,
		mach->stats.avenrun[1]/100, mach->stats.avenrun[1]%100,
		mach->stats.users_on, mach->stats.max_users_on,
		mach->stats.av_users_count / mach->stats.stats_count,
		((mach->stats.av_users_count*10) / mach->stats.stats_count)%10);
    }

int mach_sethosts(machine_t *mach, const char *name)
    {
    return mach_host_set(mach, &mach->host_external, name, external_domain
						?external_domain :domain) ||
    	   mach_host_set(mach, &mach->host_internal, name, domain);
    }

void machlist_free(machine_t *mach, size_t entries)
    {
    int loop;

    for (loop = 0 ; loop < entries ; ++loop)
	{
	if (mach[loop].host_external.name)
	    {
	    free((char *)mach[loop].host_external.name);
	    mach[loop].host_external.name = 0;
	    }
	if (mach[loop].host_internal.name)
	    {
	    free((char *)mach[loop].host_internal.name);
	    mach[loop].host_internal.name = 0;
	    }
	mach_disconnect(&mach[loop]);
	}
    free(mach);
    }

FILE *open_tmpfile(char *tmpstr, const char *filename)
    {
    int		fd;
    FILE	*fds;

    snprintf(tmpstr, (size_t)MAXPATHLEN, "%s.XXX", filename);
    if ((fd = mkstemp(tmpstr)) == -1)
	err(1, "Unable to open outputfile '%s'", tmpstr);
    fchmod(fd, 0644);
    if (!(fds = fdopen(fd, "w")))
	err(1, "Unable to fdopen filehandle for outputfile '%s'", tmpstr);
    return fds;
    }

void read_hostfile(const char *hostfile, machine_t **machptr, size_t *end)
    {
    static struct timespec mtime = {0, 0};
    char	line[MAXHOSTNAMELEN+1],
		*ptr,
		*host;
    FILE	*fds;
    size_t	entries = 0,
    		newend = 0;
    int		pass;
    machine_t	*newmach = 0;
    struct stat	sb;

    if (stat(hostfile, &sb))
	err(1, "Unable to stat hostfile '%s'", hostfile);

    if (memcmp(&mtime, &sb.st_mtimespec, sizeof(struct timespec)) == 0)
	return;					/* File has not changed */
    mtime = sb.st_mtimespec;

    if ((fds = fopen(hostfile, "r")) == 0)
	err(1, "Unable to open hostfile '%s'", hostfile);

    for (pass = 0 ; pass < 2 ; ++pass)
	{
	rewind(fds);
	if (pass)
	    {
	    newend = entries;
	    newmach = calloc(sizeof(machine_t), newend);

	    if (!newmach)
		{
		warnx("Insufficient memory to reread hostfile");
		fclose(fds);
		return;
		}
	    }
	entries = 0;
	while (fgets(line, (int)sizeof(line), fds))
	    {
	    if ((ptr = strchr(line, '#')))
		*ptr = 0;
	    if (! (host = strtok(line, "\n\t ")))
		continue;
	    if (hostfiletag)
		{
		while ((ptr = strtok(0, "\n\t ")))
		    {
		    if (strcmp(ptr, hostfiletag) == 0)
			break;
		    }
		}
	    if (!hostfiletag || ptr) /* No tag wanted, or tag found */
		{
		if (pass)
		    {
		    if (entries >= newend) /* File changed */
			{
			pass = -1;
			continue;
			}
		    if (mach_sethosts(&newmach[entries], host))
			{
			warnx("Insufficient memory to allocate hostentries");
			machlist_free(newmach, entries);
			fclose(fds);
			return;
			}
		    }
		++entries;
		}
	    }
	}
    fclose(fds);
    if (*machptr)
	{
	for (entries = 0 ; entries < newend ; ++entries)	/* newmach */
	    {
	    for (pass = 0 ; pass<*end ; ++pass)		/* machptr */
		{
		if (strcmp(newmach[entries].host_internal.name,
				(*machptr)[pass].host_internal.name) == 0)
		    {
		    newmach[entries].stats = (*machptr)[pass].stats;
		    break;
		    }
		}
	    }
	machlist_free(*machptr, *end);
	}
    *end = newend;
    *machptr = newmach;
    }

void sig_alrm()
    {
    }

int sortlistcmp(const void *a, const void *b)
    {
    int	aload,
	bload;

    if ((*(const machine_t **)a)->error)
	aload = 100000;
    else if ( (*(const machine_t **)a)->stats.full )
	aload = 10000;
    else
	aload = (*(const machine_t **)a)->stats.avenrun[0];

    if ((*(const machine_t **)b)->error)
	bload = 100000;
    else if ( (*(const machine_t **)b)->stats.full )
	bload = 10000;
    else
	bload = (*(const machine_t **)b)->stats.avenrun[0];
    return aload - bload;
    }

const char *tm_etime(struct timeval tm)
    {
    static  char    	tstr[16];
    time_t		tim = time((time_t *)0);

    if (tm.tv_sec == 0)
	return "   ????";
    tim -= tm.tv_sec;

    if (tim <= 0)
	(void)strcpy(tstr, "None");
    else if ((tim /= 60)<(60*24))
	(void)sprintf(tstr, "  %02d:%02d", (int)tim/60, (int)tim%60);
    else
	{
	tim /= (60*24);
	(void)sprintf(tstr, "%3u Day%s", (int)tim, tim == 1 ?"" :"s");
	}
    return tstr;
    }

void usage(const char *error)
    {
    if (error)
	fprintf(stderr, "Error: %s\n", error);
    (void)fprintf(stderr, "\n\
Track load, uptime, and number of users on specified hosts.\n\n\
Usage: mrstat [opts] [hostname [hostname2 ...]]\n\
[opts]\t-d domain     Append domainame to non qualified hostnames\n\
\t-e edomain    Use edomain for displayed names and IP addresses\n\
\t-f file       Read list of hosts from file\n\
\t-h            This help\n\
\t-i interval   Seconds between updates (Default: one update then exit)\n\
\t-o outputfile Redirect into outputfile\n\
\t-u upfile     Sort available hosts by load into upfile (hostname+ip)\n\
\t-t tag        Only use lines in file that contain 'tag'\n\
\n\
If -f is given the hostfile is checked on every update and reread as needed.\n\
Either -f or a list of hosts must be given.\n\n\
Hosts file: # comments permitted. First argument taken as hostname.\n\n\
(Version %s).\n", VERSION);
    exit(3);
    }
