/*
Copyright 2015 Google Inc. All Rights Reserved.

Simple client/server app to establish a pair of TCP connections
between hosts (one unencrypted, and one encrypted/validated using
PSP) and pass some test data over the encrypted connection.
*/

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <linux/bpf.h>
#include <linux/psp.h>
#include <linux/tcp.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_PER_PENDING 65536

/* So okay, this is a mess. These definitions do not exist in uapi/include/
 * and there is no clean way to extract them from the kernel headers without
 * breaking the build in various ghastly ways. Therefore we just punt:
 */

#ifndef SOL_TCP
#define SOL_TCP		6
#endif
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN	0x20000000
#endif

struct pending_data {
	struct pending_data *next;
	size_t count;
	size_t offset;
	uint64_t repeat_bytes;
	uint32_t generation;
	char data[MAX_PER_PENDING];
};

static struct pending_data *pending_head, *pending_tail;

static int psp_bypass;
static int psp_same_port;
static int psp_loop;
static uint64_t psp_bulk_length;
static int psp_randomize;
static int psp_quiet;
static int psp_reuse;
static int psp_stats;
static int psp_fastopen;
static int psp_break;
static int psp_bpf;

static int psp_write_loops;
static uint32_t psp_seed;
static int zero_bind;

struct psp_server {
	struct psp_spi_tuple tuple;
	uint16_t port;
};

static int usage(const char *argv0)
{
	fprintf(stderr,
	    "Usage: %s [-bcls] [-S size] [-v ipversion] [-r reuseports ] interface [serveraddress] port\n",
	    argv0);
	return 1;
}

static int
pid_printf(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	int rc;

	if (psp_reuse) {
		char buf[1000];
		vsnprintf(buf, sizeof(buf), format, args);
		rc = printf("[pid %u] %s", getpid(), buf);
	} else {
		rc = vprintf(format, args);
	}

	va_end(args);

	return rc;
}

static struct bpf_object *
open_and_load_bpf()
{
	const char *filepath = "../bpf/bpf_psp.o";
	struct bpf_object *obj = bpf_object__open(filepath);

	if (!obj) {
		fprintf(stderr, "Could not open BPF object file %s\n",
			filepath);
		return NULL;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "Could not load BPF object file %s\n",
			filepath);
		return NULL;
	}

	return obj;
}

static struct bpf_link *
attach_bpf(struct bpf_object *obj)
{
	const char *cgroup_path = "/dev/cgroup/net/kokonut_test";
	const char *sec_name = "_psp";
	struct bpf_program *prog = bpf_object__find_program_by_name(obj,
								    sec_name);
	struct bpf_link *link;
	int prog_fd, fd;

	if (!prog) {
		fprintf(stderr,
			"Could not find find program %s in BPF object file\n",
			sec_name);
		return NULL;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr,
			"Could not get file descriptor of BPF program: %d\n",
			prog_fd);
		return NULL;
	}

	fd = open(cgroup_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not get fd for cgroup %s: %d\n",
			cgroup_path, fd);
		return NULL;
	}

	link = bpf_program__attach_cgroup(prog, fd);
	if (!link) {
		fprintf(stderr, "Could not attach program to cgroup: %d\n",
			errno);
	}
	close(fd);
	return link;
}

static int
verify_bpf_map(int spi)
{
	const char *map_name = "psp_spi_map";
	struct bpf_map_info info = {};
	uint32_t info_len = sizeof(info);
	uint32_t map_id = 0;
	int rc, value;
	int fd = -1;

	// Iterate through all BPF maps to find the FD of the `psp_spi_map`.
	while (!bpf_map_get_next_id(map_id, &map_id)) {
		fd  = bpf_map_get_fd_by_id(map_id);
		if (fd < 0) {
			fprintf(stderr, "Error reading fd by id(%d): %d\n",
				map_id, fd);
			return fd;
		}

		rc = bpf_obj_get_info_by_fd(fd, &info, &info_len);
		if (rc < 0) {
			fprintf(stderr,
				"Error reading map info by fd(%d): %d\n", fd,
				rc);
			return rc;
		}

		if (!strncmp(info.name, map_name, strlen(map_name)))
			break;
	}

	if (fd < 0) {
		fprintf(stderr, "Could not find map %s: %d\n", map_name, fd);
		return fd;
	}

	value = 0;
	rc = bpf_map_lookup_elem(fd, &spi, &value);
	if (rc < 0) {
		fprintf(stderr, "Could not read map %s: %d\n", map_name, rc);
		return rc;
	}

	if (value != 1) {
		fprintf(stderr,
			"Map value for SPI %08X is wrong. Expected 1 vs. %d\n",
			spi, value);
		return -EINVAL;
	}

	return 0;
}


static void
dump_tuple(const struct psp_spi_tuple *t)
{
	const unsigned char *c = (const unsigned char *)t;
	int i;

	pid_printf("Tuple");
	for (i = 0; i < sizeof(*t); i++) {
		pid_printf(" %02x", c[i]);
	}
	pid_printf("\n");
}

void
parse_ip_version(const char *argv0, const char *optarg)
{
	if (strcmp(optarg, "ipv6") == 0)
		return;
	if (strcmp(optarg, "6") == 0)
		return;
	fprintf(stderr, "%s: bad --ip_version: %s\n", argv0, optarg);
	exit(usage(argv0));
}

static int
ip_name_to_sa(const char *name, struct sockaddr_in6 *sin6, int port)
{
	memset(sin6, 0, sizeof(struct sockaddr_in6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(port);
	if (inet_pton(AF_INET6, name, &sin6->sin6_addr) != 1) {
		error(0, errno, "Server address '%s' doesn't parse", name);
		return -1;
	}
	return 0;
}

/* Data consumers, to take data which has arrived over the network and
 *  do something with it.
 */

static void append_to_pending(const void *data, size_t len)
{
	struct pending_data *new_data;
	size_t len_to_take;
	if (pending_tail && len + pending_tail->count <= MAX_PER_PENDING) {
		memcpy(pending_tail->data + pending_tail->count,
		    data, len);
		pending_tail->count += len;
		return;
	}
	while (len > 0) {
		len_to_take = len > MAX_PER_PENDING ? MAX_PER_PENDING : len;
		new_data = malloc(sizeof(struct pending_data));
		new_data->count = len_to_take;
		new_data->offset = 0;
		new_data->next = NULL;
		new_data->repeat_bytes = 0;
		new_data->generation = 0;
		memcpy(new_data->data, data, len_to_take);
		if (pending_tail)
			pending_tail->next = new_data;
		else
			pending_head = new_data;
		pending_tail = new_data;
		data += len_to_take;
		len -= len_to_take;
	}
}

static void append_bulk_pending(size_t len)
{
	struct pending_data *new_data;
	new_data = malloc(sizeof(struct pending_data));
	memset(new_data->data, '*', sizeof(new_data->data));
	new_data->data[sizeof(new_data->data)-1] = '\n';
	if (len > sizeof(new_data->data)) {
		new_data->count = sizeof(new_data->data);
		new_data->repeat_bytes = len - sizeof(new_data->data);
	} else {
		new_data->count = len;
		new_data->repeat_bytes = 0;
	}
	new_data->offset = 0;
	new_data->next = NULL;
	new_data->generation = 0;
	if (pending_head == NULL)
		pending_head  = new_data;
	else
		pending_tail->next = new_data;
	pending_tail = new_data;
}

static void write_output(const void *data, size_t len)
{
	write(1, data, len);
}

static void discard_output(const void *data, size_t len)
{
}

/* Read data from an FD known to have it available, and pass the data
 * to a consumer.
 */

static int data_readable(int fd, void (*take_data)(const void *, size_t))
{
	uint8_t data[MAX_PER_PENDING];
	ssize_t len;
	len = read(fd, data, sizeof(data));
	if (len <= 0)
		return len;
	(*take_data)(data, (size_t) len);
	return len;
}

static void push_data(int fd)
{
	ssize_t wrote = 0;
	size_t to_write;
	int force_sleep = 0;
	if (!pending_head) {
		fprintf(stderr, "Oops!  push_data() with empty queue!\n");
		return;
	}
	to_write = pending_head->count - pending_head->offset;
	if (psp_randomize && to_write > 0) {
		if (++psp_write_loops == 3) {
			psp_write_loops = 0;
		} else {
			psp_seed = psp_seed * 1103515245 + 12345;
			to_write = (psp_seed % to_write) + 1;
			force_sleep = 1;
		}
	}
	wrote = write(fd, pending_head->data + pending_head->offset,
	    to_write);
	if (wrote < 0) {
		perror("push_data");
		return;
	}
	pending_head->offset += wrote;
	if (pending_head->offset >= pending_head->count) {
		if (pending_head->repeat_bytes > 0) {
			char generation[128];
			snprintf(generation, sizeof(generation),
			    "*** This is automatic repetition %08d ***\n",
			    pending_head->generation);
			++pending_head->generation;
			if (strlen(generation) > sizeof(pending_head->data)) {
				memcpy(pending_head->data, generation,
				    sizeof(pending_head->data));
			} else {
				memcpy(pending_head->data, generation,
				    strlen(generation));
			}
			if (pending_head->repeat_bytes <
			    sizeof(pending_head->data))
				pending_head->count =
					pending_head->repeat_bytes;
			pending_head->repeat_bytes -= pending_head->count;
			pending_head->offset = 0;
		} else {
			struct pending_data *fini = pending_head;
			pending_head = fini->next;
			free(fini);
			if (!pending_head)
				pending_tail = NULL;
		}
	}
	if (force_sleep)
		usleep(10000);
}

/* Full duplex transmission routine. */

static int full_duplex_io(int fd, void (*take_data)(const void *, size_t),
	int early_shutdown)
{
	static const int one = 1;
	int sent_shutdown = 0;
	int socket_eof = 0;
	int flags;
	int polls;
	struct pollfd fds;
	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		perror("fcntl F_SETFL O_NONBLOCK");
		return -1;
	}
	if (psp_randomize)
		if (0 > setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one,
			sizeof(one)))
			perror("setsockopt TCP_NONDELAY");
	fds.fd = fd;
	/* Loop until reading the fd has reported end-of-file or error,
	 * and we have no further data left to write.
	 */
	while (!socket_eof || pending_head != NULL) {
		fds.events = 0;
		if (!socket_eof)
			fds.events |= POLLIN;
		if (pending_head) {
			fds.events |= POLLOUT;
		} else if (early_shutdown && !sent_shutdown) {
			shutdown(fd, SHUT_WR);
			sent_shutdown = 1;
		}
		polls = poll(&fds, 1, 0);
		if (polls < 0) {
			perror("Poll");
			return polls;
		}
		if (fds.revents & POLLIN) {
			if (data_readable(fd, take_data) <= 0)
				socket_eof = 1;
		}
		if (fds.revents & POLLOUT)
			push_data(fd);
	}
	return 0;
}

static void randomize(void *target, size_t count)
{
	static int urandom = -1;
	ssize_t got;
	if (urandom < 0) {
		urandom = open("/dev/urandom", O_RDONLY);
		if (urandom < 0) {
			perror("open /dev/urandom");
			exit(1);
		}
	}
	got = read(urandom, target, count);
	if (got != count) {
		perror("read /dev/urandom");
		exit(1);
	}
}

static void v4map(struct sockaddr_in6 *v6, struct sockaddr_in *v4)
{
	uint32_t *addr32 = (uint32_t *)(&v6->sin6_addr);

	addr32[0] = 0;
	addr32[1] = 0;
	addr32[2] = htonl(0xffff);
	addr32[3] = v4->sin_addr.s_addr;
}



/* Parses a value for the size of the bulk data.  The size
 * is an integer, optionally followed by one or more multiplier
 * factors.  Lower-case factors "k", "m", and "g" are the mundane
 * "powers of ten" multipliers, while the upper-case "K", "M", and
 * "G" are for kibi/mibi/gibi powers-of-two multipliers.  Multiplier
 * factors accumulate... e.g. "10kk" is equivalent to "10m", while
 * "2kG" is 2147483648000 (2*1000*1024*1024*1024).  If the integer
 * is missing/degenerate/empty it is assumed to be 1 - e.g. a
 * size value of G means "1000000000".
 */
static uint64_t parse_size(char *s)
{
	uint64_t multiplier = 1;
	uint64_t multiplicand = 1;
	char *last;
	int scanning = 1;
	last = s + strlen(s) - 1;
	while (scanning) {
		if (last < s)
			break;
		switch (*last) {
		case 'k':
			multiplier *= 1000;
			break;
		case 'K':
			multiplier *= 1024;
			break;
		case 'm':
			multiplier *= 1000000;
			break;
		case 'M':
			multiplier *= 1024 * 1024;
			break;
		case 'g':
			multiplier *= 1000000000;
			break;
		case 'G':
			multiplier *= 1024 * 1024 * 1024;
			break;
		default:
			scanning = 0;
			break;
		}
		if (scanning) {
			*last = '\0';
			--last;
		}
	}
	if (*s != '\0')
		multiplicand = atol(s);
	return multiplier * multiplicand;
}


/* Create and return a TCP socket bound to a given device. */
static int sock(const char *dev, int pf, int af, int port)
{
	struct ifaddrs *ifaddrs, *ifa;
	int s = -1, rc, fam;
	int on = 1;
	struct sockaddr_storage ifaddr_storage;
	struct sockaddr *ifaddr = (struct sockaddr *)&ifaddr_storage;
	struct sockaddr_in *ifaddr4 = (struct sockaddr_in *)&ifaddr_storage;
	struct sockaddr_in6 *ifaddr6 = (struct sockaddr_in6 *)&ifaddr_storage;
	int ifaddrlen;
	struct sockaddr_in *ifa4;
	struct sockaddr_in6 *ifa6;
	char addrbuf[INET6_ADDRSTRLEN];

	rc = getifaddrs(&ifaddrs);
	if (rc)
		return -1;

	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_name)
			continue;

		if (strcmp(ifa->ifa_name, dev))
			continue;

		if (!ifa->ifa_addr)
			continue;

		fam = ifa->ifa_addr->sa_family;
		ifa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		ifa4 = (struct sockaddr_in *)ifa->ifa_addr;

		if (af && (af != fam))
			continue;

		memset(&ifaddr_storage, 0, sizeof(ifaddr_storage));

		switch (pf) {
		case AF_INET:
			*ifaddr4 = *ifa4;
			ifaddr4->sin_family = pf;
			ifaddr4->sin_port = port;
			ifaddrlen = sizeof(struct sockaddr_in);
			inet_ntop(AF_INET, &ifaddr4->sin_addr,
				  addrbuf, sizeof(addrbuf));
			break;
		case AF_INET6:
			if (zero_bind)
				memset(ifaddr6, 0, sizeof(*ifaddr6));
			else if (af == pf)
				*ifaddr6 = *ifa6;
			else
				v4map(ifaddr6, ifa4);
			ifaddr6->sin6_family = pf;
			ifaddr6->sin6_port = port;

			ifaddrlen = sizeof(struct sockaddr_in6);
			inet_ntop(AF_INET6, &ifaddr6->sin6_addr,
				  addrbuf, sizeof(addrbuf));
			break;
		default:
			continue;
		}

		s = socket(pf, SOCK_STREAM, 0);
		if (s < 0) {
			perror("socket");
			continue;
		}
		rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
				&on, sizeof(on));
		if (rc) {
			perror("setsockopt(SO_REUSEADDR)");
			close(s);
			s = -1;
			continue;
		}
		if (psp_reuse) {
			rc = setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
					&on, sizeof(on));
			if (rc) {
				perror("setsockopt(SO_REUSEPORT)");
				close(s);
				s = -1;
				continue;
			}
		}
		printf("binding to %s port %d\n",
		       addrbuf, ntohs(port));
		rc = bind(s, ifaddr, ifaddrlen);
		if (rc) {
			perror("bind");
			close(s);
			s = -1;
			continue;
		}

		break;
	}

	freeifaddrs(ifaddrs);
	return s;
}

static int check_psp(int fd)
{
	int val;
	socklen_t len;

	len = sizeof(val);

	if (getsockopt(fd, IPPROTO_TCP, TCP_PSP_CHECK, &val, &len)) {
		perror("TCP_PSP_CHECK");
		return 1;
	}
	printf("TCP_PSP_CHECK val is %d\n", val);

	return (val == 0);
}



static void print_stats(int fd)
{
	struct tcp_info info;
	socklen_t info_size = sizeof(info);
	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &info_size)) {
		perror("getsockinfo");
		return;
	}

	printf("tcpi_state: %d\n", info.tcpi_state);
	printf("tcpi_ca_state: %d\n", info.tcpi_ca_state);
	printf("tcpi_retransmits: %d\n", info.tcpi_retransmits);
	printf("tcpi_probes: %d\n", info.tcpi_probes);
	printf("tcpi_backoff: %d\n", info.tcpi_backoff);
	printf("tcpi_options: %d\n", info.tcpi_options);
	printf("tcpi_snd_wscale: %d\n", info.tcpi_snd_wscale);
	printf("tcpi_rcv_wscale: %d\n", info.tcpi_rcv_wscale);
	printf("tcpi_rto: %d\n", info.tcpi_rto);
	printf("tcpi_ato: %d\n", info.tcpi_ato);
	printf("tcpi_snd_mss: %d\n", info.tcpi_snd_mss);
	printf("tcpi_rcv_mss: %d\n", info.tcpi_rcv_mss);
	printf("tcpi_unacked: %d\n", info.tcpi_unacked);
	printf("tcpi_sacked: %d\n", info.tcpi_sacked);
	printf("tcpi_lost: %d\n", info.tcpi_lost);
	printf("tcpi_retrans: %d\n", info.tcpi_retrans);
	printf("tcpi_fackets: %d\n", info.tcpi_fackets);
	printf("tcpi_last_data_sent: %d\n", info.tcpi_last_data_sent);
	printf("tcpi_last_ack_sent: %d\n", info.tcpi_last_ack_sent);
	printf("tcpi_last_data_recv: %d\n", info.tcpi_last_data_recv);
	printf("tcpi_last_ack_recv: %d\n", info.tcpi_last_ack_recv);
	printf("tcpi_pmtu: %d\n", info.tcpi_pmtu);
	printf("tcpi_rcv_ssthresh: %d\n", info.tcpi_rcv_ssthresh);
	printf("tcpi_rtt: %d\n", info.tcpi_rtt);
	printf("tcpi_rttvar: %d\n", info.tcpi_rttvar);
	printf("tcpi_snd_ssthresh: %d\n", info.tcpi_snd_ssthresh);
	printf("tcpi_snd_cwnd: %d\n", info.tcpi_snd_cwnd);
	printf("tcpi_advmss: %d\n", info.tcpi_advmss);
	printf("tcpi_reordering: %d\n", info.tcpi_reordering);
}

static int do_client(const char *dev, const char *server_name, int port)
{
	int s;
	int err;
	int s2;
	ssize_t count;
	struct sockaddr_in6 server_addr;
	socklen_t caller_size;
	struct psp_spi_tuple client_tuple, syn_tuple;
	struct psp_server my_server_params;
	socklen_t len;
	long ms;
	struct timeval startTime, endTime;
	const char message[] = "Client sends: Hello world!";
	int pf = PF_INET6;
	int af = AF_INET6;

	do {

		s = sock(dev, pf, af, 0);
		if (s < 0)
			return -1;
		s2 = sock(dev, pf, af, 0);
		if (s2 < 0)
			return -1;

		if (psp_bypass) {
			do {
				randomize(&client_tuple, sizeof(client_tuple));
			} while (client_tuple.spi == 0);
		} else {
			caller_size = sizeof(client_tuple);
			err = getsockopt(s2, IPPROTO_TCP, TCP_PSP_RX_SPI_KEY,
			    &client_tuple, &caller_size);
			if (err < 0) {
				perror("getsockopt TCP_PSP_RX_SPI_KEY");
				return -1;
			}
		}

		printf("Got SPI 0x%08X for our secure connection\n",
		    client_tuple.spi);

		client_tuple.spi = htonl(client_tuple.spi);

		if (ip_name_to_sa(server_name, &server_addr, port) < 0) {
			fprintf(stderr, "ERROR: no such host\n");
			return -1;
		}
		if (psp_fastopen) {
			dump_tuple(&client_tuple);
			count = sendto(s, &client_tuple, sizeof(client_tuple),
				       MSG_FASTOPEN, &server_addr,
				       sizeof(server_addr));
			if (count != sizeof(client_tuple)) {
				perror("sendto tuple");
				return -1;
			}
			if (check_psp(s)) {
				fprintf(stderr, "path not PSP-capable!\n");
				return -1;
			}
			printf("Connected to server (fastopen), wrote SPI and key, awaiting response\n");
		} else {
			if (connect(s, &server_addr, sizeof(server_addr)) < 0) {
				perror("connect");
				return -1;
			}
			if (check_psp(s)) {
				fprintf(stderr, "path not PSP-capable!\n");
				return -1;
			}

			printf("Connected to server, writing our SPI and key\n");
			count = write(s, &client_tuple, sizeof(client_tuple));
			if (count != sizeof(client_tuple)) {
				perror("write tuple");
				return -1;
			}
			printf("Wrote SPI and key, awaiting response\n");
		}
		count = read(s, &my_server_params, sizeof(my_server_params));
		if (count != sizeof(my_server_params)) {
			perror("read response");
			printf("Wanted %lu bytes, got %ld bytes\n",
			    sizeof(my_server_params), count);
			return -1;
		}
		my_server_params.tuple.spi = ntohl(my_server_params.tuple.spi);
		my_server_params.port = ntohs(my_server_params.port);
		printf("Server wants contact on port %d using SPI %08X\n",
		    my_server_params.port, my_server_params.tuple.spi);
		close(s);

		if (psp_break)
			my_server_params.tuple.key.k[0] ^= 0xa5;

		if (!psp_bypass) {
			err = setsockopt(s2, IPPROTO_TCP, TCP_PSP_TX_SPI_KEY,
			    &my_server_params.tuple,
			    sizeof(my_server_params.tuple));
			if (err < 0) {
				perror("setsockopt TCP_PSP_TX_SPI_KEY");
				return -1;
			}
		}
		server_addr.sin6_port = htons(my_server_params.port);
		if (psp_fastopen) {
			count = sendto(s2, message, sizeof(message),
				       MSG_FASTOPEN, &server_addr,
				       sizeof(server_addr));
			if (count != sizeof(message)) {
				perror("sendto message");
				return -1;
			}
			printf("Connected! (fastopen)\n");
		} else {
			printf("Connecting to secure port\n");
			if (connect(s2, &server_addr,
				    sizeof(server_addr)) < 0) {
				perror("secure connect");
				return -1;
			}
			append_to_pending(message, sizeof(message));
			printf("Connected!\n");
		}
		if (!psp_bypass) {
			len = sizeof(syn_tuple);
			memset(&syn_tuple, 0, len);
			err = getsockopt(s2, IPPROTO_TCP, TCP_PSP_SYN_SPI,
			    &syn_tuple, &len);
			if (err == 0) {
				printf("Server is using SPI %08X\n",
					syn_tuple.spi);
			} else {
				perror("get PSP syn info");
			}
		}
		if (psp_bulk_length > 0)
			append_bulk_pending(psp_bulk_length);
		gettimeofday(&startTime, NULL);
		if (psp_quiet)
			full_duplex_io(s2, discard_output, 1);
		else
			full_duplex_io(s2, write_output, 1);
		gettimeofday(&endTime, NULL);
		printf("\nConnection closed\n");
		ms = 1000 * (endTime.tv_sec - startTime.tv_sec);
		ms += (endTime.tv_usec - startTime.tv_usec) / 1000;
		printf("Data transfer required %ld milliseconds\n", ms);
		if (psp_stats)
			print_stats(s2);
		close(s2);
	} while (psp_loop);
	return 0;
}

static int do_server(const char *dev, int port)
{
	socklen_t len;
	int s, client;
	int err;
	int s2 = -1;
	int port2 = 0;
	ssize_t count;
	struct sockaddr_storage caller_storage;
	struct sockaddr *caller = (struct sockaddr *)&caller_storage;
	struct sockaddr_storage secure_sock_storage;
	struct sockaddr *secure_sock = (struct sockaddr *)&secure_sock_storage;
	struct sockaddr_in6 *secure_sock6 =
		(struct sockaddr_in6 *)&secure_sock_storage;
	socklen_t caller_size;
	struct psp_spi_tuple client_tuple;
	struct psp_spi_addr_tuple my_addr_tuple;
	struct psp_server my_server_params;
	const char preamble[] = "Server echoes back: ";
	int pf = PF_INET6;
	int af = AF_INET6;

	s = sock(dev, pf, af, htons(port));
	if (s < 0) {
		perror("sock");
		return 1;
	}
	if (psp_fastopen) {
		int qlen = 5;
		if (setsockopt(s, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen))) {
			perror("setsockopt(TCP_FASTOPEN)");
			return 1;
		}
	}
	pid_printf("Server bound to port %d using fd %d\n", port, s);
	if (listen(s, 1)) {
		perror("listen");
		return 1;
	}
	pid_printf("Listening\n");
	caller_size = sizeof(struct sockaddr_in6);
	do {
		client = accept(s, caller, &caller_size);
		if (client < 0) {
			perror("accept");
			return 1;
		}
		pid_printf("Accepted connection on descriptor %d\n", client);
		count = read(client, &client_tuple, sizeof(client_tuple));
		if (count < 0) {
			perror("read");
			return 1;
		}
		if (count != sizeof(client_tuple)) {
			fprintf(stderr,
			    "Expected %lu bytes from client, got %lu\n",
			    sizeof(client_tuple), count);
			return 1;
		}
		client_tuple.spi = ntohl(client_tuple.spi);
		pid_printf("Got client tuple, client's SPI is %08X\n",
		    client_tuple.spi);
		if (s2 < 0) {
			if (psp_same_port) {
				s2 = s;
				port2 = port;
				pid_printf("Reusing port %d fd %d\n",
				    port2, s2);
			} else {
				s2 = sock(dev, pf, af, 0);
				if (s2 < 0)
					return 1;
				len = sizeof(struct sockaddr_in6);
				if (getsockname(s2, secure_sock, &len) < 0) {
					perror("getsockname");
					return 1;
				}
				port2 = ntohs(secure_sock6->sin6_port);
				pid_printf(
				    "Secure socket bound to port %d using fd %d\n",
				    port2, s2);
				if (listen(s2, 1)) {
					perror("listen");
					return 1;
				}
				pid_printf("Secure socket listening on port %d\n",
				    port2);
			}
		}
		my_addr_tuple.tuple = client_tuple;
		if (psp_bypass) {
			do {
				randomize(&my_addr_tuple.tuple,
					  sizeof(my_addr_tuple.tuple));
			} while (my_addr_tuple.tuple.spi == 0);
		} else {
			if (zero_bind) {
				char addrbuf[INET6_ADDRSTRLEN];
				struct sockaddr_in6 sockname;

				len = sizeof(sockname);
				if (getsockname(client, &sockname, &len) < 0) {
					perror("getsockname client");
					return 1;
				}
				my_addr_tuple.saddr = sockname.sin6_addr;
				inet_ntop(AF_INET6, &my_addr_tuple.saddr,
					  addrbuf, sizeof(addrbuf));
				pid_printf("Local address is %s\n", addrbuf);
				len = sizeof(my_addr_tuple);
			} else {
				len = sizeof(my_addr_tuple.tuple);
			}
			err = getsockopt(s2, IPPROTO_TCP, TCP_PSP_LISTENER,
			    &my_addr_tuple,
			    &len);
			if (err < 0) {
				perror("getsockopt TCP_PSP_LISTENER");
				return 1;
			}
		}
		my_server_params.tuple.key = my_addr_tuple.tuple.key;
		my_server_params.tuple.spi = htonl(my_addr_tuple.tuple.spi);
		my_server_params.port = htons(port2);
		pid_printf("My receive SPI is %08X\n", my_addr_tuple.tuple.spi);
		count = write(client, &my_server_params,
		    sizeof(my_server_params));
		pid_printf("Wrote parameters, got %ld back from write\n", count);
		if (count < 0) {
			perror("write");
			return 1;
		}
		close(client);
		if (psp_same_port) {
			pid_printf("Awaiting call on dual-purpose socket\n");
		} else {
			if (!psp_loop) {
				close(s);
				s = -1;
			}
			pid_printf("Awaiting call on secure socket\n");
		}
		caller_size = sizeof(struct sockaddr_in6);
		client = accept(s2, caller, &caller_size);
		if (client < 0) {
			perror("accept");
			return 1;
		}
		pid_printf("Accepted connection on descriptor %d\n", client);
		if (!psp_same_port) {
			close(s2);
			s2 = -1;
		}
		if (!psp_bypass) {
			len = sizeof(client_tuple);
			memset(&client_tuple, 0, len);
			if (getsockopt(client, IPPROTO_TCP, TCP_PSP_SYN_SPI,
				&client_tuple, &len) < 0) {
				perror("getsockopt TCP_PSP_SYN_SPI");
				return 1;
			}
			pid_printf("Client is sending using SPI %08X\n",
			    client_tuple.spi);
			if (psp_bpf) {
				err = verify_bpf_map(client_tuple.spi);
				if (err < 0)
					return 1;
			}
		}
		append_to_pending(preamble, sizeof(preamble));
		if (psp_quiet)
			full_duplex_io(client, discard_output, 1);
		else
			full_duplex_io(client, append_to_pending, 0);
		pid_printf("Connection closed\n");
		if (psp_stats)
			print_stats(client);
		close(client);
	} while (psp_loop);
	return 0;
}

static int do_servers(const char *dev, int port)
{
	int i;

	if (!psp_reuse)
		return do_server(dev, port);

	printf("Starting %d servers with SO_REUSEPORT enabled\n", psp_reuse);

	for (i = 0; i < psp_reuse; i++) {
		switch (fork()) {
		case -1:
			fprintf(stderr, "error in fork()\n");
			return -1;
		case 0:
			return do_server(dev, port);
		default:
			break;
		}
	}

	for (i = 0; i < psp_reuse; i++)
		waitpid(-1, NULL, 0);

	return 0;
}

static int do_check(void)
{
	return 1; /* For now, trivially report failure always. */
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	const char *dev = NULL;
	const char *server = NULL;
	int port = 0;
	int rc;
	int opt;
	int options_index = 0;

	static struct option long_options[] = {
		{"bypass",    no_argument,   &psp_bypass, 1},
		{"same",      no_argument,   &psp_same_port, 1},
		{"loop",      no_argument,   &psp_loop, 1},
		{"randomize", no_argument,   &psp_randomize, 1},
		{"check",     no_argument,   NULL, 'c'},
		{"break",     no_argument,   &psp_break, 'B'},
		{"send",      required_argument, NULL, 'S'},
		{"quiet",     no_argument,   &psp_quiet, 'q'},
		{"stats",     no_argument,   &psp_stats, 1},
		{"ip_version", required_argument, NULL, 'v'},
		{"reuseport", required_argument, &psp_reuse, 'r'},
		{"fastopen",  no_argument,   &psp_fastopen, 'f'},
		{"zerobind",  no_argument,   &zero_bind, 'z'},
		{"bpf",       no_argument,   &psp_bpf, 'e'},
		{NULL,        no_argument,   NULL, 0 } };

	do {
		randomize(&psp_seed, sizeof(psp_seed));
	} while (psp_seed == 0);

	while ((opt = getopt_long(argc, argv, "bBcelsS:v:r:fqz", long_options,
		    &options_index)) != -1) {
		switch (opt) {
		case 'b':
			psp_bypass = 1;
			break;
		case 'B':
			psp_break = 1;
			break;
		case 's':
			psp_same_port = 1;
			break;
		case 'l':
			psp_loop = 1;
			break;
		case 'e':
			psp_bpf = 1;
			break;
		case 'c':
			usage(argv[0]);
			return do_check();
		case 'S':
			psp_bulk_length = parse_size(optarg);
			break;
		case 'v':
			parse_ip_version(argv[0], optarg);
			break;
		case 'r':
			psp_reuse = atoi(optarg);
			break;
		case 'f':
			psp_fastopen = 1;
			break;
		case 'q':
			psp_quiet = 1;
			break;
		case 'z':
			zero_bind = 1;
			break;
		case 0:
			break;
		default:
			return usage(argv[0]);
		}
	}

	argc = argc - optind;

	switch (argc) {
	case 3:
		dev = argv[optind];
		server = argv[optind+1];
		port = atoi(argv[optind+2]);
		rc = do_client(dev, server, port);
		break;

	case 2:
		if (psp_bpf) {
			// With this option, a BPF program is enabled to record
			// the SPI on incoming packets in order to verify BPF
			// can read the SPI field.
			obj = open_and_load_bpf();
			if (!obj) {
				rc = EINVAL;
				break;
			}

			link = attach_bpf(obj);
			if (!link) {
				rc = EINVAL;
				break;
			}
		}

		dev = argv[optind];
		port = atoi(argv[optind+1]);
		rc = do_servers(dev, port);

		if (rc)
			break;

		break;

	default:
		rc = usage(argv[0]);
		break;
	}

	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);
	return rc;
}
