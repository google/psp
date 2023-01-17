#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <linux/limits.h>
#include <linux/psp.h>
#include <linux/tcp.h>
#include <math.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/*
 * ############################
 * TEST CASES DECLARATION
 * ############################
 */
static void *psp_key_gen(void *arg);
static void *psp_key_install(void *arg);
static void *psp_key_listener(void *arg);

/*
 * ############################
 * DATA STRUCTURES and GLOBALS
 * ############################
 */
/* PSP key_mgmt_test stats */
typedef enum {
	KEY_GENERATION,	/* number of PSP keys generated */
	KEY_INSERTION,	/* number of PSP keys inserted */
	KEY_DELETION,	/* number of PSP keys deleted */
	KEY_LISTENER,	/* number of PSP keys listened */
	TIME_GENERATION,/* elapsed time for key generation */
	TIME_INSERTION, /* elapsed time for key insertion */
	TIME_DELETION,  /* elapsed time for key deletion */
	TIME_LISTENER,	/* elapsed time for key listener */
	ERR_LISTENER,	/* number of key listener errors */
	ERR_DELETION,   /* number of key deletion errors */
	ERR_INSERTION,  /* number of key insertion errors */
	ERR_GENERATION,	/* number of key generation errors */
	MAX_DELAY_WOR,	/* max delay when no error happened */
	MAX_DELAY_WR,	/* max delay when error happened */
	STAT_ALL,	/* must be the last */
} psp_stat_t;

/* Descriptions of above stats */
static const char *psp_stat_desc[] = {
	"Key_generation_throughput",
	"Key_insertion_throughput",
	"Key_deletion_throughput",
	"Key_listener_throughput",
	"Elapsed_generation_time(us)_per_sec",
	"Elapsed_insertion_time(us)_per_sec",
	"Elapsed_deletion_time(us)_per_sec",
	"Elapsed_listener_time(us)_per_sec",
	"Err_listener_per_sec",
	"Err_deletion_per_sec",
	"Err_insertion_per_sec",
	"Err_generation_per_sec",
	"Max_delay_wo_error(us)",
	"Max_delay_w_error(us)",
};

/* Telemetry struct */
typedef struct {
	double mean[STAT_ALL];
	double std[STAT_ALL];
} telemetry_t;

/* Thread struct */
typedef struct {
	pthread_t tID;		   /* ID returned by pthread_create() */
	int tNum;		   /* application-defined thread number */
	int tSock;		   /* thread associated socket */
	const char *dev;	   /* device under test */
	uint64_t tStats[STAT_ALL]; /* statistics array */
} thread_t;

/* Worker struct */
typedef struct {
	char name[NAME_MAX];
	void* (*worker)(void *arg);
} psp_task_t;

/* Test_case struct */
typedef struct {
	int id;			/* test case ID */
	bool enabled;		/* test case enabled */
	psp_task_t task;	/* function pointer of task routine */
	telemetry_t *tlm;	/* average stats per workload */
} test_t;

/* Default device interface under test */
static char dev[IFNAMSIZ] = "eth0";
/* Default runtime in seconds */
static int tRuntime = 10;
/* Default iteration rounds */
static int tRound = 10;
/* Default inter request delay */
static int tDelayMS;
/* Default maximum number of connections for a listen socket */
static int maxConn = 1000;
/* Default file path for outputs */
static char filePath[PATH_MAX] = "/tmp/psp_key_benchmark.csv";
/* Global test ID to run (default for all) */
static int testID;
/* Global thread termination flag */
static bool do_stop;
/* Global flag to close sockets at the end of test */
static bool close_sock_later;
/* Global flag to simulate TX key rotation */
static bool rotate_keys;
/* Global flag for psp mode (stateful/stateless) */
static bool stateful_api;
/* Global workloads array */
static int tCounts[] = {1, 10, 100, 500, 1000};
/* Global worker tasks */
static const psp_task_t tasks[] = {
	[0] = {
		.name = "psp_key_generation",
		.worker = psp_key_gen,
	},
	[1] = {
		.name = "psp_key_installation",
		.worker = psp_key_install,
	},
	[2] = {
		.name = "psp_key_listenerer",
		.worker = psp_key_listener,
	},
};

/*
 * ############################
 * Utility Functions
 * ############################
 */
/* Create and return a TCP socket binding to an address associated with a device */
static int sock(const char *dev, int family)
{
	static const int sa_size[] = {
		[AF_INET]	= sizeof(struct sockaddr_in),
		[AF_INET6]	= sizeof(struct sockaddr_in6)
	};

	struct ifaddrs *ifaddrs, *ifa;
	int s = -1, rc, fam;

	rc = getifaddrs(&ifaddrs);
	if (rc) {
		perror("getifaddrs()");
		return -1;
	}

	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_name)
			continue;
		if (strcmp(ifa->ifa_name, dev))
			continue;
		if (!ifa->ifa_addr)
			continue;

		fam = ifa->ifa_addr->sa_family;
		if (family && (family != fam))
			continue;

		s = socket(fam, SOCK_STREAM, 0);
		if (s < 0) {
			perror("socket");
			continue;
		}

		rc = bind(s, ifa->ifa_addr, sa_size[fam]);
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

/* Compute mean and std from a given array */
static void compute_mean_std(uint64_t *arr, double *mean, double *std)
{
	int i;
	uint64_t sum = 0;
	double avg, var = 0.0;

	for (i = 0; i < tRound; ++i)
		sum += arr[i];
	avg = (double)sum / tRound;

	for (i = 0; i < tRound; ++i)
		var += (arr[i]-avg) * (arr[i]-avg);
	var = var / tRound;

	*mean = avg;
	*std = sqrt(var);
}

/* Helper to compute the mean and std of all stats */
static void compute_stat(uint64_t stat_arr[][STAT_ALL], telemetry_t *tlm)
{
	int i, j;
	double mean, std;
	uint64_t data[tRound];

	for (j = 0; j < STAT_ALL; ++j) {
		for (i = 0; i < tRound; ++i)
			data[i] = stat_arr[i][j];

		compute_mean_std(data, &mean, &std);
		tlm->mean[j] = mean;
		tlm->std[j] = std;
	}
}

/* Print a single round stats to console */
static void print_stats(int round, int count, uint64_t *stats)
{
	int i;

	printf("#Round:%d, Threads:%d,", round, count);
	for (i = 0; i < STAT_ALL; ++i)
		if (stats[i])
			printf(" %s: %lu,", psp_stat_desc[i], stats[i]);
	printf("#\n");
}

/* Print a test case stats to console */
static void print_tlms(int id, char *name, telemetry_t *tlm)
{
	int i, j;

	printf("\n######### Testcase_id: %d, name: %s #########\n",
		id, name);
	for (i = 0; i < ARRAY_SIZE(tCounts) && tCounts[i]; ++i) {
		printf("#Threads: %d,", tCounts[i]);
		for (j = 0; j < STAT_ALL; ++j) {
			if (tlm[i].mean[j])
				printf(" %s: %0.1f/%0.1f (mean/std),",
					psp_stat_desc[j], tlm[i].mean[j], tlm[i].std[j]);
		}
		printf("#\n");
	}
}

/* Print all results to tmp */
static void print_tlms_to_file(test_t *tests, const char *filePath)
{
	int i, j, k;
	FILE *fptr = fopen(filePath, "w");

	if (fptr == NULL)
		error(EXIT_FAILURE, errno,
		      "Error: %s failed to open.\n", filePath);

	for (i = 0; i < ARRAY_SIZE(tasks); ++i) {
		if (!tests[i].enabled)
			continue;
		fprintf(fptr, "\n######### Testcase_id: %d, name: %s #########\n",
			i, tests[i].task.name);
		fprintf(fptr, "Threads,");
		for (j = 0; j < STAT_ALL; ++j)
			fprintf(fptr, "%s-mean,%s-std,",
				psp_stat_desc[j], psp_stat_desc[j]);
		fprintf(fptr, "\n");
		for (j = 0; j < ARRAY_SIZE(tCounts) && tCounts[j]; ++j) {
			fprintf(fptr, "%d,", tCounts[j]);
			for (k = 0; k < STAT_ALL; ++k) {
				fprintf(fptr, "%0.1f,%0.1f,",
					tests[i].tlm[j].mean[k], tests[i].tlm[j].std[k]);
			}
			fprintf(fptr, "\n");
		}
	}

	fclose(fptr);
	printf("\nAll results have been written to %s.\n", filePath);
}

static void usleep_if_requested(void)
{
	if (tDelayMS)
		usleep(tDelayMS * 1000);
}

/* Print tool usage */
static void usage_error(char *cmd)
{
	error(EXIT_FAILURE, 0,
	      "\nUsage options:\n"
	      "[-h] : print usage options\n"
	      "[-s] : close sockets at the end of listener test\n"
	      "[-R] : rotate keys during insertion test\n"
	      "[-d device] : netdev under test\n"
	      "[-D delay] : test delay in milliseconds\n"
	      "[-f filepath] : output results path\n"
	      "[-i testname] : test case name\n"
	      "[-l maxconn] : maximum listen socket connections\n"
	      "[-r round] : the number of rounds for tests\n"
	      "[-t second] : total running time in seconds\n"
	      "[-w workload] : the number of threads for tests\n"
	      "[-z] : expectation for stateful psp mode\n"
	      );
}

/* Check input string length and error out if oversized */
static void check_strLen(char *input, int size)
{
	if (strlen(input) >= size)
		error(EXIT_FAILURE, 0,
		      "Error: %s is longer than the allowed size %d.\n",
		      input, size);
}

static inline uint64_t get_elapsed_time_in_us(struct timeval *start,
					      struct timeval *end)
{
	return ((end->tv_sec - start->tv_sec) * 1000UL * 1000UL +
	       (end->tv_usec - start->tv_usec));
}

/* Run a single testcase */
static void run_task(char *dev, int tCount, uint64_t *stat, psp_task_t *task)
{
	int i, j;
	struct timespec ts;
	thread_t *tInfo = calloc(tCount, sizeof(*tInfo));

	if (tInfo == NULL)
		error(EXIT_FAILURE, errno,
		      "Error: calloc failure when creating %d threads.\n",
		      tCount);

	if (clock_gettime(CLOCK_REALTIME, &ts))
		error(EXIT_FAILURE, errno,
		      "Error: clock_gettime failure.\n");
	else
		ts.tv_sec += tRuntime*2;

	do_stop = false;

	/* setup parallel worker threads */
	for (i = 0; i < tCount; ++i) {
		tInfo[i].tNum = i + 1;
		tInfo[i].dev = dev;
		tInfo[i].tSock = -1;
		if (pthread_create(&tInfo[i].tID, NULL, task->worker, &tInfo[i]))
			error(EXIT_FAILURE, errno,
			      "Error: pthread_create after %d/%d.\n",
			      i, tCount);
	}

	/* idle sleeping while waiting for the timer to hit */
	sleep(tRuntime);

	do_stop = true;

	/* wait for all threads to join */
	for (i = 0; i < tCount; i++) {
		if (pthread_timedjoin_np(tInfo[i].tID, NULL, &ts)) {
			printf("Error: tNum/ID=%d/%lu join failure.\n",
			       tInfo[i].tNum, tInfo[i].tID);
			if (pthread_cancel(tInfo[i].tID))
				error(EXIT_FAILURE, errno,
				      "Error: tNum/ID=%d/%lu cancel failure.\n",
				      tInfo[i].tNum, tInfo[i].tID);
		}
	}

	/* close all thread sockets at the end of test if specified */
	if (close_sock_later) {
		for (i = 0; i < tCount; i++)
			if ((tInfo[i].tSock != -1) && close(tInfo[i].tSock))
				perror("sock_close_end");
	}

	/* compute statistics from all threads */
	for (i = 0; i < tCount; i++) {
		for (j = KEY_GENERATION; j <= ERR_GENERATION; ++j)
			stat[j] += tInfo[i].tStats[j];

		for (j = MAX_DELAY_WOR; j <= MAX_DELAY_WR; ++j)
			if (stat[j] < tInfo[i].tStats[j])
				stat[j] = tInfo[i].tStats[j];
	}

	/* compute throughput if needed */
	for (i = KEY_GENERATION; i <= ERR_GENERATION; ++i)
		stat[i] /= tRuntime;

	free(tInfo);
}

/* Run all workloads */
static void run_workload(char *dev, test_t *test)
{
	int i, j;

	printf("\nRunning %s:\n", test->task.name);
	for (i = 0; i < ARRAY_SIZE(tCounts) && tCounts[i]; ++i) {
		uint64_t stats[tRound][STAT_ALL];
		int tCount = tCounts[i];

		memset(stats, 0, sizeof(stats));

		for (j = 0; j < tRound; ++j) {
			run_task(dev, tCount, stats[j], &test->task);
			print_stats(j, tCount, stats[j]);
		}
		/* compute stats over all rounds */
		compute_stat(stats, &test->tlm[i]);
	}
}

/* Set up test cases */
static test_t *setup_testCase()
{
	int i;
	int num_testcases = ARRAY_SIZE(tasks);
	int num_workloads = ARRAY_SIZE(tCounts);

	test_t *tests = calloc(num_testcases, sizeof(*tests));

	if (tests == NULL)
		error(EXIT_FAILURE, errno,
		      "Error: calloc failure when creating %d num_testcases.\n",
		      num_testcases);

	for (i = 0; i < num_testcases; ++i) {
		tests[i].id = i + 1;
		tests[i].task = tasks[i];
		tests[i].tlm = calloc(num_workloads, sizeof(telemetry_t));
		if (tests[i].tlm == NULL)
			error(EXIT_FAILURE, errno,
			      "Error: calloc failure when creating %d tlms.\n",
			      num_workloads);
		if (!testID || testID == tests[i].id)
			tests[i].enabled = true;
		else
			tests[i].enabled = false;
	}

	return tests;
}

/* Run test cases under workloads */
static void run_testCase(test_t *tests)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tasks); ++i)
		if (tests[i].enabled)
			run_workload(dev, &tests[i]);
}

/* Print test cases statistics and clean up */
static void printStats_cleanUp(test_t *tests)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tasks); ++i)
		if (tests[i].enabled)
			print_tlms(tests[i].id, tests[i].task.name, tests[i].tlm);
	print_tlms_to_file(tests, filePath);

	for (i = 0; i < ARRAY_SIZE(tasks); ++i)
		free(tests[i].tlm);
	free(tests);
}

/*
 * ############################
 * TESTCASE Functions
 * ############################
 */
/* Testcase-1: psp key generation rate test */
static void *psp_key_gen(void *arg)
{
	int s, rc;
	uint64_t us;
	bool err = true;
	socklen_t reqLen;
	thread_t *tInfo = arg;
	struct psp_spi_tuple tuple;
	struct timeval start, end;

	s = sock(tInfo->dev, AF_INET6);
	if (s < 0)
		error(EXIT_FAILURE, errno,
		      "Error: tNum/ID=%d/%lu sock AF_INET6 failure.\n",
		      tInfo->tNum, tInfo->tID);

	reqLen = sizeof(struct psp_spi_tuple);

	while (!do_stop) {
		gettimeofday(&start, NULL);

		rc = getsockopt(s, IPPROTO_TCP, TCP_PSP_RX_SPI_KEY, &tuple, &reqLen);

		gettimeofday(&end, NULL);
		us = get_elapsed_time_in_us(&start, &end);

		if (!rc && reqLen != sizeof(struct psp_spi_tuple))
			printf("Error: tNum/ID=%d/%lu, keyGen req/check=%d/%lu.\n",
			       tInfo->tNum, tInfo->tID,
			       reqLen, sizeof(struct psp_spi_tuple));
		else if (!rc && !tuple.spi)
			printf("Error: tNum/ID=%d/%lu, keyGen tuple.spi==0.\n",
			       tInfo->tNum, tInfo->tID);
		else if (!rc)
			err = false;

		if (err) {
			tInfo->tStats[ERR_GENERATION]++;
			if (us > tInfo->tStats[MAX_DELAY_WR])
				tInfo->tStats[MAX_DELAY_WR] = us;

		} else {
			tInfo->tStats[TIME_GENERATION] += us;
			tInfo->tStats[KEY_GENERATION]++;
			if (us > tInfo->tStats[MAX_DELAY_WOR])
				tInfo->tStats[MAX_DELAY_WOR] = us;
			err = true;
		}

		usleep_if_requested();
	}

	if (close(s))
		perror("sock_close");

	return NULL;
}

/* Testcase-2: psp key installation rate test */
static void *psp_key_install(void *arg)
{
	int i, s, rc;
	uint64_t us;
	socklen_t rxLen = sizeof(struct psp_spi_tuple);
	socklen_t txLen = sizeof(struct psp_spi_tuple);
	thread_t *tInfo = arg;
	struct timeval start, end;
	struct psp_spi_tuple rxTuple;
	struct psp_spi_tuple txTuple = {
		.spi = 9,
		.key.k = {
			1, 2, 3, 4, 5, 6, 7, 8,
			1, 2, 3, 4, 5, 6, 7, 8,
		}
	};

	while (!do_stop) {
		s = sock(tInfo->dev, AF_INET6);
		if (s < 0)
			error(EXIT_FAILURE, errno,
			      "Error: tNum/ID=%d/%lu sock AF_INET6 failure.\n",
			      tInfo->tNum, tInfo->tID);

		/* Need to generate a RX tuple before inserting TX tuple */
		gettimeofday(&start, NULL);
		if (getsockopt(s, IPPROTO_TCP, TCP_PSP_RX_SPI_KEY, &rxTuple, &rxLen)) {
			tInfo->tStats[ERR_GENERATION]++;
			if (close(s))
				perror("sock_close");
			usleep_if_requested();
			continue;
		} else {
			gettimeofday(&end, NULL);
			us = get_elapsed_time_in_us(&start, &end);
			tInfo->tStats[TIME_GENERATION] += us;
			tInfo->tStats[KEY_GENERATION]++;
		}

		gettimeofday(&start, NULL);

		/* install TX tuple */
		rc = setsockopt(s, IPPROTO_TCP, TCP_PSP_TX_SPI_KEY, &txTuple, txLen);

		gettimeofday(&end, NULL);
		us = get_elapsed_time_in_us(&start, &end);

		if (!rc) {
			tInfo->tStats[TIME_INSERTION] += us;
			tInfo->tStats[KEY_INSERTION]++;
			if (us > tInfo->tStats[MAX_DELAY_WOR])
				tInfo->tStats[MAX_DELAY_WOR] = us;

			/* simulate at most two TX keys in use during rotation */
			if (rotate_keys) {
				rc = setsockopt(s, IPPROTO_TCP, TCP_PSP_TX_SPI_KEY,
						&txTuple, txLen);
				if (rc)
					error(EXIT_FAILURE, errno,
					      "Error: tNum/ID=%d/%lu rotate key failure.\n",
					      tInfo->tNum, tInfo->tID);

				for (i = 0; i < maxConn && !do_stop; i++) {
					rc = setsockopt(s, IPPROTO_TCP,
							TCP_PSP_TX_SPI_KEY,
							&txTuple, txLen);
					if (stateful_api &&
					    (!rc || errno != EBUSY))
						error(EXIT_FAILURE, 0,
						      "Error: tNum/ID=%d/%lu rotate key should fail with EBUSY (i/rc/errno=%d/%d/%d).\n",
						      tInfo->tNum, tInfo->tID,
						      i, rc, errno);
				}
			}

			/* remove TX tuple entry via socket close */
			gettimeofday(&start, NULL);
			if (!close(s)) {
				gettimeofday(&end, NULL);
				us = get_elapsed_time_in_us(&start, &end);
				tInfo->tStats[TIME_DELETION] += us;
				tInfo->tStats[KEY_DELETION]++;
			} else {
				tInfo->tStats[ERR_DELETION]++;
				perror("sock_close");
			}
		} else {
			tInfo->tStats[ERR_INSERTION]++;
			if (us > tInfo->tStats[MAX_DELAY_WR])
				tInfo->tStats[MAX_DELAY_WR] = us;
			if (close(s))
				perror("sock_close");
		}

		usleep_if_requested();
	}

	return NULL;
}

/* Testcase-3: psp key listener rate test */
static void *psp_key_listener(void *arg)
{
	int i, s, rc;
	uint64_t us;
	socklen_t txLen = sizeof(struct psp_spi_tuple);
	thread_t *tInfo = arg;
	struct timeval start, end;
	struct psp_spi_tuple txTuple = {
		.spi = 9,
		.key.k = {
			1, 2, 3, 4, 5, 6, 7, 8,
			1, 2, 3, 4, 5, 6, 7, 8,
		}
	};

	while (!do_stop) {
		s = sock(tInfo->dev, AF_INET6);
		if (s < 0)
			error(EXIT_FAILURE, errno,
			      "Error: tNum/ID=%d/%lu sock AF_INET6 failure.\n",
			      tInfo->tNum, tInfo->tID);

		if (close_sock_later)
			tInfo->tSock = s;

		rc = listen(s, maxConn);
		if (rc) {
			close(s);
			error(EXIT_FAILURE, errno,
			      "Error: tNum/ID=%d/%lu sock listen failure.\n",
			      tInfo->tNum, tInfo->tID);
		}

		for (i = 0; i < maxConn && !do_stop; i++) {
			gettimeofday(&start, NULL);

			rc = getsockopt(s, IPPROTO_TCP, TCP_PSP_LISTENER,
					&txTuple, &txLen);

			gettimeofday(&end, NULL);
			us = get_elapsed_time_in_us(&start, &end);

			if (!rc) {
				tInfo->tStats[TIME_LISTENER] += us;
				tInfo->tStats[KEY_LISTENER]++;
				if (us > tInfo->tStats[MAX_DELAY_WOR])
					tInfo->tStats[MAX_DELAY_WOR] = us;
			} else {
				tInfo->tStats[ERR_LISTENER]++;
				if (us > tInfo->tStats[MAX_DELAY_WR])
					tInfo->tStats[MAX_DELAY_WR] = us;
			}
		}

		if (close_sock_later)
			/* Socket will be closed when all threads are done. */
			break;

		/* remove TX tuple entry via socket close */
		gettimeofday(&start, NULL);
		if (!close(s)) {
			gettimeofday(&end, NULL);
			us = get_elapsed_time_in_us(&start, &end);
			tInfo->tStats[TIME_DELETION] += us;
			tInfo->tStats[KEY_DELETION] += maxConn;
		} else {
			tInfo->tStats[ERR_DELETION] += maxConn;
			perror("sock_close");
		}

		usleep_if_requested();
	}

	return NULL;
}

/*
 * ############################
 * Main program starts here
 * ############################
 */
int main(int argc, char **argv)
{
	int i, opt;
	const char *testNames[] = {"generation", "insertion", "listener"};
	test_t *tests;

	/* check any input argument */
	while ((opt = getopt(argc, argv, "d:D:f:hi:l:r:Rt:w:sz")) != -1) {
		switch (opt) {
		case 'd':
			check_strLen(optarg, IFNAMSIZ);
			strcpy(dev, optarg);
			break;
		case 'D':
			tDelayMS = atoi(optarg);
			break;
		case 'f':
			check_strLen(optarg, PATH_MAX);
			strcpy(filePath, optarg);
			break;
		case 'h':
			usage_error(argv[0]);
			break;
		case 'i':
			for (i = 0; i < ARRAY_SIZE(testNames); ++i) {
				if (!strcmp(optarg, testNames[i])) {
					testID = i + 1;
					break;
				}
			}
			if (!testID) {
				printf("-i %s is not supported testName.\n", optarg);
				printf("Please use the following testNames.\n");
				for (i = 0; i < ARRAY_SIZE(testNames); ++i)
					printf("-i %s\n", testNames[i]);
				usage_error(argv[0]);
			}
			break;
		case 'l':
			maxConn = atoi(optarg);
			break;
		case 'r':
			tRound = atoi(optarg);
			break;
		case 'R':
			rotate_keys = true;
			break;
		case 's':
			close_sock_later = true;
			break;
		case 't':
			tRuntime = atoi(optarg);
			break;
		case 'w':
			/* single workload for quick run */
			memset(tCounts, 0, sizeof(tCounts));
			tCounts[0] = atoi(optarg);
			break;
		case 'z':
			stateful_api = true;
			break;
		default:
			usage_error(argv[0]);
		}
	}
	if (optind != argc)
		usage_error(argv[0]);

	printf("Worker thread runtime = %d seconds.\n", tRuntime);
	/* start all test cases */
	tests = setup_testCase();
	run_testCase(tests);
	printStats_cleanUp(tests);

	return EXIT_SUCCESS;
}
