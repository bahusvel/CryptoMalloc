#ifndef __TIME_IT__
#define __TIME_IT__

#define TIMEIT_INIT()                                                          \
	struct timeval start;                                                      \
	struct timeval stop;                                                       \
	unsigned long stime;                                                       \
	unsigned long ftime;

#define TIMEIT(expression)                                                     \
	gettimeofday(&start, NULL);                                                \
	expression;                                                                \
	gettimeofday(&stop, NULL);                                                 \
	stime = 1000000 * start.tv_sec + start.tv_usec;                            \
	ftime = 1000000 * stop.tv_sec + stop.tv_usec;                              \
	printf(#expression " took: %ld us\n", ftime - stime);

#endif
