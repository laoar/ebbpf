#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fentry.skel.h"

const char* program_name;

static int
libbpf_output(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static struct option long_options[] = {
	{"sym", required_argument, NULL, 's'},
	{0, 0, 0, 0 }
};

void print_help()
{
	fprintf(stdout, "Usage:  %s -s symbol\n", program_name);
	fprintf(stdout, "  -h  --help       Display this usage information.\n"
					"  -s  --symbol     Symbol to attach\n");
	exit(EXIT_SUCCESS);
}

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(int argc, char *argv[])
{
	struct fentry_bpf *skel;
	char *sym = NULL;
	int err = 0;
	char c;

	program_name = strdup(argv[0]);
	while ((c = getopt_long(argc, argv, "hs:", long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			print_help();
			break;
		case 's':
			sym = strdup(optarg);
			break;
		default:
			fprintf(stderr, "Unknow option: %s\n", optarg);
			exit(EXIT_FAILURE);
		}
	}

	if (!sym) {
		fprintf(stderr, "Pls. set the symbol!\n");
		exit(EXIT_FAILURE);
	}

	skel = fentry_bpf__open();
	if (!skel) {
		fprintf(stderr, "fail to open skeleton\n");
		exit(EXIT_FAILURE);
	}
	err = bpf_program__set_attach_target(skel->progs.fentry_run, 0, sym);
	if (err) {
		fprintf(stderr, "fail to set target\n");
		goto cleanup;
	}
	err = fentry_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load bpf skeleton\n");
		goto cleanup;
	}

	err = fentry_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach bpf programs\n");
		goto cleanup;
	}

	// read_trace_pipe();

cleanup:
	fentry_bpf__destroy(skel);
	return err;  
}
