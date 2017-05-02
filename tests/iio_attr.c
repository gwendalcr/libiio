/*
 * libiio - Library for interfacing industrial I/O (IIO) devices
 *
 * Copyright (C) 2014, 2017 Analog Devices, Inc.
 * Author: Paul Cercueil <paul.cercueil@analog.com>
 *         Robin Getz <robin.getz@analog.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * */

#include <errno.h>
#include <getopt.h>
#include <iio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MY_NAME "iio_attr"

#ifdef _WIN32
#define snprintf sprintf_s
#endif

enum backend {
	LOCAL,
	XML,
	AUTO,
};

static const struct option options[] = {
	  {"help", no_argument, 0, 'h'},
	  {"auto", no_argument, 0, 'a'},
	  {"uri", required_argument, 0, 'u'},
	  {"iio-attr", required_argument, 0, 'i'},
	  {"device", required_argument, 0, 'd'},
	  {"device_attr", required_argument, 0, 'e'},
	  {"channel", required_argument, 0, 'c'},
	  {"input-channel", no_argument, 0, 'I'},
	  {"output-channel", no_argument, 0, 'O'},
	  {"scan-channel", no_argument, 0, 'S'},
	  {"channel-attr", required_argument, 0, 'b'},
	  {"debug-attr", required_argument, 0, 'D'},
	  {"verbose", no_argument, 0, 'v'},
	  {"exact-match", no_argument, 0, 'x'},
	  {0, 0, 0, 0},
};

static const char *options_descriptions[] = {
	"Show this help and quit.",
	"Use the first context found.",
	"Use the context at the provided URI.",
	"IIO context attribute to read.",
	"Filter by specified IIO device.",
	"Device attribute to access.",
	"Filter by specified channel name or channel ID.",
	"Filter Input Channels only.",
	"Filter Output Channels only.",
	"Filter Scan Channels only.",
	"Channel attribute to access.",
	"Debug attribute to access.",
	"Be verbose.",
	"Exact name matches only",
};

static void usage(void)
{
	unsigned int i;

	printf("Usage:\n\t" MY_NAME " [-u <uri>]\n\nOptions:\n");
	for (i = 0; options[i].name; i++)
		printf("\t-%c, --%s\n\t\t\t%s\n",
					options[i].val, options[i].name,
					options_descriptions[i]);
}

static bool str_match(bool exact, const char * haystack, char * needle)
{
	bool ret = false;

	if (!haystack || !needle)
		return ret;

	if (!exact) {
		/* strcasestr is a GNU extention, and not supported by MSDN */
		char * tmp1, * tmp2;
		int i;

		tmp1 = strdup(haystack);
		tmp2 = strdup(needle);
		for (i = 0; i < strlen(tmp1); i++)
			tmp1[i] = toupper(tmp1[i]);
		for (i = 0; i < strlen(tmp2); i++)
			tmp2[i] = toupper(tmp2[i]);
		ret = !!strstr(tmp1, tmp2);
		free(tmp1);
		free(tmp2);
	} else {
		ret = !strcmp(haystack, needle);
	}

	return ret;
}
static struct iio_context * autodetect_context(void)
{
	struct iio_scan_context *scan_ctx;
	struct iio_context_info **info;
	struct iio_context *ctx = NULL;
	unsigned int i;
	ssize_t ret;

	scan_ctx = iio_create_scan_context(NULL, 0);
	if (!scan_ctx) {
		fprintf(stderr, "Unable to create scan context\n");
		return NULL;
	}

	ret = iio_scan_context_get_info_list(scan_ctx, &info);
	if (ret < 0) {
		char err_str[1024];
		iio_strerror(-ret, err_str, sizeof(err_str));
		fprintf(stderr, "Scanning for IIO contexts failed: %s\n", err_str);
		goto err_free_ctx;
	}

	if (ret == 0) {
		printf("No IIO context found.\n");
		goto err_free_info_list;
	}
	if (ret == 1) {
		printf("Using auto-detected IIO context at URI \"%s\"\n",
				iio_context_info_get_uri(info[0]));
		ctx = iio_create_context_from_uri(iio_context_info_get_uri(info[0]));
	} else {
		fprintf(stderr, "Multiple contexts found. Please select one using --uri:\n");
		for (i = 0; i < (size_t) ret; i++) {
			fprintf(stderr, "\t%d: %s [%s]\n",
					i, iio_context_info_get_description(info[i]),
					iio_context_info_get_uri(info[i]));
		}
	}

err_free_info_list:
	iio_context_info_list_free(info);
err_free_ctx:
	iio_scan_context_destroy(scan_ctx);

	return ctx;
}


static void dump_device_attributes(const struct iio_device *dev,
		const char *attr, const char *wbuf)
{
	ssize_t ret;
	char buf[1024];

	printf("dev '%s', attr '%s', value :",
			iio_device_get_name(dev), attr);
	ret = iio_device_attr_read(dev, attr, buf, sizeof(buf));
	if (ret > 0) {
		printf("'%s'\n", buf);
	} else {
		iio_strerror(-ret, buf, sizeof(buf));
		printf("ERROR: %s (%li)\n", buf, ret);
	}

	if (wbuf) {
		ret = iio_device_attr_write(dev, attr, wbuf);
		if (ret > 0) {
			printf("wrote %li bytes to %s\n", ret, attr);
		} else {
			iio_strerror(-ret, buf, sizeof(buf));
			printf("ERROR: %s (%li) while writing '%s' with '%s'\n",
					buf, ret, attr, wbuf);
		}
		dump_device_attributes(dev, attr, NULL);
	}
}

static void dump_debug_attributes(const struct iio_device *dev,
		const char *attr, const char *wbuf)
{
	ssize_t ret;
	char buf[1024];

	ret = iio_device_debug_attr_read(dev, attr, buf, sizeof(buf));

	printf("dev '%s', debug attr '%s', value :",
			iio_device_get_name(dev), attr);

	if (ret > 0) {
		printf("'%s'\n", buf);
	} else {
		iio_strerror(-ret, buf, sizeof(buf));
		printf("ERROR: %s (%li)\n", buf, ret);
	}

	if (wbuf) {
		ret = iio_device_debug_attr_write(dev, attr, wbuf);
		if (ret > 0) {
			printf("wrote %li bytes to %s\n", ret, attr);
		} else {
			iio_strerror(-ret, buf, sizeof(buf));
			printf("ERROR: %s (%li) while writing '%s' with '%s'\n", buf, ret, attr, wbuf);
		}
		dump_debug_attributes(dev, attr, NULL);
	}
}

static void dump_channel_attributes(const struct iio_device *dev,
		struct iio_channel *ch, const char *attr, const char *wbuf)
{
	ssize_t ret;
	char buf[1024];
	const char *type_name;

	if (iio_channel_is_output(ch))
		type_name = "output";
	else
		type_name = "input";

	ret = iio_channel_attr_read(ch, attr, buf, sizeof(buf));
	printf("dev '%s', channel '%s' (%s), ",
			iio_device_get_name(dev),
			iio_channel_get_id(ch),
			type_name);
	if (iio_channel_get_name(ch))
		printf("id '%s', ", iio_channel_get_name(ch));
	printf("attr '%s', ", attr);

	if (ret > 0) {
		printf("value '%s'\n", buf);
	} else {
		iio_strerror(-ret, buf, sizeof(buf));
		printf("ERROR: %s (%li)\n", buf, ret);
	}

	if (wbuf) {
		ret = iio_channel_attr_write(ch, attr, wbuf);
		if (ret > 0) {
			printf("wrote %li bytes to %s\n", ret, attr);
		} else {
			iio_strerror(-ret, buf, sizeof(buf));
			printf("error %s (%li) while writing '%s' with '%s'\n",
					buf, ret, attr, wbuf);
		}
		dump_channel_attributes(dev, ch, attr, NULL);
	}
}

int main(int argc, char **argv)
{
	struct iio_context *ctx;
	int c, option_index = 0, arg_index = 0, debug_index = 0,
	    uri_index = 0, iio_attr_index = 0, device_index = 0, d_attr_index = 0,
	    channel_index = 0, channel_attr_index = 0;
	enum backend backend = LOCAL;
	bool detect_context = false, quiet = true, exact = false,
	     input_only = false, output_only = false, scan_only = false;
	unsigned int i;
	char *wbuf = NULL;

	while ((c = getopt_long(argc, argv, "+hae:u:d:D:i:c:b:rw:vIOSx",
					options, &option_index)) != -1) {
		switch (c) {
		case 'a':
			arg_index += 1;
			detect_context = true;
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'u':
			backend = AUTO;
			arg_index += 2;
			uri_index = arg_index;
			break;
		case 'i':
			arg_index +=2;
			iio_attr_index = arg_index;
			break;
		case 'd':
			arg_index += 2;
			device_index = arg_index;
			if (!channel_index)
				channel_index = -1;
			if (!channel_attr_index)
				channel_attr_index = -1;
			break;
		case 'D':
			arg_index +=2;
			debug_index = arg_index;
			if (!device_index)
				device_index = -1;
			break;
		case 'e':
			arg_index +=2;
			d_attr_index = arg_index;
			if (!device_index)
				device_index = -1;
			break;
		case 'c':
			arg_index +=2;
			channel_index = arg_index;
			if (!device_index)
				device_index = -1;
			break;
		case 'b':
			arg_index +=2;
			channel_attr_index = arg_index;
			if (!device_index)
				device_index = -1;
			if (!channel_index)
				channel_index = -1;
			break;
		case 'v':
			arg_index += 1;
			quiet = false;
			break;
		case 'I':
			arg_index += 1;
			input_only = true;
			break;
		case 'O':
			arg_index += 1;
			output_only = true;
			break;
		case 'S':
			arg_index += 1;
			scan_only = true;
			break;
		case 'x':
			arg_index += 1;
			exact = true;
			break;
		case '?':
			printf("Unknown argument '%c'\n", c);
			return EXIT_FAILURE;
		}
	}

	if (arg_index >= argc) {
		fprintf(stderr, "Incorrect number of arguments.\n\n");
		usage();
		return EXIT_FAILURE;
	}
	if ((arg_index + 2) == argc) {
		arg_index += 1;
		wbuf = argv[arg_index];
	}
	if ((arg_index + 1) != argc) {
		fprintf(stderr, "Incorrect number of arguments.\n\n");
		usage();
		return EXIT_FAILURE;
	}

	if (debug_index && device_index && channel_index == -1)
		channel_index = 0;

	if (quiet && device_index && !channel_index && !debug_index && !scan_only) {
		quiet = false;
		channel_index = -1;
	}

	if (quiet && !device_index && !channel_index && !debug_index && !scan_only) {
		quiet = false;
		device_index = -1;
	}

	if (scan_only && !device_index)
		device_index = -1;

	if (scan_only && !channel_index)
		channel_index = -1;

	if (detect_context)
		ctx = autodetect_context();
	else if (backend == AUTO)
		ctx = iio_create_context_from_uri(argv[uri_index]);
	else
		ctx = iio_create_default_context();

	if (!ctx) {
		if (!detect_context) {
			char buf[1024];

			iio_strerror(errno, buf, sizeof(buf));
			fprintf(stderr, "Unable to create IIO context: %s\n",
					buf);
		}

		return EXIT_FAILURE;
	}

	if (iio_attr_index) {
		printf("iio_context: %i %s\n", iio_attr_index, argv[iio_attr_index]);
		unsigned int nb_ctx_attrs = iio_context_get_attrs_count(ctx);
		if (nb_ctx_attrs > 0 && !quiet)
			printf("Found IIO context with %u attributes:\n", nb_ctx_attrs);

		for (i = 0; i < nb_ctx_attrs; i++) {
			const char *key, *value;

			iio_context_get_attr(ctx, i, &key, &value);
			if (str_match(exact, key, argv[iio_attr_index])) {
				if (!quiet)
					printf("\t");
				printf("%s: %s\n", key, value);
			}
		}
	}

	if (device_index) {
		unsigned int nb_devices = iio_context_get_devices_count(ctx);
		if (!quiet)
			printf("IIO context has %u devices:\n", nb_devices);

		for (i = 0; i < nb_devices; i++) {
			const struct iio_device *dev = iio_context_get_device(ctx, i);
			const char *name = iio_device_get_name(dev);

			if (device_index > 0 &&
					!str_match(exact, name, argv[device_index]))
				continue;

			if (!quiet) {
				printf("\t%s:", iio_device_get_id(dev));
				if (name)
					printf(" %s", name);
				printf("\n");
			}

			if (channel_index) {
				unsigned int nb_channels =
					iio_device_get_channels_count(dev);
				if (!quiet)
					printf("\t\t%u channels found:\n", nb_channels);
	
				unsigned int j;
				for (j = 0; j < nb_channels; j++) {
					struct iio_channel *ch =
						iio_device_get_channel(dev, j);
					const char *type_name;

					if (iio_channel_is_output(ch) && input_only)
						continue;
					if (!iio_channel_is_output(ch) && output_only)
						continue;

					if (iio_channel_is_output(ch))
						type_name = "output";
					else
						type_name = "input";

					name = iio_channel_get_name(ch);

					if (channel_index > 0 &&
							!str_match(exact,
								iio_channel_get_id(ch),
							       	argv[channel_index]) &&
						(!name || (name &&
							   !str_match(exact,
								   name,
								   argv[channel_index]))))
						continue;

					if ((!scan_only && channel_attr_index <= 0) ||
					    ( scan_only && iio_channel_is_scan_element(ch))) {
						printf("dev '%s', channel '%s'",
							iio_device_get_name(dev),
							iio_channel_get_id(ch));

						if (name)
							printf(", id '%s'", name);

						printf(" (%s", type_name);
	
						if (iio_channel_is_scan_element(ch)) {
							const struct iio_data_format *format =
								iio_channel_get_data_format(ch);
							char sign = format->is_signed ? 's' : 'u';
							char repeat[8] = "";
		
							if (format->is_fully_defined)
								sign += 'A' - 'a';
		
							if (format->repeat > 1)
								snprintf(repeat, sizeof(repeat), "X%u",
									format->repeat);
							printf(", index: %lu, format: %ce:%c%u/%u%s>>%u)\n",
									iio_channel_get_index(ch),
									format->is_be ? 'b' : 'l',
									sign, format->bits,
									format->length, repeat,
										format->shift);
						} else {
							printf(")\n");
						}
					}

					unsigned int nb_attrs = iio_channel_get_attrs_count(ch);
					if (!nb_attrs)
						continue;
	
					if (!quiet && channel_index > 0)
						printf("\t\t\t%u channel-specific attributes found:\n",
								nb_attrs);

					unsigned int k;
					for (k = 0; k < nb_attrs; k++) {
						const char *attr =
							iio_channel_get_attr(ch, k);

						if (channel_attr_index > 0 && 
							!str_match(exact, attr, argv[channel_attr_index]))
							continue;
						if (channel_index > 0)
							dump_channel_attributes(dev, ch, attr, wbuf);
					}
				}
			}

			unsigned int nb_attrs = iio_device_get_attrs_count(dev);
			if (nb_attrs) {
				if (!quiet && device_index > 0)
					printf("\t\t%u %s attributes found:\n",
							nb_attrs, iio_device_get_name(dev));
				unsigned int j;
				for (j = 0; j < nb_attrs; j++) {
					const char *attr = iio_device_get_attr(dev, j);
					if (!str_match(exact, attr, argv[d_attr_index]))
						continue;

					dump_device_attributes(dev, attr, wbuf);
				}
			}
	
			nb_attrs = iio_device_get_debug_attrs_count(dev);
			if (nb_attrs) {
				unsigned int j;

				if (!quiet && device_index > 0)
					printf("\t\t%u debug attributes found:\n", nb_attrs);

				for (j = 0; j < nb_attrs; j++) {
					const char *attr = iio_device_get_debug_attr(dev, j);

					if (debug_index > 0 && str_match(exact, attr, argv[debug_index]))
						dump_debug_attributes(dev, attr, wbuf);
				}
			}
	
		}
	}

	iio_context_destroy(ctx);
	return EXIT_SUCCESS;
}
