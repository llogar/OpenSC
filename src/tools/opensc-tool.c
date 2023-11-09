/*
 * opensc-tool.c: Tool for accessing smart cards with libopensc
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/asn1.h"
#include "util.h"

/* type for associations of IDs to names */
typedef struct _id2str {
	unsigned int id;
	const char *str;
} id2str_t;

static const char *app_name = "opensc-tool";

static int	opt_wait = 0;
static char **	opt_apdus;
static char	*opt_reader;
static int	opt_apdu_count = 0;
static int	verbose = 0;

enum {
	OPT_SERIAL = 0x100,
	OPT_LIST_ALG,
	OPT_VERSION,
	OPT_RESET
};

static const struct option options[] = {
	{ "version",		0, NULL,	OPT_VERSION },
	{ "info",		0, NULL,		'i' },
	{ "atr",		0, NULL,		'a' },
	{ "serial",		0, NULL,	OPT_SERIAL  },
	{ "name",		0, NULL,		'n' },
	{ "get-conf-entry",	1, NULL,		'G' },
	{ "set-conf-entry",	1, NULL,		'S' },
	{ "list-readers",	0, NULL,		'l' },
	{ "list-drivers",	0, NULL,		'D' },
	{ "list-files",		0, NULL,		'f' },
	{ "send-apdu",		1, NULL,		's' },
	{ "reader",		1, NULL,		'r' },
	{ "reset",		2, NULL,	OPT_RESET   },
	{ "card-driver",	1, NULL,		'c' },
	{ "list-algorithms",    0, NULL,	OPT_LIST_ALG },
	{ "wait",		0, NULL,		'w' },
	{ "verbose",		0, NULL,		'v' },
	{ "read",		1, NULL,		'R' },
	{ "write",		1, NULL,		'W' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Prints OpenSC package revision",
	"Prints information about OpenSC",
	"Prints the ATR bytes of the card",
	"Prints the card serial number",
	"Identify the card and print its name",
	"Get configuration, e.g. section:name:key",
	"Set configuration, e.g. section:name:key:val",
	"Lists readers",
	"Lists all installed card drivers",
	"Recursively lists files stored on card",
	"Sends an APDU (may need '-c default')",
	"Uses reader number <arg> [0]",
	"Does card reset of type <cold|warm> [cold]",
	"Forces a card driver (use '?' for list)",
	"Lists algorithms supported by card",
	"Wait for a card to be inserted",
	"Verbose operation, may be used several times",
	"Read whole card contents",
	"Write whole card contents",
};

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;

static int opensc_info(void)
{
	printf (
		"%s %s ",
		PACKAGE_NAME,
		PACKAGE_VERSION
	);

#if defined(__VERSION__)
	printf (
		"[%s %s]\n",
#if defined(__GNUC__)
		"gcc ",
#else
		"unknown ",
#endif
		__VERSION__
	);
#elif defined(__SUNPRO_C)
	printf (
		"[Sun C %x.%x]\n",
#if __SUNPRO_C > 0x590
		(__SUNPRO_C >> 12), (__SUNPRO_C >> 4) & 0xFF
#else
		(__SUNPRO_C >>  8), (__SUNPRO_C >> 4) & 0xF
#endif
	);
#elif defined(_MSC_VER)
	printf ("[Microsoft %d]\n", _MSC_VER);
#else
	printf ("[Unknown compiler, please report]");
#endif
	printf ("Enabled features:%s\n", OPENSC_FEATURES);
	return 0;
}

static int opensc_get_conf_entry(const char *config)
{
	scconf_block *conf_block = NULL, **blocks;
	char *buffer = NULL;
	char *section = NULL;
	char *name = NULL;
	char *key = NULL;
	int r = 0;

	if (ctx->conf == NULL) {
		r = ENOENT;
		goto cleanup;
	}

	if ((buffer = strdup(config)) == NULL) {
		r = ENOMEM;
		goto cleanup;
	}

	section = buffer;
	name = strchr(section+1, ':');
	key = name == NULL ? NULL : strchr(name+1, ':');
	if (key == NULL) {
		r = EINVAL;
		goto cleanup;
	}
	*name = '\0';
	name++;
	*key = '\0';
	key++;

	blocks = scconf_find_blocks(ctx->conf, NULL, section, name);
	if (blocks && blocks[0])
		conf_block = blocks[0];
	free(blocks);
	if (conf_block != NULL) {
		const char *value = scconf_get_str(conf_block, key, NULL);

		if (value != NULL) {
			printf ("%s\n", value);
		}
	}

	r = 0;

cleanup:

	if (buffer != NULL)
		free(buffer);

	return r;
}

static int opensc_set_conf_entry(const char *config)
{
	scconf_block *conf_block = NULL, **blocks;
	char *buffer = NULL;
	char *section = NULL;
	char *name = NULL;
	char *key = NULL;
	char *value = NULL;
	int r = 0;

	if (ctx->conf == NULL) {
		r = ENOENT;
		goto cleanup;
	}

	if ((buffer = strdup(config)) == NULL) {
		r = ENOMEM;
		goto cleanup;
	}

	section = buffer;
	name = strchr(section+1, ':');
	key = name == NULL ? NULL : strchr(name+1, ':');
	value = key == NULL ? NULL : strchr(key+1, ':');
	if (value == NULL) {
		r = EINVAL;
		goto cleanup;
	}
	*name = '\0';
	name++;
	*key = '\0';
	key++;
	*value = '\0';
	value++;

	blocks = scconf_find_blocks(ctx->conf, NULL, section, name);
	if (blocks && blocks[0])
		conf_block = blocks[0];
	free(blocks);
	if (conf_block != NULL) {
		scconf_item *item;

		for (item = conf_block->items; item != NULL; item = item->next) {
			scconf_list *list;

			if ((item->type != SCCONF_ITEM_TYPE_VALUE)
			   || (strcmp(item->key, key) != 0))
				continue;
			list = item->value.list;
			scconf_list_destroy(list);
			list = NULL;
			scconf_list_add(&list, value);
			item->value.list = list;
			break;
		}
		if (item == NULL)
			scconf_put_str(conf_block, key, value);
	}

	/* Write */
	if ((r = scconf_write(ctx->conf, ctx->conf->filename)) != 0) {
		fprintf(stderr, "scconf_write(): %s\n", strerror(r));
		goto cleanup;
	}

	r = 0;

cleanup:

	if (buffer != NULL)
		free(buffer);

	return r;
}

static int list_readers(void)
{
	unsigned int i, rcount = sc_ctx_get_reader_count(ctx);

	if (rcount == 0) {
		printf("No smart card readers found.\n");
		return 0;
	}
	printf("# Detected readers (%s)\n", ctx->reader_driver->short_name);
	printf("Nr.  Card  Features  Name\n");
	for (i = 0; i < rcount; i++) {
		sc_reader_t *reader = sc_ctx_get_reader(ctx, i);
		int state = sc_detect_card_presence(reader);
		printf("%-5d%-6s%-10s%s\n", i, state & SC_READER_CARD_PRESENT ? "Yes":"No",
		      reader->capabilities & SC_READER_CAP_PIN_PAD ? "PIN pad":"",
		      reader->name);
		if (state & SC_READER_CARD_PRESENT && verbose) {
			struct sc_card *c;
			int r;
			char tmp[SC_MAX_ATR_SIZE*3];
			sc_bin_to_hex(reader->atr.value, reader->atr.len, tmp, sizeof(tmp) - 1, ':');

			if (state & SC_READER_CARD_EXCLUSIVE)
				printf("     %s [EXCLUSIVE]\n", tmp);
			else {
				if ((r = sc_connect_card(reader, &c)) != SC_SUCCESS) {
					fprintf(stderr, "     failed: %s\n", sc_strerror(r));
				} else {
					printf("     %s %s %s\n", tmp, c->name ? c->name : "", state & SC_READER_CARD_INUSE ? "[IN USE]" : "");
					sc_disconnect_card(c);
				}
			}
		}
	}
	return 0;
}

static int print_file(sc_card_t *in_card, const sc_file_t *file,
	const sc_path_t *path, int depth)
{
	int r;
	const char *tmps;

	for (r = 0; r < depth; r++)
		printf("  ");
	printf("%s ", sc_print_path(path));
	if (file->namelen) {
		printf("[");
		util_print_binary(stdout, file->name, file->namelen);
		printf("] ");
	}
	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		tmps = "wEF";
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		tmps = "iEF";
		break;
	case SC_FILE_TYPE_DF:
		tmps = "DF";
		break;
	default:
		tmps = "unknown";
		break;
	}
	printf("type: %s, ", tmps);
	if (file->type != SC_FILE_TYPE_DF) {
		const id2str_t ef_type_name[] = {
			{ SC_FILE_EF_TRANSPARENT,         "transparent"           },
			{ SC_FILE_EF_LINEAR_FIXED,        "linear-fixed"          },
			{ SC_FILE_EF_LINEAR_FIXED_TLV,    "linear-fixed (TLV)"    },
			{ SC_FILE_EF_LINEAR_VARIABLE,     "linear-variable"       },
			{ SC_FILE_EF_LINEAR_VARIABLE_TLV, "linear-variable (TLV)" },
			{ SC_FILE_EF_CYCLIC,              "cyclic"                },
			{ SC_FILE_EF_CYCLIC_TLV,          "cyclic (TLV)"          },
			{ 0, NULL }
		};
		const char *ef_type = "unknown";

		for (r = 0; ef_type_name[r].str != NULL; r++)
			if (file->ef_structure == ef_type_name[r].id)
				ef_type = ef_type_name[r].str;

		printf("ef structure: %s, ", ef_type);
	}
	printf("size: %lu\n", (unsigned long) file->size);
	for (r = 0; r < depth; r++)
		printf("  ");
	if (file->type == SC_FILE_TYPE_DF) {
		const id2str_t ac_ops_df[] = {
			{ SC_AC_OP_SELECT,       "select" },
			{ SC_AC_OP_LOCK,         "lock"   },
			{ SC_AC_OP_DELETE,       "delete" },
			{ SC_AC_OP_CREATE,       "create" },
			{ SC_AC_OP_REHABILITATE, "rehab"  },
			{ SC_AC_OP_INVALIDATE,   "inval"  },
			{ SC_AC_OP_LIST_FILES,   "list"   },
			{ 0, NULL }
		};

		for (r = 0; ac_ops_df[r].str != NULL; r++)
			printf("%s[%s] ", ac_ops_df[r].str,
					 util_acl_to_str(sc_file_get_acl_entry(file, ac_ops_df[r].id)));
	}
	else {
		const id2str_t ac_ops_ef[] = {
			{ SC_AC_OP_READ,         "read"   },
			{ SC_AC_OP_UPDATE,       "update" },
			{ SC_AC_OP_ERASE,        "erase"  },
			{ SC_AC_OP_WRITE,        "write"  },
			{ SC_AC_OP_REHABILITATE, "rehab"  },
			{ SC_AC_OP_INVALIDATE,   "inval"  },
			{ 0, NULL }
		};

		for (r = 0; ac_ops_ef[r].str != NULL; r++)
			printf("%s[%s] ", ac_ops_ef[r].str,
					util_acl_to_str(sc_file_get_acl_entry(file, ac_ops_ef[r].id)));
	}

	if (file->sec_attr_len) {
		printf("sec: ");
		/* Octets are as follows:
		*   DF: select, lock, delete, create, rehab, inval
		*   EF: read, update, write, erase, rehab, inval
		* 4 MSB's of the octet mean:
		*  0 = ALW, 1 = PIN1, 2 = PIN2, 4 = SYS,
		* 15 = NEV */
		util_hex_dump(stdout, file->sec_attr, file->sec_attr_len, ":");
	}
	if (file->prop_attr_len) {
		printf("\n");
		for (r = 0; r < depth; r++)
			printf("  ");
		printf("prop: ");
		util_hex_dump(stdout, file->prop_attr, file->prop_attr_len, ":");
	}
	printf("\n\n");

	if (file->type == SC_FILE_TYPE_DF)
		return 0;

	if (file->ef_structure == SC_FILE_EF_TRANSPARENT) {
		unsigned char *buf;

		if (!(buf = malloc(file->size))) {
			fprintf(stderr, "out of memory");
			return 1;
		}

		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_read_binary(in_card, 0, buf, file->size, 0);
		sc_unlock(card);
		if (r > 0)
			util_hex_dump_asc(stdout, buf, r, 0);
		free(buf);
	} else {
		unsigned char buf[256];
		size_t rec_nr;

		for (rec_nr = 1; rec_nr <= file->record_count; rec_nr++) {
			printf("Record %"SC_FORMAT_LEN_SIZE_T"u\n", rec_nr);
			r = sc_lock(card);
			if (r == SC_SUCCESS)
				r = sc_read_record(in_card, rec_nr, 0, buf, sizeof(buf), SC_RECORD_BY_REC_NR);
			sc_unlock(card);
			if (r > 0)
				util_hex_dump_asc(stdout, buf, r, 0);
		}
	}
	return 0;
}

static int enum_dir(sc_path_t path, int depth)
{
	sc_file_t *file;
	int r, file_type;
	u8 files[SC_MAX_EXT_APDU_BUFFER_SIZE];

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_select_file(card, &path, &file);
	sc_unlock(card);
	if (r) {
		fprintf(stderr, "SELECT FILE failed: %s\n", sc_strerror(r));
		return 1;
	}
	print_file(card, file, &path, depth);
	file_type = file->type;
	sc_file_free(file);
	if (file_type == SC_FILE_TYPE_DF) {
		int i;

		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_list_files(card, files, sizeof(files));
		sc_unlock(card);
		if (r < 0) {
			fprintf(stderr, "sc_list_files() failed: %s\n", sc_strerror(r));
			return 1;
		}
		if (r == 0) {
			printf("Empty directory\n");
		} else {
			for (i = 0; i < r/2; i++) {
				sc_path_t tmppath;

				memset(&tmppath, 0, sizeof(tmppath));
				memcpy(&tmppath, &path, sizeof(path));
				memcpy(tmppath.value + tmppath.len, files + 2*i, 2);
				tmppath.len += 2;
				enum_dir(tmppath, depth + 1);
			}
		}
	}
	return 0;
}

static int list_files(void)
{
	sc_path_t path;
	int r;

	sc_format_path("3F00", &path);
	r = enum_dir(path, 0);
	return r;
}

static int send_apdu(void)
{
	sc_apdu_t apdu;
	u8 buf[SC_MAX_EXT_APDU_BUFFER_SIZE],
	  rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	size_t len0, r;
	int c;

	for (c = 0; c < opt_apdu_count; c++) {
		len0 = sizeof(buf);
		sc_hex_to_bin(opt_apdus[c], buf, &len0);

		r = sc_bytes2apdu(card->ctx, buf, len0, &apdu);
		if (r) {
			fprintf(stderr, "Invalid APDU: %s\n", sc_strerror(r));
			return 2;
		}

		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);

		printf("Sending: ");
		for (r = 0; r < len0; r++)
			printf("%02X ", buf[r]);
		printf("\n");
		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_transmit_apdu(card, &apdu);
		sc_unlock(card);
		if (r) {
			fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
			return 1;
		}
		printf("Received (SW1=0x%02X, SW2=0x%02X)%s\n", apdu.sw1, apdu.sw2,
		      apdu.resplen ? ":" : "");
		if (apdu.resplen)
			util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
	}
	return 0;
}

static void print_serial(sc_card_t *in_card)
{
	int r;
	sc_serial_number_t serial;

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_card_ctl(in_card, SC_CARDCTL_GET_SERIALNR, &serial);
	sc_unlock(card);
	if (r)
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_GET_SERIALNR, *) failed\n");
	else
		util_hex_dump_asc(stdout, serial.value, serial.len, -1);
}

static int list_algorithms(void)
{
	int i;
	const char *aname = "unknown";

	const id2str_t alg_type_names[] = {
		{ SC_ALGORITHM_RSA,       "rsa"       },
		{ SC_ALGORITHM_EC,        "ec"        },
		{ SC_ALGORITHM_EDDSA,     "eddsa"     },
		{ SC_ALGORITHM_GOSTR3410, "gostr3410" },
		{ SC_ALGORITHM_DES,       "des"       },
		{ SC_ALGORITHM_3DES,      "3des"      },
		{ SC_ALGORITHM_GOST,      "gost"      },
		{ SC_ALGORITHM_MD5,       "md5"       },
		{ SC_ALGORITHM_SHA1,      "sha1"      },
		{ SC_ALGORITHM_GOSTR3411, "gostr3411" },
		{ SC_ALGORITHM_PBKDF2,    "pbkdf2"    },
		{ SC_ALGORITHM_PBES2,     "pbes2"     },
		{ SC_ALGORITHM_AES,       "aes"       },
		{ 0, NULL }
	};
	const id2str_t alg_flag_names[] = {
		{ SC_ALGORITHM_ONBOARD_KEY_GEN, "onboard key generation" },
		{ SC_ALGORITHM_NEED_USAGE,      "needs usage"            },
		{ 0, NULL }
	};
	const id2str_t rsa_flag_names[] = {
		{ SC_ALGORITHM_RSA_PAD_PKCS1,      "pkcs1"     },
		{ SC_ALGORITHM_RSA_PAD_ANSI,       "ansi"      },
		{ SC_ALGORITHM_RSA_PAD_PSS,        "pss"       },
		{ SC_ALGORITHM_RSA_PAD_OAEP,       "oaep"      },
		{ SC_ALGORITHM_RSA_PAD_ISO9796,    "iso9796"   },
		{ SC_ALGORITHM_RSA_HASH_SHA1,      "sha1"      },
		{ SC_ALGORITHM_RSA_HASH_MD5,       "MD5"       },
		{ SC_ALGORITHM_RSA_HASH_MD5_SHA1,  "md5-sha1"  },
		{ SC_ALGORITHM_RSA_HASH_RIPEMD160, "ripemd160" },
		{ SC_ALGORITHM_RSA_HASH_SHA256,    "sha256"    },
		{ SC_ALGORITHM_RSA_HASH_SHA384,    "sha384"    },
		{ SC_ALGORITHM_RSA_HASH_SHA512,    "sha512"    },
		{ SC_ALGORITHM_RSA_HASH_SHA224,    "sha224"    },
		{ 0, NULL }
	};

	if (verbose)
		printf("Card supports %d algorithm(s)\n\n",card->algorithm_count);

	for (i=0; i < card->algorithm_count; i++) {
		int j;

		/* find algorithm name */
		for (j = 0; alg_type_names[j].str != NULL; j++) {
			if (card->algorithms[i].algorithm == alg_type_names[j].id) {
				aname = alg_type_names[j].str;
				break;
			}
		}

		printf("Algorithm: %s\n", aname);
		printf("Key length: %d\n", card->algorithms[i].key_length);
		printf("Flags:");

		/* print general flags */
		for (j = 0; alg_flag_names[j].str != NULL; j++)
			if (card->algorithms[i].flags & alg_flag_names[j].id)
				printf(" %s", alg_flag_names[j].str);

		/* print RSA specific flags */
		if ( card->algorithms[i].algorithm == SC_ALGORITHM_RSA) {
			int padding = card->algorithms[i].flags
					& SC_ALGORITHM_RSA_PADS;
			int hashes =  card->algorithms[i].flags
					& SC_ALGORITHM_RSA_HASHES;

			/* print RSA padding flags */
			printf(" padding (");
			for (j = 0; rsa_flag_names[j].str != NULL; j++)
				if (padding & rsa_flag_names[j].id)
					printf(" %s", rsa_flag_names[j].str);
			if (padding == SC_ALGORITHM_RSA_PAD_NONE)
				printf(" none");
			printf(" ) ");
			/* print RSA hash flags */
			printf("hashes (");
			for (j = 0; rsa_flag_names[j].str != NULL; j++)
				if (hashes & rsa_flag_names[j].id)
					printf(" %s", rsa_flag_names[j].str);
			if (hashes == SC_ALGORITHM_RSA_HASH_NONE)
				printf(" none");
			printf(" )");
		}
		printf("\n");
		if (card->algorithms[i].algorithm == SC_ALGORITHM_RSA
			&& card->algorithms[i].u._rsa.exponent) {
			printf("RSA public exponent: %lu\n", (unsigned long)
				card->algorithms[i].u._rsa.exponent);
		}

		if (i < card->algorithm_count)
			printf("\n");
	}
	return 0;
}

static int card_reset(const char *reset_type)
{
	int cold_reset;
	int r;

	if (reset_type && strcmp(reset_type, "cold") &&
	    strcmp(reset_type, "warm")) {
		fprintf(stderr, "Invalid reset type: %s\n", reset_type);
		return 2;
	}

	cold_reset = !reset_type || strcmp(reset_type, "cold") == 0;

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_reset(card, cold_reset);
	sc_unlock(card);
	if (r) {
		fprintf(stderr, "sc_reset(%s) failed: %d\n",
			cold_reset ? "cold" : "warm", r);
		return 1;
	}

	return 0;
}

static char *desc_nameImpExp(int type, const char *file)
{
	static char tmp[256];
	if (strcmp(file, "3f005015") == 0) {
		strcpy(tmp, "PKCS15-AppDF");
	} else if (strcmp(file, "3f0050154401") == 0) {
		strcpy(tmp, "PKCS15-AODF");
	} else if (strcmp(file, "3f0050155031") == 0) {
		strcpy(tmp, "PKCS15-ODF");
	} else if (strcmp(file, "3f0050155032") == 0) {
		strcpy(tmp, "PKCS15-TokenInfo");
	} else if (strcmp(file, "3f0050154946") == 0) {
		strcpy(tmp, "profile-name");
	} else if (strcmp(file, "3f0050154402") == 0) {
		strcpy(tmp, "PKCS15-PrKDF");
	} else if (strcmp(file, "3f0050154404") == 0) {
		strcpy(tmp, "PKCS15-CDF");
	} else if (strcmp(file, "3f0050154403") == 0) {
		strcpy(tmp, "PKCS15-PuKDF");
	} else if (strcmp(file, "3f0050154405") == 0) {
		strcpy(tmp, "PKCS15-DODF");
	} else if (strcmp(file, "3f002f00") == 0) {
		strcpy(tmp, "DIR");
	} else if (strncmp(file, "3f00501532xx", 10) == 0) {
		sprintf(tmp, "data #%s", file[10] != '0' ? &file[10] : &file[11]);
	} else if (strncmp(file, "3f00501533xx", 10) == 0) {
		sprintf(tmp, "public-key #%s", file[10] != '0' ? &file[10] : &file[11]);
	} else if (strncmp(file, "3f00501534xx", 10) == 0) {
		sprintf(tmp, "certificate #%s", file[10] != '0' ? &file[10] : &file[11]);
	} else if (strncmp(file, "3f00501535xx", 10) == 0) {
		sprintf(tmp, "privdata #%s", file[10] != '0' ? &file[10] : &file[11]);
	} else {
		strcpy(tmp, file);
	}
	return tmp;
}

static int print_fileImpExp(FILE *fh, sc_card_t *in_card, const sc_file_t *file,
	const sc_path_t *path, int depth)
{
	int r;

	if (file->id == 0x3F00)
		return 0;

	fprintf(stdout, "Reading %s\n", desc_nameImpExp(file->type, sc_print_path(path)));

	fprintf(fh, "; FILE %s FCI=6F158102%02X%02X8201%02X8302%02X%02X8608%02X%02X%02X%02X%02X%02X%02X%02X\n",
		sc_print_path(path),
		(int)file->size/0x100, (int)file->size%0x100,						/* size */
		file->type == SC_FILE_TYPE_DF ? 0x38 : 0x01,						/* type */
		path->value[path->len - 2], path->value[path->len - 1],
		file->sec_attr[0], file->sec_attr[1], file->sec_attr[2], file->sec_attr[3], file->sec_attr[4], file->sec_attr[5], file->sec_attr[6], file->sec_attr[7]);

	if (file->type == SC_FILE_TYPE_DF)
		return 0;

	if (file->ef_structure == SC_FILE_EF_TRANSPARENT) {
		unsigned char *buf;

		if (!(buf = malloc(file->size))) {
			fprintf(stderr, "out of memory");
			return -1;
		}

		r = sc_read_binary(in_card, 0, buf, file->size, 0);
		if (r > 0)
			util_hex_dump_asc(fh, buf, r, -1);
		free(buf);
	} else {
		fprintf(stderr, "not a transparent file");
		return -2;
	}
	return 0;
}

static int enum_dirImpExp(FILE *fh, sc_path_t path, int depth)
{
	sc_file_t *file;
	int r, file_type;
	u8 files[SC_MAX_APDU_BUFFER_SIZE];

	r = sc_select_file(card, &path, &file);
	if (r) {
		fprintf(stderr, "SELECT FILE failed: %s\n", sc_strerror(r));
		return -1;
	}
	print_fileImpExp(fh, card, file, &path, depth);
	file_type = file->type;
	sc_file_free(file);
	if (file_type == SC_FILE_TYPE_DF) {
		int i;

		r = sc_list_files(card, files, sizeof(files));
		if (r < 0) {
			fprintf(stderr, "sc_list_files() failed: %s\n", sc_strerror(r));
			return -2;
		}
		if (r > 0) {
			for (i = 0; i < r/2; i++) {
				sc_path_t tmppath;

				memset(&tmppath, 0, sizeof(tmppath));
				memcpy(&tmppath, &path, sizeof(path));
				memcpy(tmppath.value + tmppath.len, files + 2*i, 2);
				tmppath.len += 2;
				enum_dirImpExp(fh, tmppath, depth + 1);
			}
		}
	}
	return 0;
}

static int send_apduImpExp(u8 *buf, size_t len, u8 *rbuf, size_t rlen)
{
	sc_apdu_t apdu;
	size_t r;

	r = sc_bytes2apdu(card->ctx, buf, len, &apdu);
	if (r) {
		fprintf(stderr, "invalid APDU: %s\n", sc_strerror(r));
		return -1;
	}

	apdu.resp = rbuf;
	apdu.resplen = rlen;

	r = sc_transmit_apdu(card, &apdu);

	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
		return -2;
	}
	if ((apdu.sw1 != 0x90) || (apdu.sw2 != 0x00)) {
		fprintf(stderr, "received (SW1=0x%02X, SW2=0x%02X)%s\n", apdu.sw1, apdu.sw2,
		      apdu.resplen ? ":" : "");
	}

	return apdu.resplen;
}

static u8 *read_blobImpExp(FILE *fh, const char *first_line, size_t len)
{
	char line[256];
	u8 *buf;
	unsigned h;

	if (len > 32768)
		return NULL;

	buf = (u8*)malloc(len);

	for (size_t pos = 0; pos < len; ) {
		if (first_line) {
			strcpy(line, first_line);
			first_line = NULL;
		} else {
			if (fgets(line, 250, fh) == NULL) {
				free(buf);
				return NULL;
			}
		}
		for (int n = 0; n < 16; n++) {
			if (sscanf(&line[3*n], "%02X", &h) != 1) {
				free(buf);
				return NULL;
			}
			buf[pos++] = h;
			if (pos == len)
				break;
		}
	}

	return buf;
}

static int mkdirImpExp(char *name, u8 *fci, size_t fci_len)
{
	sc_path_t path;
	const u8 *tag_val, *tv;
	u8 buf[32];
	size_t tag_len, tl, buf_len;
	sc_file_t *file;
	int r;

	buf_len = sizeof(buf);
	sc_hex_to_bin(name, buf, &buf_len);
	if (buf_len < 2) {
		fprintf(stderr, "invalud path\n");
		return -1;
	}
	if (sc_path_set(&path, SC_PATH_TYPE_FILE_ID, buf, buf_len - 2, 0, 0) != SC_SUCCESS) {
		fprintf(stderr, "unable to set path\n");
		return -2;
	}

	/* Select parent file */
	r = sc_select_file(card, &path, &file);
	if (r) {
		fprintf(stderr, "SELECT FILE failed: %s\n", sc_strerror(r));
		return -3;
	}

	/* Parse outer tag 0x6F */
	tag_val =  sc_asn1_find_tag(card->ctx, fci, fci_len, (unsigned int) 0x6F, &tag_len);
	if (tag_val == NULL) {
		fprintf(stderr, "invalid or missing fci\n");
		return -4;
	}

	file = sc_file_new();
	file->type = SC_FILE_TYPE_DF;
	file->status = SC_FILE_STATUS_ACTIVATED;

	/* Parse tag 0x83 - file id */
	tv =  sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x83, &tl);
	if ((tv == NULL) || (tl != 2)) {
		fprintf(stderr, "invalid or missing file id\n");
		return -5;
	}
	file->id = (tv[0] << 8) | tv[1];

	/* Parse tag 0x81 - file size */
	tv =  sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x81, &tl);
	if ((tv == NULL) || (tl != 2)) {
		fprintf(stderr, "invalid or missing file size\n");
		return -6;
	}
	file->size = (tv[0] << 8) + tv[1];

	/* Parse tag 0x86 - security attributes */
	tv =  sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x86, &tl);
	if ((tv == NULL) || (tl != 8)) {
		fprintf(stderr, "invalid or missing security attributes\n");
		return -7;
	}
	file->sec_attr = malloc(tl);
	file->sec_attr_len = tl;
	memcpy(file->sec_attr, tv, tl);

	r = sc_create_file(card, file);
	if (r) {
		fprintf(stderr, "CREATE FILE failed\n");
		return -8;
	}

	sc_file_free(file);
	return r;
}

static int mkfileImpExp(char *name, u8 *fci, size_t fci_len, u8 *data, size_t len)
{
	sc_path_t path;
	const u8 *tag_val, *tv;
	u8 buf[32];
	size_t tag_len, tl, buf_len;
	sc_file_t *file;
	int r;

	buf_len = sizeof(buf);
	sc_hex_to_bin(name, buf, &buf_len);
	if (buf_len < 4) {
		fprintf(stderr, "invalud path\n");
		return -1;
	}
	if (buf_len == 4) {
		if (sc_path_set(&path, SC_PATH_TYPE_FILE_ID, buf, buf_len - 2, 0, 0) != SC_SUCCESS) {
			fprintf(stderr, "unable to set path\n");
			return -2;
		}
	} else {
		if (sc_path_set(&path, SC_PATH_TYPE_PATH, &buf[2], buf_len - 4, 0, 0) != SC_SUCCESS) {
			fprintf(stderr, "unable to set path\n");
			return -2;
		}
	}

	/* Select parent file */
	r = sc_select_file(card, &path, &file);
	if (r) {
		fprintf(stderr, "SELECT FILE failed: %s\n", sc_strerror(r));
		return -3;
	}

	/* Parse outer tag 0x6F */
	tag_val =  sc_asn1_find_tag(card->ctx, fci, fci_len, (unsigned int) 0x6F, &tag_len);
	if (tag_val == NULL) {
		fprintf(stderr, "invalid or missing fci\n");
		return -4;
	}

	file = sc_file_new();
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->status = SC_FILE_STATUS_ACTIVATED;

	/* Parse tag 0x83 - file id */
	tv =  sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x83, &tl);
	if ((tv == NULL) || (tl != 2)) {
		fprintf(stderr, "invalid or missing file id\n");
		return -5;
	}
	file->id = (tv[0] << 8) | tv[1];

	/* Parse tag 0x81 - file size */
	tv =  sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x81, &tl);
	if ((tv == NULL) || (tl != 2)) {
		fprintf(stderr, "invalid or missing file size\n");
		return -6;
	}
	file->size = (tv[0] << 8) + tv[1];

	/* Parse tag 0x86 - security attributes */
	tv =  sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x86, &tl);
	if ((tv == NULL) || (tl != 8)) {
		fprintf(stderr, "invalid or missing security attributes\n");
		return -7;
	}
	file->sec_attr = malloc(tl);
	file->sec_attr_len = tl;
	memcpy(file->sec_attr, tv, tl);

	r = sc_create_file(card, file);
	if (r) {
		fprintf(stderr, "CREATE FILE failed\n");
		return -8;
	}

	r = sc_update_binary(card, 0, data, file->size, 0);
	if (r != (int)file->size) {
		fprintf(stderr, "UPDATE BINARY failed\n");
		return -8;
	}

	sc_file_free(file);
	return r;
}

static int card_readImpExp(const char *file)
{
	FILE *fh;
	u8 select_isoApplet[] = {0x00, 0xA4, 0x04, 0x00, 0x0C, 0xF2, 0x76, 0xA2, 0x88, 0xBC, 0xFB, 0xA6, 0x9D, 0x34, 0xF3, 0x10, 0x01, 0xFF};
	u8 read_config[] = {0x00, 0xCA, 0x3F, 0xCF, 0xFF};
	u8 read_key[] = {0x00, 0xCA, 0x3F, 0xFF, 0x01, 0x00, 0xFF};
	u8 resp[SC_MAX_EXT_APDU_BUFFER_SIZE];
	int resplen;
	sc_path_t path;
	const u8 *tag_val;
	size_t tag_len;
	int key_max_count;
	u8 import_export = 0x00;

	resplen = send_apduImpExp(select_isoApplet, sizeof(select_isoApplet), resp, sizeof(resp));
	if (resplen < 0) {
		return -1;
	}
	if (resplen != 6) {
		if (resplen != 7) {
			fprintf(stderr, "Unsupported IsoApplet version\n");
			return -2;
		}
		if ((resp[6] & 0x80) == 0) {
			fprintf(stderr, "Unsupported IsoApplet version\n");
			return -3;
		}
		resp[0] = 0;
		resp[1] = 7;
		resp[3] = 0xC0;
	}
	if ((resp[0] == 0) && (resp[1] < 7)) {
		fprintf(stderr, "Unsupported IsoApplet version\n");
		return -4;
	}
	if (resp[3] & 0x80) {
		fprintf(stderr, "IsoApplet v%X.%X EXPORT %s\n", resp[0], resp[1], resp[3] & 0x40 ? "enabled" : "disabled");
		import_export = 0x02 | (resp[3] & 0x40 ? 0x01 : 0x00);
	} else {
		fprintf(stderr, "IsoApplet v%X.%X RELEASE\n", resp[0], resp[1]);
		import_export = 0x00;
	}

	fh = fopen(file, "w");
	if (fh == NULL) {
		fprintf(stderr, "can not open file '%s'\n", file);
		return -5;
	}

	fprintf(stdout, "Reading general settings\n");

	resplen = send_apduImpExp(read_config, sizeof(read_config), resp, sizeof(resp));
	if (resplen < 0) {
		return -6;
        }
	fprintf(fh, "; INFO\n");
	util_hex_dump_asc(fh, resp, resplen, -1);

	if ((import_export & 0x01) == 0x00) {
		if (fh != stdout) {
			fclose(fh);
		}
		fprintf(stdout, "Done\n");
		return 0;
	}

	/* Find TAG_CONFIG */
	tag_val = sc_asn1_find_tag(card->ctx, resp, resplen, (unsigned int) 0xCF, &tag_len);
	if (tag_val == NULL) {
		fprintf(stderr, "invalid config data\n");
		return -7;
	}

	/* Find TAG_KEY_MAX_COUNT */
	tag_val = sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x07, &tag_len);
	if (tag_val == NULL) {
		fprintf(stderr, "missing TAG_KEY_MAX_COUNT.\n");
		return -8;
	}
	key_max_count = tag_val[0];

	sc_format_path("3F00", &path);
	enum_dirImpExp(fh, path, 0);

	for (int n = 0; n < key_max_count; n++) {
		read_key[5] = n;
		resplen = send_apduImpExp(read_key, sizeof(read_key), resp, sizeof(resp));
		if (resplen < 0) {
			return -9;
		}
		if (resplen != 0) {
			fprintf(stdout, "Reading private key #%d\n", n);
			fprintf(fh, "; KEY #%d\n", n);
			util_hex_dump_asc(fh, resp, resplen, -1);
		}
	}

	if (fh != stdout) {
		fclose(fh);
	}

	fprintf(stdout, "Done\n");

	return 0;
}

static int card_writeImpExp(const char *file)
{
	u8 select_isoApplet[] = {0x00, 0xA4, 0x04, 0x00, 0x0C, 0xF2, 0x76, 0xA2, 0x88, 0xBC, 0xFB, 0xA6, 0x9D, 0x34, 0xF3, 0x10, 0x01, 0xFF};
	FILE *fh;
	char buf[256], first_line[256];
	u8 apdu[SC_MAX_EXT_APDU_BUFFER_SIZE];
	u8 *data, tmp[256];
	const u8* tag_val, *tv;
	size_t len, tag_len, tmp_len, tl;
	u8 resp[SC_MAX_EXT_APDU_BUFFER_SIZE];
	int resplen;
	int import_export = 0x00;

	resplen = send_apduImpExp(select_isoApplet, sizeof(select_isoApplet), resp, sizeof(resp));
	if (resplen < 0) {
		return -1;
	}
	if (resplen != 6) {
		if (resplen != 7) {
			fprintf(stderr, "Unsupported IsoApplet version\n");
			return -2;
		}
		if ((resp[6] & 0x80) == 0) {
			fprintf(stderr, "Unsupported IsoApplet version\n");
			return -3;
		}
		resp[0] = 0;
		resp[1] = 7;
		resp[3] = 0xC0;
	}
	if ((resp[0] == 0) && (resp[1] < 7)) {
		fprintf(stderr, "Unsupported IsoApplet version\n");
		return -4;
	}
	if (resp[3] & 0x80) {
		fprintf(stderr, "IsoApplet v%X.%X EXPORT %s\n", resp[0], resp[1], resp[3] & 0x40 ? "enabled" : "disabled");
		import_export = 0x02 | (resp[3] & 0x40 ? 0x01 : 0x00);
	} else {
		fprintf(stderr, "IsoApplet v%X.%X RELEASE\n", resp[0], resp[1]);
		import_export = 0x00;
	}

	if ((import_export & 0x01) == 0x00) {
		fprintf(stdout, "Import disabled\n");
		return -5;
	}

	fh = fopen(file, "rb");
	if (fh == NULL) {
		fprintf(stderr, "can not open file '%s'\n", file);
		return -6;
	}

	while (!feof(fh)) {
		if (fgets(buf, 250, fh) == NULL)
			break;
		if (strncmp(buf, "; INFO", 6) == 0) {
			if (fgets(first_line, sizeof(first_line), fh) == NULL) {
				fprintf(stderr, "error reading file\n");
				break;
			}
			tmp_len = sizeof(tmp);
			sc_hex_to_bin(first_line, tmp, &tmp_len);
			if (tmp[0] != 0xCF) {
				fprintf(stderr, "invalid or missing config tag\n");
				break;
			}
			tag_val =  sc_asn1_find_tag(card->ctx, tmp, 16384, (unsigned int) 0xCF, &tag_len);
			len = (tag_len > 127 ? 3 : 2) + tag_len;
			fprintf(stdout, "Initialising card\n");
			data = read_blobImpExp(fh, first_line, len);
			if (data == NULL) {
				fprintf(stderr, "error reading config data\n");
				break;
			}
			apdu[0] = 0x80;
			apdu[1] = 0x50;
			apdu[2] = 0x00;
			apdu[3] = 0x00;
			apdu[4] = len;
			memcpy(&apdu[5], data, len);
			resplen = send_apduImpExp(apdu, len + 5, resp, sizeof(resp));
			if (resplen < 0) {
				break;
			}
			free(data);
		}
		if (strncmp(buf, "; KEY", 5) == 0) {
			if (fgets(first_line, 250, fh) == NULL) {
				fprintf(stderr, "error reading file\n");
				break;
			}
			tmp_len = sizeof(tmp);
			sc_hex_to_bin(first_line, tmp, &tmp_len);
			if ((tmp[0] == 0x7F) && (tmp[1] == 0x48)) {
				tag_val = sc_asn1_find_tag(card->ctx, tmp, 16384, (unsigned int) 0x7F48, &tag_len);
			} else if ((tmp[0] = 0xE0)) {
				tag_val =  sc_asn1_find_tag(card->ctx, tmp, 16384, (unsigned int) 0xE0, &tag_len);
			} else {
				fprintf(stderr, "invalid key data\n");
				break;
			}
			len = tag_len + (tag_val - tmp);
			tv = sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x1D, &tl);
			if ((tv == 0) || (tl != 1)) {
				fprintf(stderr, "invalid key reference\n");
				break;
			}
			fprintf(stdout, "Writing private key #%u\n", tv[0]);
			data = read_blobImpExp(fh, first_line, len);
			if (data == NULL) {
				fprintf(stderr, "error reading key data\n");
				break;
			}
			for (size_t pos = 0; pos < len;) {
				size_t len0 = len - pos;
				apdu[0] = len0 > 0xFF ? 0x10 : 0x00;
				apdu[1] = 0xDB;
				apdu[2] = 0x3F;
				apdu[3] = 0xFF;
				apdu[4] = len0 > 0xFF ? 0xFF : len0;
				memcpy(&apdu[5], &data[pos], len0 > 0xFF ? 0xFF : len0);
				resplen = send_apduImpExp(apdu, len0 > 0xFF ? 0x104 : len0 + 5, resp, sizeof(resp));
				if (resplen < 0) {
					break;
				}
				pos += len0 > 0xFF ? 0xFF : len0;
			}
			free(data);
		}
		if (strncmp(buf, "; FILE", 6) == 0) {
			char name[64];
			u8 fci[64];
			const u8 *tag_val, *tv;
			size_t fci_len = sizeof(fci), tag_len, tl;
			sscanf(strstr(buf, "FILE ") + 5, "%s", name);
			sc_hex_to_bin(strstr(buf, "FCI=") + 4, fci, &fci_len);
			tag_val =  sc_asn1_find_tag(card->ctx, fci, fci_len, (unsigned int) 0x6F, &tag_len);
			if (tag_val == NULL) {
				fprintf(stderr, "invalid or missing fci\n");
				break;
			}
			tv = sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x81, &tl);
			if ((tv == NULL) || (tl != 2)) {
				fprintf(stderr, "invalid or missing file size\n");
				break;
			}
			len = (tv[0] << 8) + tv[1];
			tag_val =  sc_asn1_find_tag(card->ctx, tag_val, tag_len, (unsigned int) 0x82, &tag_len);
			if (tag_val == NULL) {
				break;
				fprintf(stderr, "invalid or missing file type\n");
			}
			if (tag_val[0] == 0x38) {
				fprintf(stdout, "Creating %s\n", desc_nameImpExp(SC_FILE_TYPE_DF, name));
				if (mkdirImpExp(name, fci, fci_len) != 0) {
					break;
				}
			} else if (tag_val[0] == 0x01) {
				fprintf(stdout, "Writing %s\n", desc_nameImpExp(SC_FILE_TYPE_WORKING_EF, name));
				data = read_blobImpExp(fh, NULL, len);
				if (data == NULL) {
					fprintf(stderr, "error reading file data\n");
					break;
				}
				if (mkfileImpExp(name, fci, fci_len, data, len) != (int)len)
					break;
				free(data);
			} else {
					fprintf(stderr, "invalid file type\n");
					break;
			}
		}
	}

	fclose(fh);

	fprintf(stdout, "Done\n");

	return 0;
}

int main(int argc, char *argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_info = 0;
	int do_get_conf_entry = 0;
	int do_set_conf_entry = 0;
	int do_list_readers = 0;
	int do_list_drivers = 0;
	int do_list_files = 0;
	int do_send_apdu = 0;
	int do_print_atr = 0;
	int do_print_version = 0;
	int do_print_serial = 0;
	int do_print_name = 0;
	int do_list_algorithms = 0;
	int do_reset = 0;
	int action_count = 0;
	int do_read = 0;
	int do_write = 0;
	const char *opt_driver = NULL;
	const char *opt_conf_entry = NULL;
	const char *opt_reset_type = NULL;
	const char *opt_file = NULL;
	char **p;
	struct sc_reader *reader = NULL;
	sc_context_param_t ctx_param;

	while (1) {
		c = getopt_long(argc, argv, "inlG:S:fr:vs:Dc:awR:W:", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
		case 'i':
			do_info = 1;
			action_count++;
			break;
		case 'G':
			do_get_conf_entry = 1;
			opt_conf_entry = optarg;
			action_count++;
			break;
		case 'S':
			do_set_conf_entry = 1;
			opt_conf_entry = optarg;
			action_count++;
			break;
		case 'l':
			do_list_readers = 1;
			action_count++;
			break;
		case 'D':
			do_list_drivers = 1;
			action_count++;
			break;
		case 'f':
			do_list_files = 1;
			action_count++;
			break;
		case 's':
			p = (char **) realloc(opt_apdus,
					(opt_apdu_count + 1) * sizeof(char *));
			if (!p) {
				fprintf(stderr, "Not enough memory\n");
				err = 1;
				goto end;
			}
			opt_apdus = p;
			opt_apdus[opt_apdu_count] = optarg;
			do_send_apdu++;
			if (opt_apdu_count == 0)
				action_count++;
			opt_apdu_count++;
			break;
		case 'a':
			do_print_atr = 1;
			action_count++;
			break;
		case 'n':
			do_print_name = 1;
			action_count++;
			break;
		case 'r':
			opt_reader = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case OPT_VERSION:
			do_print_version = 1;
			action_count++;
			break;
		case 'c':
			opt_driver = optarg;

			/* treat argument "?" as request to list drivers */
			if (opt_driver && strncmp("?", opt_driver, sizeof("?")) == 0) {
				opt_driver = NULL;
				do_list_drivers = 1;
				action_count++;
			}
			break;
		case 'w':
			opt_wait = 1;
			break;
		case OPT_SERIAL:
			do_print_serial = 1;
			action_count++;
			break;
		case OPT_LIST_ALG:
			do_list_algorithms = 1;
			action_count++;
			break;
		case OPT_RESET:
			do_reset = 1;
			opt_reset_type = optarg;
			action_count++;
			break;
		case 'R':
			do_read = 1;
			opt_file = optarg;
			action_count++;
			break;
		case 'W':
			do_write = 1;
			opt_file = optarg;
			action_count++;
			break;
		}
	}
	if (action_count == 0)
		util_print_usage_and_die(app_name, options, option_help, NULL);

	if (do_print_version)   {
		printf("%s\n", OPENSC_SCM_REVISION);
		action_count--;
	}

	if (do_info) {
		opensc_info();
		action_count--;
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;
	ctx_param.debug    = verbose;
	if (verbose)
		ctx_param.debug_file = stderr;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	ctx->flags |= SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER;

	if (do_get_conf_entry) {
		if ((err = opensc_get_conf_entry (opt_conf_entry)))
			goto end;
		action_count--;
	}
	if (do_set_conf_entry) {
		if ((err = opensc_set_conf_entry (opt_conf_entry)))
			goto end;
		action_count--;
	}
	if (do_list_readers) {
		if ((err = list_readers()))
			goto end;
		action_count--;
	}
	if (do_list_drivers) {
		if ((err = util_list_card_drivers(ctx)))
			goto end;
		action_count--;
	}
	if (action_count <= 0)
		goto end;

	err = util_connect_reader(ctx, &reader, opt_reader, opt_wait);
	if (err) {
		fprintf(stderr, "Failed to connect to reader: %s\n", sc_strerror(err));
		err = 1;
		goto end;
	}
	if (do_print_atr) {
		if (verbose) {
			printf("Card ATR:\n");
			util_hex_dump_asc(stdout, reader->atr.value, reader->atr.len, -1);
		} else {
			char tmp[SC_MAX_ATR_SIZE*3];
			sc_bin_to_hex(reader->atr.value, reader->atr.len, tmp, sizeof(tmp) - 1, ':');
			fprintf(stdout,"%s\n",tmp);
		}
		action_count--;
	}
	if (action_count <= 0)
		goto end;

	if (opt_driver != NULL) {
		err = sc_set_card_driver(ctx, opt_driver);
		if (err) {
			fprintf(stderr, "Driver '%s' not found!\n", opt_driver);
			err = 1;
			goto end;
		}
	}

	if (verbose)
		printf("Connecting to card in reader %s...\n", reader->name);

	err = sc_connect_card(reader, &card);
	if (err < 0) {
		fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(err));
		err = 1;
		goto end;
	}

	if (verbose)
                printf("Using card driver %s.\n", card->driver->name);

	if (do_print_serial) {
		if (verbose)
			printf("Card serial number:");
		print_serial(card);
		action_count--;
	}
	if (do_print_name) {
		if (verbose)
			printf("Card name: ");
		printf("%s\n", card->name);
		action_count--;
	}
	if (do_send_apdu) {
		if ((err = send_apdu()))
			goto end;
		action_count--;
	}

	if (do_list_files) {
		if ((err = list_files()))
			goto end;
		action_count--;
	}

	if (do_list_algorithms) {
		if ((err = list_algorithms()))
			goto end;
		action_count--;
	}

	if (do_reset) {
		if ((err = card_reset(opt_reset_type)))
			goto end;
		action_count--;
	}

	if (do_read) {
		if ((err = card_readImpExp(opt_file)))
			goto end;
		action_count--;
	}

	if (do_write) {
		if ((err = card_writeImpExp(opt_file)))
			goto end;
		action_count--;
	}

end:
	sc_disconnect_card(card);
	sc_release_context(ctx);
	return err;
}
