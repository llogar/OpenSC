/*
 * Support for the IsoApplet JavaCard Applet.
 *
 * Copyright (C) 2014 Philip Wendland <wendlandphilip@gmail.com>
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

#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "cardctl.h"
#include "internal.h"
#include "log.h"
#include "opensc.h"
#include "pkcs15.h"
#include "types.h"

#define ISOAPPLET_ALG_REF_ECDSA_SHA1 0x21
#define ISOAPPLET_ALG_REF_ECDSA_PRECOMPUTED_HASH 0x22
#define ISOAPPLET_ALG_REF_ECDH 0x23
#define ISOAPPLET_ALG_REF_RSA_PAD_PKCS1 0x11
#define ISOAPPLET_ALG_REF_RSA_PAD_PSS 0x12

#include "card-isoApplet.h"

static const u8 isoApplet_aid[] = {0xf2,0x76,0xa2,0x88,0xbc,0xfb,0xa6,0x9d,0x34,0xf3,0x10,0x01};

static char *isoApplet_model = "isoApplet";

/* Operations supported by the applet. */
static struct sc_card_operations isoApplet_ops;

/* A reference to the iso7816_* functions.
 * Initialized in sc_get_driver. */
static const struct sc_card_operations *iso_ops = NULL;

/* The description of the driver. */
static struct sc_card_driver isoApplet_drv =
{
	"Javacard with IsoApplet",
	"isoApplet",
	&isoApplet_ops,
	NULL, 0, NULL
};

static struct isoapplet_supported_ec_curves {
		struct sc_object_id oid;
		size_t size;
		unsigned int min_applet_version;
} ec_curves[] = {
	{{{1, 2, 840, 10045, 3, 1, 1, -1}},     192, 0x0000}, /* secp192r1, nistp192, prime192v1, ansiX9p192r1 */
	{{{1, 3, 132, 0, 33, -1}},              224, 0x0000}, /* secp224r1, nistp224 */
	{{{1, 2, 840, 10045, 3, 1, 7, -1}},     256, 0x0000}, /* secp256r1, nistp256, prime256v1, ansiX9p256r1 */
	{{{1, 3, 132, 0, 34, -1}},              384, 0x0000}, /* secp384r1, nistp384, prime384v1, ansiX9p384r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 3, -1}}, 192, 0x0000}, /* brainpoolP192r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 5, -1}}, 224, 0x0000}, /* brainpoolP224r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 7, -1}}, 256, 0x0000}, /* brainpoolP256r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 9, -1}}, 320, 0x0000}, /* brainpoolP320r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 11, -1}},    384, 0x0000}, /* brainpoolP384r1 */
	{{{1, 3, 36, 3, 3, 2, 8, 1, 1, 13, -1}},    512, 0x0000}, /* brainpoolP512r1 */
	{{{1, 3, 132, 0, 31, -1}},              192, 0x0006}, /* secp192k1 */
	{{{1, 3, 132, 0, 10, -1}},              256, 0x0006}, /* secp256k1 */
	{{{1, 3, 132, 0, 35, -1}},              521, 0x0000}, /* secp521r1, nistp521 */
	{{{-1}}, 0, 0} /* This entry must not be touched. */
};

/*
 * SELECT an applet on the smartcard. (Not in the emulated filesystem.)
 * The response will be written to resp.
 *
 * @param[in]     card
 * @param[in]     aid      The applet ID.
 * @param[in]     aid_len  The length of aid.
 *
 * @return SC_SUCCESS: The applet is present and could be selected.
 *         any other:  Transmit failure or the card returned an error.
 *                     The card will return an error when the applet is
 *                     not present.
 */
static int
isoApplet_select_applet(sc_card_t *card, const u8 *aid, const size_t aid_len)
{
	int rv;
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);

	if(aid_len > SC_MAX_APDU_BUFFER_SIZE)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xa4, 0x04, 0x00);
	apdu.lc = aid_len;
	apdu.data = aid;
	apdu.datalen = aid_len;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failure.");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
isoApplet_finish(sc_card_t *card)
{
	struct isoApplet_drv_data *drvdata=DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);
	if (drvdata)
	{
		free(drvdata);
		card->drv_data=NULL;
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
isoApplet_match_card(sc_card_t *card)
{
	int rv;

	rv = isoApplet_select_applet(card, isoApplet_aid, sizeof(isoApplet_aid));
	if(rv != SC_SUCCESS)
	{
		return 0;
	}

	return 1;
}

static int
isoApplet_get_info(sc_card_t * card, struct isoApplet_drv_data * drvdata) {
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;
	sc_context_t * ctx = card->ctx;

	rv = sc_get_data(card, 0x0101, rbuf, 7);
	if(rv == SC_ERROR_INS_NOT_SUPPORTED || rv == SC_ERROR_INCORRECT_PARAMETERS) {
		/* INS not supported. This is an older IsoApplet that might return the
		 * applet information upon selection. For backward compatibility, try this. */
		sc_apdu_t apdu;
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xa4, 0x04, 0x00);
		apdu.lc = sizeof(isoApplet_aid);
		apdu.data = isoApplet_aid;
		apdu.datalen = sizeof(isoApplet_aid);
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;
		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failure.");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "Error selecting applet.");
		rv = (int) apdu.resplen;
	}

	if (rv < 0) {
		LOG_TEST_RET(ctx, rv, "Card returned error.");
	}

	/* Fill up drvdata */
	if(rv >= 3)
	{
		drvdata->isoapplet_version = rbuf[0] << 8 | rbuf[1];
		if (rv < 6)
		{
			drvdata->isoapplet_features = rbuf[2];
		}
		else if ((rv == 7) && (rbuf[3] == 0xC7)) /* C7_LEGACY_MODE */
		{
			drvdata->isoapplet_features = rbuf[2];
			card->version.hw_major = rbuf[4] >> 4;
			card->version.hw_minor = rbuf[4] & 0x0F;
			card->version.fw_major = rbuf[5] >> 4;
			card->version.fw_minor = rbuf[5] & 0x0F;
		}
		else if (rv == 6)
		{
			drvdata->isoapplet_features = ((unsigned int)rbuf[2] << 8) | rbuf[3];
			card->version.hw_major = rbuf[4] >> 4;
			card->version.hw_minor = rbuf[4] & 0x0F;
			card->version.fw_major = rbuf[5] >> 4;
			card->version.fw_minor = rbuf[5] & 0x0F;
		}
		else
		{
			sc_log(card->ctx, "IsoApplet: Invalid card config data.");
			return SC_ERROR_INVALID_CARD;
		}
	}

	return SC_SUCCESS;
}

static int
isoApplet_init(sc_card_t *card)
{
	int i, r;
	unsigned int major_version = 0;
	unsigned long flags = 0;
	unsigned long ext_flags = 0;
	struct isoApplet_drv_data *drvdata;

	LOG_FUNC_CALLED(card->ctx);

	drvdata=calloc(1, sizeof(*drvdata));
	if (!drvdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	card->drv_data = drvdata;
	card->cla = 0x00;

	/* Obtain applet version and specific features */
	r = isoApplet_get_info(card, drvdata);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Error obtaining information about applet.");

	major_version = drvdata->isoapplet_version & 0xFF00;
	if(major_version == (ISOAPPLET_VERSION_V1 & 0xFF00))
	{
		if (drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_V1_RSA_PSS_CARD)
		{
			drvdata->isoapplet_features &= ~ISOAPPLET_API_FEATURE_V1_RSA_PSS_CARD;
			drvdata->isoapplet_features |= ISOAPPLET_API_FEATURE_V1_RSA_PSS;
		}
		if (drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_V1_RSA_4096_CARD)
		{
			drvdata->isoapplet_features &= ~ISOAPPLET_API_FEATURE_V1_RSA_4096_CARD;
			drvdata->isoapplet_features |= ISOAPPLET_API_FEATURE_V1_RSA_4096;
		}
	}
	if(major_version != (ISOAPPLET_VERSION_V0 & 0xFF00) && major_version != (ISOAPPLET_VERSION_V1 & 0xFF00))
	{
		sc_log(card->ctx, "IsoApplet: Mismatching major API version. Not proceeding. "
			   "API versions: Driver (%04X or %04X), applet (%04X). Please update accordingly.",
			   ISOAPPLET_VERSION_V0, ISOAPPLET_VERSION_V1, drvdata->isoapplet_version);
		r = SC_ERROR_INVALID_CARD;
		goto err;
	}
	else if(drvdata->isoapplet_version != ISOAPPLET_VERSION_V0 && drvdata->isoapplet_version != ISOAPPLET_VERSION_C7 && drvdata->isoapplet_version != ISOAPPLET_VERSION_V1)
	{
		sc_log(card->ctx, "IsoApplet: Mismatching minor version. Proceeding anyway. "
			   "API versions: Driver (%04X or %04X), applet (%04X). "
			   "Please update accordingly whenever possible.",
			   ISOAPPLET_VERSION_V0, ISOAPPLET_VERSION_V1, drvdata->isoapplet_version);
	}

	if(drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_EXT_APDU)
		card->caps |=  SC_CARD_CAP_APDU_EXT;
	if(drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_SECURE_RANDOM)
		card->caps |=  SC_CARD_CAP_RNG;
	if(drvdata->isoapplet_version <= 0x0005
			|| drvdata->isoapplet_features & (ISOAPPLET_API_FEATURE_ECDSA_SHA1 | ISOAPPLET_API_FEATURE_ECDSA_PRECOMPUTED_HASH | ISOAPPLET_API_FEATURE_ECDH))
	{
		/* There are Java Cards that do not support ECDSA at all. The IsoApplet
		 * started to report this with version 00.06.
		 *
		 * Curves supported by the pkcs15-init driver are indicated per curve. This
		 * should be kept in sync with the explicit parameters in the pkcs15-init
		 * driver. */
		flags = 0;
		if (major_version == (ISOAPPLET_VERSION_V0 & 0xFF00)) {
			// V0 & C7
			if (drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_ECDSA_SHA1)
			{
				flags |= SC_ALGORITHM_ECDSA_RAW;
				flags |= SC_ALGORITHM_ECDSA_HASH_SHA1;
			}
			if (drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_ECDSA_PRECOMPUTED_HASH)
			{
				flags |= SC_ALGORITHM_ECDSA_RAW;
				flags |= SC_ALGORITHM_ECDSA_HASH_NONE;
			}
			if (drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_ECDH)
			{
				flags |= SC_ALGORITHM_ECDSA_RAW;
				flags |= SC_ALGORITHM_ECDH_CDH_RAW;
			}
		} else { // ISOAPPLET_VERSION_V1
			flags |= SC_ALGORITHM_ECDSA_RAW;
			flags |= SC_ALGORITHM_ECDSA_HASH_NONE;
		}
		flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
		ext_flags = SC_ALGORITHM_EXT_EC_UNCOMPRESES;
		ext_flags |=  SC_ALGORITHM_EXT_EC_NAMEDCURVE;
		ext_flags |= SC_ALGORITHM_EXT_EC_F_P;
		for (i=0; ec_curves[i].oid.value[0] >= 0; i++)
		{
			if(drvdata->isoapplet_version >= ec_curves[i].min_applet_version)
				_sc_card_add_ec_alg(card, ec_curves[i].size, flags, ext_flags, &ec_curves[i].oid);
		}
	}
	card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;

	/* RSA */
	flags = 0;
	flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	flags |= SC_ALGORITHM_RSA_HASH_NONE;
	if(drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_V1_RSA_PSS) {
		flags |= SC_ALGORITHM_RSA_PAD_PSS;
	}
	/* Key-generation: */
	flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
	/* Modulus lengths: */
	if (drvdata->isoapplet_version >= ISOAPPLET_VERSION_C7 && drvdata->isoapplet_version < ISOAPPLET_VERSION_V1) {
		_sc_card_add_rsa_alg(card, 1024, flags, 0);
		_sc_card_add_rsa_alg(card, 1536, flags, 0);
	}
	_sc_card_add_rsa_alg(card, 2048, flags, 0);
	if (drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_V1_RSA_4096) {
		_sc_card_add_rsa_alg(card, 4096, flags, 0);
	}
	if(drvdata->isoapplet_features & ISOAPPLET_API_FEATURE_RSA_4096)
	{
		_sc_card_add_rsa_alg(card, 3072, flags, 0);
		_sc_card_add_rsa_alg(card, 4096, flags, 0);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
err:
	free(drvdata);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * @brief convert an OpenSC ACL entry to the security condition
 * byte used by the IsoApplet.
 *
 * Used by IsoApplet_create_file to parse OpenSC ACL entries
 * into ISO 7816-4 Table 20 security condition bytes.
 *
 * @param entry The OpenSC ACL entry.
 *
 * @return The security condition byte. No restriction (0x00)
 *         if unknown operation.
 */
static u8
isoApplet_acl_to_security_condition_byte(const sc_acl_entry_t *entry)
{
	if(!entry)
		return 0x00;
	switch(entry->method)
	{
	case SC_AC_CHV:
		return 0x90 | (entry->key_ref - 1);
	case SC_AC_NEVER:
		return 0xFF;
	case SC_AC_NONE:
	default:
		return 0x00;
	}
}

/*
 * The reason for this function is that OpenSC doesn't set any
 * Security Attribute Tag in the FCI upon file creation if there
 * is no file->sec_attr. I set the file->sec_attr to a format
 * understood by the applet (ISO 7816-4 tables 16, 17 and 20).
 * The iso7816_create_file will then set this as Tag 86 - Sec.
 * Attr. Prop. Format.
 * The applet will then be able to set and enforce access rights
 * for any file created by OpenSC. Without this function, the
 * applet would not know where to enforce security rules and
 * when.
 *
 * Note: IsoApplet currently only supports a "onepin" option.
 *
 * Format of the sec_attr: 8 Bytes:
 *  7      - ISO 7816-4 table 16 or 17
 *  6 to 0 - ISO 7816-4 table 20
 */
static int
isoApplet_create_file(sc_card_t *card, sc_file_t *file)
{
	int r = 0;

	LOG_FUNC_CALLED(card->ctx);

	if(file->sec_attr_len == 0)
	{
		u8 access_buf[8];
		int idx[8], i;

		if(file->type == SC_FILE_TYPE_DF)
		{
			const int df_idx[8] = /* These are the SC operations. */
			{
				0, /* Reserved. */
				SC_AC_OP_DELETE_SELF, /* b6 */
				SC_AC_OP_LOCK,        /* b5 */
				SC_AC_OP_ACTIVATE,    /* b4 */
				SC_AC_OP_DEACTIVATE,  /* b3 */
				SC_AC_OP_CREATE_DF,   /* b2 */
				SC_AC_OP_CREATE_EF,   /* b1 */
				SC_AC_OP_DELETE       /* b0 */
			};
			for(i=0; i<8; i++)
			{
				idx[i] = df_idx[i];
			}
		}
		else   /* EF */
		{
			const int ef_idx[8] =
			{
				0, /* Reserved. */
				SC_AC_OP_DELETE_SELF, /* b6 */
				SC_AC_OP_LOCK,        /* b5 */
				SC_AC_OP_ACTIVATE,    /* b4 */
				SC_AC_OP_DEACTIVATE,  /* b3 */
				SC_AC_OP_WRITE,       /* b2 */
				SC_AC_OP_UPDATE,      /* b1 */
				SC_AC_OP_READ         /* b0 */
			};
			for(i=0; i<8; i++)
			{
				idx[i] = ef_idx[i];
			}
		}
		/* Now idx contains the operation identifiers.
		 * We now search for the OPs. */
		access_buf[0] = 0xFF; /* A security condition byte is present for every OP. (Table 19) */
		for(i=1; i<8; i++)
		{
			const sc_acl_entry_t *entry;
			entry = sc_file_get_acl_entry(file, idx[i]);
			access_buf[i] = isoApplet_acl_to_security_condition_byte(entry);
		}

		r = sc_file_set_sec_attr(file, access_buf, 8);
		LOG_TEST_RET(card->ctx, r, "Error adding security attribute.");
	}

	r = iso_ops->create_file(card, file);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Add an ACL entry to the OpenSC file struct, according to the operation
 * and the saByte (Encoded according to IsoApplet FCI proprietary security
 * information, see also ISO 7816-4 table 20).
 *
 * @param[in,out] file
 * @param[in]     operation The OpenSC operation.
 * @param[in]     saByte    The security condition byte returned by the applet.
 */
static int
isoApplet_add_sa_to_acl(sc_file_t *file, unsigned int operation, u8 saByte)
{
	int r;

	switch(saByte)
	{
	case 0x90:
		r = sc_file_add_acl_entry(file, operation, SC_AC_CHV, 1);
		if(r < 0)
			return r;
		break;
	case 0xFF:
		r = sc_file_add_acl_entry(file, operation, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
		if(r < 0)
			return r;
		break;
	case 0x00:
		r = sc_file_add_acl_entry(file, operation, SC_AC_NONE, SC_AC_KEY_REF_NONE);
		if(r < 0)
			return r;
		break;
	default:
		if ((saByte & 0x90) == 0x90)
		{
			r = sc_file_add_acl_entry(file, operation, SC_AC_CHV, (saByte & 0x0F) + 1);
		}
		else
		{
			r = sc_file_add_acl_entry(file, operation, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);
		}
		if(r < 0)
			return r;
	}
	return SC_SUCCESS;
}


/*
 * This function first calls the iso7816.c process_fci() for any other FCI
 * information and then updates the ACL of the OpenSC file struct according
 * to the FCI from the applet.
 */
static int
isoApplet_process_fci(sc_card_t *card, sc_file_t *file,
                      const u8 *buf, size_t buflen)
{
	int r;
	u8 *sa = NULL;

	LOG_FUNC_CALLED(card->ctx);

	r = iso_ops->process_fci(card, file, buf, buflen);
	LOG_TEST_RET(card->ctx, r, "Error while processing the FCI.");
	/* Construct the ACL from the sec_attr. */
	if(file->sec_attr && file->sec_attr_len == 8)
	{
		sa = file->sec_attr;
		if(sa[0] != 0xFF)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA,
			             "File security attribute does not contain a ACL byte for every operation.");
		}
		if(file->type == SC_FILE_TYPE_DF)
		{
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_DELETE_SELF, sa[1]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_LOCK, sa[2]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_ACTIVATE, sa[3]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_DEACTIVATE, sa[4]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_CREATE_DF, sa[5]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_CREATE_EF, sa[6]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_DELETE, sa[7]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
		}
		else if(file->type == SC_FILE_TYPE_INTERNAL_EF
		        || file->type == SC_FILE_TYPE_WORKING_EF)
		{
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_DELETE_SELF, sa[1]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_LOCK, sa[2]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_ACTIVATE, sa[3]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_DEACTIVATE, sa[4]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_WRITE, sa[5]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_UPDATE, sa[6]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = isoApplet_add_sa_to_acl(file, SC_AC_OP_READ, sa[7]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
		}

	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * @brief Encode the EC parameters as a concatenation of TLV entries.
 *
 * The format is:
 *  81 - prime
 *  82 - coefficient A
 *  83 - coefficient B
 *  84 - base point G
 *  85 - order
 *  87 - cofactor
 *
 *	@param[in]  card
 *	@param[in]  params  The ECparameters containing the information of the curve.
 *	@param[out] out     The array the encoded parameters are written to.
 *	@param[in]  out_len The size of out
 *	@param[out] ptr     A pointer pointing to the end of the parameters in out
 *                      (the first untouched byte behind the parameters).
 */
static int
isoApplet_put_ec_params(sc_card_t *card, sc_cardctl_isoApplet_ec_parameters_t *params, u8 *out, size_t out_len, u8 **ptr)
{
	u8 *p = out;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if(!params
	        || !params->prime.value
	        || !params->coefficientA.value
	        || !params->coefficientB.value
	        || !params->basePointG.value
	        || !params->order.value
	        || !params->coFactor.value)
	{
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Error: EC params not present.");
	}

	if(out == NULL || out_len == 0)
	{
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Error: Parameter out is NULL or outlen is zero.");
	}

	r = sc_asn1_put_tag(0x81, params->prime.value, params->prime.len, p, out_len - (p - out), &p);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	r = sc_asn1_put_tag(0x82, params->coefficientA.value, params->coefficientA.len, p, out_len - (p - out), &p);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	r = sc_asn1_put_tag(0x83, params->coefficientB.value, params->coefficientB.len, p, out_len - (p - out), &p);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	r = sc_asn1_put_tag(0x84, params->basePointG.value, params->basePointG.len, p, out_len - (p - out), &p);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	r = sc_asn1_put_tag(0x85, params->order.value, params->order.len, p, out_len - (p - out), &p);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	r = sc_asn1_put_tag(0x87, params->coFactor.value, params->coFactor.len, p, out_len - (p - out), &p);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");

	if (ptr != NULL)
		*ptr = p;
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * @brief Initialise token (truncate label). In case of failed (previous) initialisation
 * send INITIALISE apdu to clean-up card fs.
 */
static int
isoApplet_ctl_init_token(sc_card_t *card, sc_cardctl_pkcs11_init_token_t *args)
{
	int r;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);

	/* ISO7816 proprietary INITIALISE apdu */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x51, 0x00, 0x00);
	apdu.cla = 0x80;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r,  "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* Continue with ISO7816 init workflow */
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

/*
 * @brief Generate a private key on the card.
 */
static int
isoApplet_ctl_generate_key(sc_card_t *card, sc_cardctl_isoApplet_genkey_t *args)
{
	int r;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_EXT_APDU_RESP_SIZE];
	u8 sbuf[SC_MAX_EXT_APDU_DATA_SIZE];
	u8 *p;
	const u8 *inner_tag_value;
	const u8 *outer_tag_value;
	unsigned int tag;
	size_t outer_tag_len;
	size_t inner_tag_len;
	unsigned int cla;

	LOG_FUNC_CALLED(card->ctx);

	/* MANAGE SECURITY ENVIRONMENT (SET). Set the algorithm and key references. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0x00);

	p = sbuf;
	*p++ = 0x80; /* algorithm reference */
	*p++ = 0x01;
	*p++ = args->algorithm_ref;

	*p++ = 0x84; /* Private key reference */
	*p++ = 0x01;
	*p++ = args->priv_key_ref;

	r = p - sbuf;
	p = NULL;

	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");


	/* GENERATE ASYMMETRIC KEY PAIR
	 * We use a larger buffer here, even if the card does not support extended apdus.
	 * There are two cases:
	 *  1) The card can do ext. apdus: The data fits in one apdu.
	 *  2) The card can't do ext. apdus: sc_transmit_apdu will handle that - the
	 *     card will send SW_BYTES_REMAINING, OpenSC will automatically do a
	 *     GET RESPONSE to get the remaining data, and will append it to the data
	 *     buffer. */
	if(args->algorithm_ref == SC_ISOAPPLET_ALG_REF_EC_GEN)
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x46, 0x00, 0x00);
		apdu.data = sbuf;
		p = sbuf;
		r = isoApplet_put_ec_params(card, &args->pubkey.ec.params, p, sizeof(sbuf), &p);
		LOG_TEST_RET(card->ctx, r, "Error composing EC params.");
		apdu.datalen = p - sbuf;
		apdu.lc = p - sbuf;
		/* Use APDU chaining if the card does not support extended apdus
		 * and the data does not fit in one short apdu. */
		if ((apdu.datalen > 255) && !(card->caps & SC_CARD_CAP_APDU_EXT))
		{
			apdu.flags |= SC_APDU_FLAGS_CHAINING;
		}
	}
	else
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x46, 0x42, 0x00);
		apdu.data = sbuf;
		p = sbuf;
		*p++ = 0x91; /* key length */
		*p++ = 0x02;
		*p++ = args->key_len / 256;
		*p++ = args->key_len % 256;
		apdu.datalen = p - sbuf;
		apdu.lc = p - sbuf;
	}

	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	if (card->caps & SC_CARD_CAP_APDU_EXT) {
		apdu.le = apdu.resplen;
	} else {
		apdu.le = 256;
	}
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if(apdu.sw1 == 0x6A && apdu.sw2 == 0x81)
	{
		sc_log(card->ctx, "Key generation not supported by the card with that particular key type. "
		       "Your card may not support the specified algorithm used by the applet / specified by you. "
		       "In most cases, this happens when trying to generate EC keys not supported by your java card. "
		       "In this case, look for supported field lengths and whether FP and/or F2M are supported.");
	}
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* Parse the public key / response. */
	outer_tag_value = apdu.resp;
	r = sc_asn1_read_tag(&outer_tag_value, apdu.resplen, &cla, &tag, &outer_tag_len);
	LOG_TEST_RET(card->ctx, r, "Error in ASN1 handling.");
	/* Interindustry template for nesting one set of public key data objects */
	if((tag != 0x1F49) || (cla != 0x60))
	{
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA,
		             "The data returned by the card is unexpected.");
	}

	switch(args->algorithm_ref)
	{

	case SC_ISOAPPLET_ALG_REF_RSA_GEN:
	case SC_ISOAPPLET_ALG_REF_RSA_GEN_4096:
		/* Search for the modulus tag (81). */
		inner_tag_value = sc_asn1_find_tag(card->ctx, outer_tag_value, outer_tag_len, (unsigned int) 0x81, &inner_tag_len);
		const size_t expected_modulus_len = args->algorithm_ref == SC_ISOAPPLET_ALG_REF_RSA_GEN ? args->key_len/8 : 512;
		if(inner_tag_value == NULL || inner_tag_len != expected_modulus_len)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid modulus.");
		}
		if(inner_tag_len > args->pubkey.rsa.modulus.len)
		{
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
		}
		memcpy(args->pubkey.rsa.modulus.value, inner_tag_value, inner_tag_len);
		args->pubkey.rsa.modulus.len = inner_tag_len;

		/* Exponent tag (82) */
		inner_tag_value = sc_asn1_find_tag(card->ctx, outer_tag_value, outer_tag_len, (unsigned int) 0x82, &inner_tag_len);
		if(inner_tag_value == NULL || inner_tag_len != 3)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid exponent.");
		}
		if(inner_tag_len > args->pubkey.rsa.exponent.len)
		{
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
		}
		if(memcmp(inner_tag_value, "\x01\x00\x01", 3) != 0)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INCOMPATIBLE_KEY,
			             "Key generation error: Unexpected public key exponent.");
		}
		memcpy(args->pubkey.rsa.exponent.value, inner_tag_value, inner_tag_len);
		args->pubkey.rsa.exponent.len = inner_tag_len;
		p = NULL;
		break;

	case SC_ISOAPPLET_ALG_REF_EC_GEN:
		/* Compare the parameters received from the card to the ones sent to the card. */
		inner_tag_value = sc_asn1_find_tag(card->ctx, outer_tag_value, outer_tag_len, (unsigned int) 0x81, &inner_tag_len);
		if(inner_tag_value == NULL || inner_tag_len != args->pubkey.ec.params.prime.len
		        || memcmp(inner_tag_value, args->pubkey.ec.params.prime.value, inner_tag_len) != 0)
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid prime.");

		inner_tag_value = sc_asn1_find_tag(card->ctx, outer_tag_value, outer_tag_len, (unsigned int) 0x82, &inner_tag_len);
		if(inner_tag_value == NULL || inner_tag_len != args->pubkey.ec.params.coefficientA.len
		        || memcmp(inner_tag_value, args->pubkey.ec.params.coefficientA.value, inner_tag_len) != 0)
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid coefficient A.");

		inner_tag_value = sc_asn1_find_tag(card->ctx, outer_tag_value, outer_tag_len, (unsigned int) 0x83, &inner_tag_len);
		if(inner_tag_value == NULL || inner_tag_len != args->pubkey.ec.params.coefficientB.len
		        || memcmp(inner_tag_value, args->pubkey.ec.params.coefficientB.value, inner_tag_len) != 0)
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid coefficient B.");

		inner_tag_value = sc_asn1_find_tag(card->ctx, outer_tag_value, outer_tag_len, (unsigned int) 0x84, &inner_tag_len);
		if(inner_tag_value == NULL || inner_tag_len != args->pubkey.ec.params.basePointG.len
		        || memcmp(inner_tag_value, args->pubkey.ec.params.basePointG.value, inner_tag_len) != 0)
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid base point G.");

		inner_tag_value = sc_asn1_find_tag(card->ctx, outer_tag_value, outer_tag_len, (unsigned int) 0x85, &inner_tag_len);
		if(inner_tag_value == NULL || inner_tag_len != args->pubkey.ec.params.order.len
		        || memcmp(inner_tag_value, args->pubkey.ec.params.order.value, inner_tag_len) != 0)
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid order.");

		inner_tag_value = sc_asn1_find_tag(card->ctx, outer_tag_value, outer_tag_len, (unsigned int) 0x87, &inner_tag_len);
		if(args->pubkey.ec.params.coFactor.len == 1 && inner_tag_len == 2)
		{
			if(inner_tag_value == NULL || inner_tag_value[0] != 0
				|| inner_tag_value[1] != args->pubkey.ec.params.coFactor.value[0])
				LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid cofactor.");
		}
		else
		{
			if(inner_tag_value == NULL || inner_tag_len != args->pubkey.ec.params.coFactor.len
			        || memcmp(inner_tag_value, args->pubkey.ec.params.coFactor.value, inner_tag_len) != 0)
				LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid cofactor.");
		}

		/* Extract public key */
		inner_tag_value = sc_asn1_find_tag(card->ctx, outer_tag_value, outer_tag_len, (unsigned int) 0x86, &inner_tag_len);
		if(inner_tag_value == NULL || inner_tag_len != args->pubkey.ec.ecPointQ.len)
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid EC point Q.");
		memcpy(args->pubkey.ec.ecPointQ.value, inner_tag_value, inner_tag_len);

		break;
	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unable to parse public key: Unsupported algorithm.");
	}/* switch */

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * @brief Perform actual on card key delete.
 */
static int
isoApplet_ctl_delete_key(sc_card_t *card, sc_pkcs15_object_t *object)
{
	int r;
	struct sc_pkcs15_prkey_info *key_info = NULL;
	sc_apdu_t apdu;
	struct isoApplet_drv_data *drvdata = (struct isoApplet_drv_data *)card->drv_data;

	LOG_FUNC_CALLED(card->ctx);

	key_info = (struct sc_pkcs15_prkey_info *)object->data;
	if (key_info == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	if (drvdata->isoapplet_version < ISOAPPLET_VERSION_C7 || drvdata->isoapplet_version >= ISOAPPLET_VERSION_V1)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	/* ISO7816 proprietary DELETE_KEY apdu */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE5, 0x00, key_info->key_reference);
	apdu.cla = 0x80;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * @brief Use PUT DATA to import a private RSA key.
 *
 * For simplicity, command chaining has to be used. One chunk (apdu) must contain
 * one RSA field (P, Q, etc.). The first apdu must contain the outer tag (7F48).
 *
 * @param card
 * @param rsa The RSA private key to import.
 *
 * @return SC_ERROR_INVALID_ARGUMENTS: The RSA key does not contain CRT fields.
 *		   other errors:               Transmit errors / errors returned by card.
 */
static int
isoApplet_put_data_prkey_rsa(sc_card_t *card, sc_cardctl_isoApplet_import_key_t *args)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_EXT_APDU_DATA_SIZE], tmp[2];
	u8 *p = NULL;
	int r;
	size_t tags_len;
	struct isoApplet_drv_data *drvdata = (struct isoApplet_drv_data *)card->drv_data;

	LOG_FUNC_CALLED(card->ctx);

	if(!args->privkey.rsa.p.value
	        || !args->privkey.rsa.q.value
	        || !args->privkey.rsa.iqmp.value
	        || !args->privkey.rsa.dmp1.value
	        || !args->privkey.rsa.dmq1.value)
	{
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "RSA key is missing information.");
	}

	/* Note: The format is according to ISO 2-byte tag 7F48
	 * "T-L pair to indicate a private key data object" */

	/* Calculate the length of all inner tag-length-value entries, but do not write anything yet. */
	tags_len = 0;
	if (drvdata->isoapplet_version >= ISOAPPLET_VERSION_C7 && drvdata->isoapplet_version < ISOAPPLET_VERSION_V1) {
		r = sc_asn1_put_tag(0x91, NULL, 2, NULL, 0, NULL);
		LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
		tags_len += r;
	}
	r = sc_asn1_put_tag(0x92, NULL, args->privkey.rsa.p.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x93, NULL, args->privkey.rsa.q.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x94, NULL, args->privkey.rsa.iqmp.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x95, NULL, args->privkey.rsa.dmp1.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x96, NULL, args->privkey.rsa.dmq1.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;

	/* Write the outer tag and length information. */
	p = sbuf;
	r = sc_asn1_put_tag(0x7F48, NULL, tags_len, p, sizeof(sbuf), &p);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");

	/* Write inner tags. */
	if (drvdata->isoapplet_version >= ISOAPPLET_VERSION_C7 && drvdata->isoapplet_version < ISOAPPLET_VERSION_V1) {
		tmp[0] = args->key_len / 256;
		tmp[1] = args->key_len % 256;
		r = sc_asn1_put_tag(0x91, tmp, 2, p, sizeof(sbuf) - (p - sbuf), &p);
		if(r < 0)
			goto out;
	}
	/* p */
	r = sc_asn1_put_tag(0x92, args->privkey.rsa.p.value, args->privkey.rsa.p.len, p, sizeof(sbuf) - (p - sbuf), &p);
	if(r < 0)
		goto out;
	/* q */
	r = sc_asn1_put_tag(0x93, args->privkey.rsa.q.value, args->privkey.rsa.q.len, p, sizeof(sbuf) - (p - sbuf), &p);
	if(r < 0)
		goto out;
	/* 1/q mod p */
	r = sc_asn1_put_tag(0x94, args->privkey.rsa.iqmp.value, args->privkey.rsa.iqmp.len, p, sizeof(sbuf) - (p - sbuf), &p);
	if(r < 0)
		goto out;
	/* d mod (p-1) */
	r = sc_asn1_put_tag(0x95, args->privkey.rsa.dmp1.value, args->privkey.rsa.dmp1.len, p, sizeof(sbuf) - (p - sbuf), &p);
	if(r < 0)
		goto out;
	/* d mod (q-1) */
	r = sc_asn1_put_tag(0x96, args->privkey.rsa.dmq1.value, args->privkey.rsa.dmq1.len, p, sizeof(sbuf) - (p - sbuf), &p);
	if(r < 0)
		goto out;

	/* Send to card, using chaining or extended APDUs. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xDB, 0x3F, 0xFF);
	apdu.data = sbuf;
	apdu.datalen = p - sbuf;
	apdu.lc = p - sbuf;
	if ((card->caps & SC_CARD_CAP_APDU_EXT) == 0)
	{
		/* The lower layers will automatically do chaining */
		apdu.flags |= SC_APDU_FLAGS_CHAINING;
	}
	r = sc_transmit_apdu(card, &apdu);
	if(r < 0)
		goto out;
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if(apdu.sw1 == 0x6A && apdu.sw2 == 0x81)
	{
		sc_log(card->ctx, "Key import not supported by the card with that particular key type. "
		       "Your card may not support the specified algorithm used by the applet / specified by you. "
		       "In most cases, this happens when trying to import EC keys not supported by your java card. "
		       "In this case, look for supported field lengths and whether FP and/or F2M are supported. "
		       "If you tried to import a private RSA key, check the key length.");
	}
	if(apdu.sw1 == 0x69 && apdu.sw2 == 0x00)
	{
		sc_log(card->ctx, "Key import not allowed by the applet's security policy. "
		       "If you want to allow key import, set DEF_PRIVATE_KEY_IMPORT_ALLOWED in the IsoApplet,"
		       " rebuild and reinstall the applet.");
	}
	if(r < 0)
		goto out;

	r = SC_SUCCESS;
out:
	sc_mem_clear(sbuf, sizeof(sbuf));
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * @brief Use PUT DATA to import a private EC key.
 *
 * Format of transmitted data:
 *  0xE0 - Private class, constructed encoding, number one.
 *  0x81 - prime
 *  0x82 - coefficient A
 *  0x83 - coefficient B
 *  0x84 - base point G
 *  0x85 - order
 *  0x87 - cofactor
 *  0x88 - private D (private key)
 *
 * @param card
 * @param ec   The EC private key to import.
 *
 * @return SC_ERROR_INVALID_ARGUMENTS: Curve parameters or private component is missing.
 *         other errors:               Transmit errors / errors returned by card.
 *                                     ASN1 errors.
 */
static int
isoApplet_put_data_prkey_ec(sc_card_t *card, sc_cardctl_isoApplet_import_key_t *args)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_EXT_APDU_DATA_SIZE];
	int r;
	u8 *p;
	size_t tags_len;

	LOG_FUNC_CALLED(card->ctx);

	if(!args->privkey.ec.privateD.value
	        || !args->privkey.ec.params.prime.value
	        || !args->privkey.ec.params.coefficientA.value
	        || !args->privkey.ec.params.coefficientB.value
	        || !args->privkey.ec.params.basePointG.value
	        || !args->privkey.ec.params.order.value
	        || !args->privkey.ec.params.coFactor.value
	  )
	{
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Missing information about EC private key.");
	}

	/* Calculate the length of all inner tag-length-value entries, but do not write anything yet. */
	tags_len = 0;
	r = sc_asn1_put_tag(0x81, NULL, args->privkey.ec.params.prime.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x82, NULL, args->privkey.ec.params.coefficientA.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x83, NULL, args->privkey.ec.params.coefficientB.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x84, NULL, args->privkey.ec.params.basePointG.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x85, NULL, args->privkey.ec.params.order.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x87, NULL, args->privkey.ec.params.coFactor.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;
	r = sc_asn1_put_tag(0x88, NULL, args->privkey.ec.privateD.len, NULL, 0, NULL);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");
	tags_len += r;

	/* Write the outer tag and length information. */
	p = sbuf;
	r = sc_asn1_put_tag(0xE0, NULL, tags_len, p, sizeof(sbuf), &p);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");

	/* Write inner tags. */
	r = isoApplet_put_ec_params(card, &args->privkey.ec.params, p, sizeof(sbuf) - (p - sbuf), &p);
	if(r < 0)
	{
		sc_log(card->ctx, "Error composing EC params.");
		goto out;
	}
	r = sc_asn1_put_tag(0x88, args->privkey.ec.privateD.value, args->privkey.ec.privateD.len, p, sizeof(sbuf) - (p - sbuf), &p);
	if(r < 0)
		goto out;

	/* Send to card. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xDB, 0x3F, 0xFF);
	apdu.lc = p - sbuf;
	apdu.datalen = p - sbuf;
	apdu.data = sbuf;
	if ((apdu.datalen > 255) && !(card->caps & SC_CARD_CAP_APDU_EXT))
	{
		apdu.flags |= SC_APDU_FLAGS_CHAINING;
	}
	r = sc_transmit_apdu(card, &apdu);
	if(r < 0)
	{
		sc_log(card->ctx, "APDU transmit failed");
		goto out;
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if(apdu.sw1 == 0x6D && apdu.sw2 == 0x00)
	{
		sc_log(card->ctx, "The applet returned that the PUT DATA instruction byte is not supported. "
		       "If you are using an older applet version and are trying to import keys, please update your applet first.");
	}
	else if(apdu.sw1 == 0x6A && apdu.sw2 == 0x81)
	{
		sc_log(card->ctx, "Key import not supported by the card with that particular key type. "
		       "Your card may not support the specified algorithm used by the applet / specified by you. "
		       "In most cases, this happens when trying to import EC keys not supported by your java card. "
		       "In this case, look for supported field lengths and whether FP and/or F2M are supported. "
		       "If you tried to import a private RSA key, check the key length.");
	}
	else if(apdu.sw1 == 0x69 && apdu.sw2 == 0x00)
	{
		sc_log(card->ctx, "Key import not allowed by the applet's security policy. "
		       "If you want to allow key import, set DEF_PRIVATE_KEY_IMPORT_ALLOWED in the IsoApplet,"
		       " rebuild and reinstall the applet.");
	}
	if(r < 0)
	{
		sc_log(card->ctx, "Card returned error");
		goto out;
	}

	r = SC_SUCCESS;
out:
	sc_mem_clear(sbuf, sizeof(sbuf));
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * @brief Import a private key.
 */
static int
isoApplet_ctl_import_key(sc_card_t *card, sc_cardctl_isoApplet_import_key_t *args)
{
	int r;
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;

	LOG_FUNC_CALLED(card->ctx);

	/*
	 * Private keys are not stored in the filesystem.
	 * ISO 7816-8 - section C.2	 describes:
	 * "Usage of the PUT DATA command for private key import"
	 * The applet uses this PUT DATA to import private keys, if private key import is allowed.
	 *
	 * The first step is to perform a MANAGE SECURITY ENVIRONMENT as it would be done
	 * with on-card key generation. The second step is PUT DATA (instead of
	 * GENERATE ASYMMETRIC KEY PAIR).
	 */

	/* MANAGE SECURITY ENVIRONMENT (SET). Set the algorithm and key references. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0x00);

	p = sbuf;
	*p++ = 0x80; /* algorithm reference */
	*p++ = 0x01;
	*p++ = args->algorithm_ref;

	*p++ = 0x84; /* Private key reference */
	*p++ = 0x01;
	*p++ = args->priv_key_ref;

	r = p - sbuf;
	p = NULL;

	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "%s: APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");


	/* PUT DATA */
	switch(args->algorithm_ref)
	{

	case SC_ISOAPPLET_ALG_REF_RSA_GEN:
		r = isoApplet_put_data_prkey_rsa(card, args);
		LOG_TEST_RET(card->ctx, r, "Error in PUT DATA.");
		break;

	case SC_ISOAPPLET_ALG_REF_EC_GEN:
		r = isoApplet_put_data_prkey_ec(card, args);
		LOG_TEST_RET(card->ctx, r, "Error in PUT DATA.");
		break;

	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unknown algorithm reference.");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * @brief Erase card
 */
static int
isoApplet_ctl_erase_card(sc_card_t *card)
{
	int r;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);
	/* ISO7816 proprietary INITIALISE apdu */
	card->cla = 0x80;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x50, 0x00, 0x00);
	card->cla = 0x00;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r,  "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * @brief Return card serial number
 */
static int
isoApplet_ctl_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int r;
	sc_apdu_t apdu;
	u8  rbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct isoApplet_drv_data *drvdata = (struct isoApplet_drv_data *)card->drv_data;

	LOG_FUNC_CALLED(card->ctx);
	if (drvdata->isoapplet_version < ISOAPPLET_VERSION_C7 || drvdata->isoapplet_version >= ISOAPPLET_VERSION_V1)
	{
		memset(serial, 0, sizeof(*serial));
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_IMPLEMENTED);
	}
	/* ISO7816 proprietary GET VALUE apdu */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x6C, 0x01, 0x00);
	apdu.cla = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = SC_MAX_SERIALNR;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r,  "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");
	/* cache serial number */
	memcpy(card->serialnr.value, rbuf, apdu.resplen);
	card->serialnr.len = apdu.resplen;
	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
isoApplet_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	int r = 0;

	LOG_FUNC_CALLED(card->ctx);
	switch (cmd)
	{
	case SC_CARDCTL_PKCS11_INIT_TOKEN:
		r =  isoApplet_ctl_init_token(card,
		                               (sc_cardctl_pkcs11_init_token_t *) ptr);
		break;
	case SC_CARDCTL_ISOAPPLET_GENERATE_KEY:
		r = isoApplet_ctl_generate_key(card,
		                               (sc_cardctl_isoApplet_genkey_t *) ptr);
		break;
	case SC_CARDCTL_ISOAPPLET_DELETE_KEY:
		r = isoApplet_ctl_delete_key(card,
		                               (sc_pkcs15_object_t *) ptr);
		break;
	case SC_CARDCTL_ISOAPPLET_IMPORT_KEY:
		r = isoApplet_ctl_import_key(card,
		                             (sc_cardctl_isoApplet_import_key_t *) ptr);
		break;
	case SC_CARDCTL_ERASE_CARD:
		r = isoApplet_ctl_erase_card(card);
		break;
	case SC_CARDCTL_GET_SERIALNR:
		r = isoApplet_ctl_get_serialnr(card,
		                             (sc_serial_number_t *) ptr);
		break;
	case SC_CARDCTL_GET_MODEL:
		if (!ptr)
			r = SC_ERROR_INVALID_ARGUMENTS;
		else {
			*(char**)ptr = isoApplet_model;
			r = SC_SUCCESS;
		}
		break;
	default:
		r = SC_ERROR_NOT_SUPPORTED;
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
isoApplet_set_security_env(sc_card_t *card,
                           const sc_security_env_t *env, int se_num)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r;
	struct isoApplet_drv_data *drvdata = DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if(se_num != 0)
	{
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED,
		             "IsoApplet does not support storing of security environments.");
	}
	assert(card != NULL && env != NULL);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0);
	switch (env->operation)
	{
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_DERIVE:
		apdu.p2 = 0xB7;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	p = sbuf;

	if (env->flags & SC_SEC_ENV_ALG_PRESENT)
	{

		switch(env->algorithm)
		{

		case SC_ALGORITHM_RSA:
			if( env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1 )
			{
				drvdata->sec_env_alg_ref = ISOAPPLET_ALG_REF_RSA_PAD_PKCS1;
			}
			else if( env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS )
			{
				drvdata->sec_env_alg_ref = ISOAPPLET_ALG_REF_RSA_PAD_PSS;
			}
			else
			{
				LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "IsoApplet does not support requested padding/hash combination");
			}
			break;

		case SC_ALGORITHM_EC:
			if (env->operation == SC_SEC_OPERATION_SIGN)
			{
				if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_NONE)
				{
					drvdata->sec_env_alg_ref = ISOAPPLET_ALG_REF_ECDSA_PRECOMPUTED_HASH;
					drvdata->sec_env_ec_field_length = env->algorithm_ref;
				}
				else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_RAW)
				{
					if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA1)
					{
						drvdata->sec_env_alg_ref = ISOAPPLET_ALG_REF_ECDSA_SHA1;
					}
					else if (env->algorithm_flags == SC_ALGORITHM_ECDSA_RAW)
					{
						drvdata->sec_env_alg_ref = ISOAPPLET_ALG_REF_ECDSA_PRECOMPUTED_HASH;
					}
					else
					{
						LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "IsoApplet only supports ECDSA with SHA1 and NONE hashes");
					}
					drvdata->sec_env_ec_field_length = env->algorithm_ref;
				}
				else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA1)
				{
					drvdata->sec_env_alg_ref = ISOAPPLET_ALG_REF_ECDSA_SHA1;
				}
				else
				{
					LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported ECDSA parameters");
				}
			}
			else if (env->operation == SC_SEC_OPERATION_DERIVE)
			{
				drvdata->sec_env_alg_ref = ISOAPPLET_ALG_REF_ECDH;
				drvdata->sec_env_ec_field_length = env->algorithm_ref;
			}
			else
			{
				LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported ECC operation.");
			}
			break;

		default:
			LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported algorithm.");
		}

		*p++ = 0x80; /* algorithm reference */
		*p++ = 0x01;
		*p++ = drvdata->sec_env_alg_ref;
	}

	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT)
	{
		*p++ = 0x81;
		*p++ = env->file_ref.len;
		assert(sizeof(sbuf) - (p - sbuf) >= env->file_ref.len);
		memcpy(p, env->file_ref.value, env->file_ref.len);
		p += env->file_ref.len;
	}

	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
	{
		if (env->flags & SC_SEC_ENV_KEY_REF_SYMMETRIC)
			*p++ = 0x83;
		else
			*p++ = 0x84;
		*p++ = env->key_ref_len;
		assert(sizeof(sbuf) - (p - sbuf) >= env->key_ref_len);
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;

	if (apdu.datalen != 0)
	{
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, r, "Card returned error");
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
isoApplet_compute_signature(struct sc_card *card,
                            const u8 *data, size_t datalen,
                            u8 *out, size_t outlen)
{
	struct sc_context *ctx = card->ctx;
	struct isoApplet_drv_data *drvdata = DRVDATA(card);
	int r;

	LOG_FUNC_CALLED(ctx);

	if (drvdata->sec_env_alg_ref == ISOAPPLET_ALG_REF_RSA_PAD_PSS) {
		// For RSA-PSS signature schemes the IsoApplet expects only the hash.
		u8 tmp[64]; // large enough for SHA512
		size_t tmplen = sizeof(tmp);
		r = sc_pkcs1_strip_digest_info_prefix(NULL, data, datalen, tmp, &tmplen);
		if (r == SC_SUCCESS) {
			r = iso_ops->compute_signature(card, tmp, tmplen, out, outlen);
		} else {
			/* No digest info present? Use the value as it is */
			r = iso_ops->compute_signature(card, data, datalen, out, outlen);
		}
	} else if (drvdata->sec_env_alg_ref == ISOAPPLET_ALG_REF_ECDSA_SHA1 || drvdata->sec_env_alg_ref == ISOAPPLET_ALG_REF_ECDSA_PRECOMPUTED_HASH) {
		/*
		* The card returns ECDSA signatures as an ASN.1 sequence of integers R,S
		* while PKCS#11 expects the raw concatenation of R,S for PKCS#11.
		* We cannot expect the caller to provide an out buffer that is large enough for the ASN.1 sequence.
		* Therefore, we allocate a temporary buffer for the card output, and then convert it to raw R,S.
		* 8 is max overhead of ASN.1 sequence of integers R,S
		*/
		u8 *seqbuf = calloc(1, outlen + 8);
		if (!seqbuf)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		size_t seqlen = outlen + 8;
		r = iso_ops->compute_signature(card, data, datalen, seqbuf, seqlen);

		if (r < 0) {
			free(seqbuf);
			LOG_FUNC_RETURN(ctx, r);
		}

		/* Convert ASN.1 sequence of integers R,S to the raw concatenation of R,S for PKCS#11. */
		size_t len = (drvdata->sec_env_ec_field_length + 7) / 8 * 2;
		if (len > outlen) {
			free(seqbuf);
			LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
		}

		r = sc_asn1_sig_value_sequence_to_rs(ctx, seqbuf, r, out, len);
		free(seqbuf);
		LOG_TEST_RET(ctx, r, "Failed to convert ASN.1 signature to raw RS");
		r = len;
	} else {
		r = iso_ops->compute_signature(card, data, datalen, out, outlen);
	}
	LOG_FUNC_RETURN(ctx, r);
}

static int
isoApplet_get_challenge(struct sc_card *card, u8 *rnd, size_t len)
{
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if(card->caps & SC_CARD_CAP_RNG) {
		r = iso_ops->get_challenge(card, rnd, len);
	} else   {
		r = SC_ERROR_NOT_SUPPORTED;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int isoApplet_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (was_reset > 0) {
		r = isoApplet_select_applet(card, isoApplet_aid, sizeof(isoApplet_aid));
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int isoApplet_logout(sc_card_t *card)
{
	int r;
	struct isoApplet_drv_data *drvdata = (struct isoApplet_drv_data *)card->drv_data;

	LOG_FUNC_CALLED(card->ctx);
	if (drvdata->isoapplet_version < ISOAPPLET_VERSION_C7 || drvdata->isoapplet_version >= ISOAPPLET_VERSION_V1)
		return isoApplet_select_applet(card, isoApplet_aid, sizeof(isoApplet_aid));

	r = iso7816_logout(card, 0x00);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r,  "logout failed");
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
isoApplet_list_files(struct sc_card *card, u8 *buf, size_t buflen) {
	sc_apdu_t apdu;
	int r;
	struct isoApplet_drv_data *drvdata = (struct isoApplet_drv_data *)card->drv_data;
	if (drvdata->isoapplet_version < ISOAPPLET_VERSION_C7 || drvdata->isoapplet_version >= ISOAPPLET_VERSION_V1)
		return SC_ERROR_NOT_SUPPORTED;
	/* ISO7816 interindustry GET_DATA apdu */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0);
	apdu.resp = buf;
	apdu.resplen = buflen;
	apdu.le = buflen > 256 ? 256 : buflen;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	return apdu.resplen;
}

static int
isoApplet_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left) {
	if ((data->cmd == SC_PIN_CMD_GET_INFO) && (card->reader->capabilities & SC_READER_CAP_PIN_PAD))
	{
		// Fix around pinpad firewalled readers
		struct sc_apdu apdu;
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, data->pin_reference);
		apdu.cla = 0x80;
		data->apdu = &apdu;
	}
	return iso_ops->pin_cmd(card, data, tries_left);
}

static struct sc_card_driver *sc_get_driver(void)
{
	sc_card_driver_t *iso_drv = sc_get_iso7816_driver();

	if(iso_ops == NULL)
	{
		iso_ops = iso_drv->ops;
	}

	isoApplet_ops = *iso_drv->ops;

	isoApplet_ops.match_card = isoApplet_match_card;
	isoApplet_ops.init = isoApplet_init;
	isoApplet_ops.finish = isoApplet_finish;

	isoApplet_ops.card_ctl = isoApplet_card_ctl;

	isoApplet_ops.create_file = isoApplet_create_file;
	isoApplet_ops.process_fci = isoApplet_process_fci;
	isoApplet_ops.set_security_env = isoApplet_set_security_env;
	isoApplet_ops.compute_signature = isoApplet_compute_signature;
	isoApplet_ops.get_challenge = isoApplet_get_challenge;
	isoApplet_ops.card_reader_lock_obtained = isoApplet_card_reader_lock_obtained;
	isoApplet_ops.logout = isoApplet_logout;
	isoApplet_ops.list_files = isoApplet_list_files;

	isoApplet_ops.pin_cmd = isoApplet_pin_cmd;

	/* unsupported functions */
	isoApplet_ops.write_binary = NULL;
	isoApplet_ops.read_record = NULL;
	isoApplet_ops.write_record = NULL;
	isoApplet_ops.append_record = NULL;
	isoApplet_ops.update_record = NULL;
	isoApplet_ops.restore_security_env = NULL;

	return &isoApplet_drv;
}

struct sc_card_driver * sc_get_isoApplet_driver(void)
{
	return sc_get_driver();
}
