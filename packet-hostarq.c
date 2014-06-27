/* packet-hostarq.c
 * Routines for HostARQ protocol packet disassembly
 * By Eric Müller <mueller@kip.uni-heidelberg.de>
 * Copyright 2014 Eric Müller
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/prefs.h>
#include "packet-hostarq.h"

#define HOSTARQ_PORT 1234

#define JTAGBULK     0x0C33
#define JTAGSINGLE   0x0C3A
#define I2C          0x0CCC
#define FPGATRACE    0x0CA5
#define HICANNREAD   0x0CA3
#define FPGAPLAYBACK 0x0C5A
#define FPGAROUTING  0x0CAA
#define FPGACONFIG   0x0C1B
#define FPGABWLIMIT  0x0DB0
#define DNCROUTING   0x1364
#define DNCCONFIG    0x1361
#define HICANNCONFIG 0x2A1B

static const value_string pdutypenames[] = {
	// copied from host_al_controller.h
	{ JTAGBULK,     "JTAGBULK" },
	{ JTAGSINGLE,   "JTAGSINGLE" },
	{ I2C,          "I2C" },
	{ FPGATRACE,    "FPGATRACE" },
	{ HICANNREAD,   "HICANNREAD" },
	{ FPGAPLAYBACK, "FPGAPLAYBACK" },
	{ FPGAROUTING,  "FPGAROUTING" },
	{ FPGACONFIG,   "FPGACONFIG" },
	{ FPGABWLIMIT,  "FPGABWLIMIT" },
	{ DNCROUTING,   "DNCROUTING" },
	{ DNCCONFIG,    "DNCCONFIG" },
	{ HICANNCONFIG, "HICANNCONFIG" },
	{ 0, NULL}
};

static int proto_hostarq = -1;

static int hf_hostarq_pdu_ack = -1;
static int hf_hostarq_pdu_seq = -1;
static int hf_hostarq_pdu_valid = -1;
static int hf_hostarq_pdu_type = -1;
static int hf_hostarq_pdu_len = -1;

static gint ett_hostarq = -1;

static dissector_table_t hostarq_dissector_table = NULL;

static const value_string packettypenames[] = {
	{ 0,          "ACK"  },
	{ 1,          "DATA" },
	{ 0xffffffff, "DATA" }
};

void
proto_register_hostarq(void)
{
	static hf_register_info hf[] = {
		{ &hf_hostarq_pdu_ack,
			{ "HostARQ PDU Acknowledge", "hostarq.ack",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_hostarq_pdu_seq,
			{ "HostARQ PDU Sequence", "hostarq.seq",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_hostarq_pdu_valid,
			{ "HostARQ PDU Valid", "hostarq.valid",
				FT_UINT32, BASE_HEX,
				VALS(packettypenames), 0x0,
				NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_hostarq
	};

	proto_hostarq = proto_register_protocol (
		"HostARQ Protocol", /* name       */
		"HostARQ",          /* short name */
		"hostarq"           /* abbrev     */
	);

	proto_register_field_array(proto_hostarq, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_hostarq(void)
{
	static dissector_handle_t hostarq_handle;

	hostarq_handle = create_dissector_handle(dissect_hostarq, proto_hostarq);
	dissector_add_uint("udp.port", HOSTARQ_PORT, hostarq_handle);
}

static void
dissect_hostarq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	guint32 packet_ack  = tvb_get_ntohl(tvb, 0);
	guint32 packet_seq  = tvb_get_ntohl(tvb, 4);
	guint32 packet_type = tvb_get_ntohl(tvb, 8);
	guint16 pdu_type = 0;
	guint16 pdu_len = 0;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HostARQ");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);
	if (!packet_type)
		col_add_fstr(pinfo->cinfo, COL_INFO, "ack %u", packet_ack);
	else {
		pdu_type = tvb_get_ntohs(tvb, 12);
		pdu_len  = tvb_get_ntohs(tvb, 14);
		col_add_fstr(pinfo->cinfo, COL_INFO, "ack %u, seq %u, type %s, len %u",
			packet_ack,
			packet_seq,
			val_to_str(pdu_type, pdutypenames, "Unknown (0x%02x)"),
			pdu_len
		);
	}

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *hostarq_tree = NULL;

		ti = proto_tree_add_item(tree, proto_hostarq, tvb, 0, 12, ENC_BIG_ENDIAN); // just the hostarq header

		hostarq_tree = proto_item_add_subtree(ti, ett_hostarq);
		proto_tree_add_item(hostarq_tree, hf_hostarq_pdu_ack, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(hostarq_tree, hf_hostarq_pdu_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(hostarq_tree, hf_hostarq_pdu_valid, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		// go to next dissector if valid data
		if (packet_type) {
			next_tvb = tvb_new_subset(tvb, offset, -1, -1);

			// sniff ahead :)
			proto_tree_add_item(hostarq_tree, hf_hostarq_pdu_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(hostarq_tree, hf_hostarq_pdu_len, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			dissector_try_uint(hostarq_dissector_table, pdu_type, next_tvb, pinfo, tree);
		}
	}
}








/* payload starting here */

static int proto_nmpm1fcp = -1;
static gint ett_nmpm1fcp = -1;
	
#define FPGACONFIG_STR       1<<(32-9)
#define FPGACONFIG_EPL       1<<(32-8)
#define FPGACONFIG_STC       1<<(32-7)
#define FPGACONFIG_STP       1<<(32-6)
#define FPGACONFIG_SOT       1<<(32-5)
#define FPGACONFIG_STT       1<<(32-4)
#define FPGACONFIG_STE       1<<(32-3)
#define FPGACONFIG_CTM       1<<(32-2)
#define FPGACONFIG_CPM       1<<(32-1)

static int hf_nmpm1fcp_pdu_fpgaconfig_epl = -1;
static int hf_nmpm1fcp_pdu_fpgaconfig_str = -1;
static int hf_nmpm1fcp_pdu_fpgaconfig_stc = -1;
static int hf_nmpm1fcp_pdu_fpgaconfig_stp = -1;
static int hf_nmpm1fcp_pdu_fpgaconfig_sot = -1;
static int hf_nmpm1fcp_pdu_fpgaconfig_stt = -1;
static int hf_nmpm1fcp_pdu_fpgaconfig_ste = -1;
static int hf_nmpm1fcp_pdu_fpgaconfig_ctm = -1;
static int hf_nmpm1fcp_pdu_fpgaconfig_cpm = -1;
		
static int hf_nmpm1fcp_pdu_fpgaplayback_fpgatime = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_fpgacount = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_label = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_timestamp = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_hicanndata = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_hicanndest = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_overflow = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_trigger = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_dnc = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_hicann = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_tag = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_write = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_read = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_data = -1;

static int hf_nmpm1fcp_pdu_fpgatracedata_timestamp = -1;
static int hf_nmpm1fcp_pdu_fpgatracedata_label = -1;
static int hf_nmpm1fcp_pdu_fpgatracedata_overflow = -1;
static int hf_nmpm1fcp_pdu_fpgatracedata_flags = -1;




void
proto_register_nmpm1fcp(void)
{
	static hf_register_info hf[] = {
		{ &hf_hostarq_pdu_type,
			{ "NMPM1 FCP PDU Type", "nmpm1fcp.type",
				FT_UINT16, BASE_HEX,
				VALS(pdutypenames), 0x0,
				NULL, HFILL }
		},
		{ &hf_hostarq_pdu_len,
			{ "NMPM1 FCP PDU Length", "nmpm1fcp.len",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},

		/* FPGACONFIG */
		{ &hf_nmpm1fcp_pdu_fpgaconfig_str,
			{ "FPGA Config Start Enable Systime Replace", "fpgaconfig.str",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_STR,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaconfig_epl,
			{ "FPGA Config Enable Loopback", "fpgaconfig.epl",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_EPL,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaconfig_stc,
			{ "FPGA Config Start Read Traced Configuration", "fpgaconfig.stc",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_STC,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaconfig_stp,
			{ "FPGA Config Start Read Traced Pulses", "fpgaconfig.stp",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_STP,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaconfig_sot,
			{ "FPGA Config Stop Trace", "fpgaconfig.sot",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_SOT,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaconfig_stt,
			{ "FPGA Config Start Trace", "fpgaconfig.stt",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_STT,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaconfig_ste,
			{ "FPGA Config Start Experiment", "fpgaconfig.ste",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_STE,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaconfig_ctm,
			{ "FPGA Config Clear Trace Memory", "fpgaconfig.ctm",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_CTM,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaconfig_cpm,
			{ "FPGA Config Clear Playback Memory", "fpgaconfig.cpm",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_CPM,
				NULL, HFILL }
		},


		/* FPGAPLAYBACK */
		{ &hf_nmpm1fcp_pdu_fpgaplayback_fpgatime,
			{ "FPGA Playback Data FPGA Time", "fpgaplayback.fpgatime",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaplayback_fpgacount,
			{ "FPGA Playback Data Count", "fpgaplayback.fpgacount",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaplayback_label,
			{ "FPGA Playback Data Label", "fpgaplayback.label",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaplayback_timestamp,
			{ "FPGA Playback Data Timestamp", "fpgaplayback.timestamp",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		/* HICANN Configuration */
		{ &hf_nmpm1fcp_pdu_fpgaplayback_hicanndata,
			{ "FPGA Playback HICANN Data", "fpgaplayback.hicanndata",
				FT_UINT64, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaplayback_hicanndest,
			{ "FPGA Playback HICANN Data", "fpgaplayback.hicanndest",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		/* Timestamp Overflow Indicator */
		{ &hf_nmpm1fcp_pdu_fpgaplayback_overflow,
			{ "FPGA Playback Overflow Indicator", "fpgaplayback.overflow",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		/* Timestamp Overflow Indicator */
		{ &hf_nmpm1fcp_pdu_fpgaplayback_trigger,
			{ "FPGA Playback Trigger", "fpgaplayback.trigger",
				FT_UINT64, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},


		/* HICANN CFG Data */
		{ &hf_nmpm1fcp_pdu_hicanncfgdata_dnc,
			{ "HICANN Configuration Data DNC", "hicanncfgdata.dnc",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_hicanncfgdata_hicann,
			{ "HICANN Configuration Data HICANN", "hicanncfgdata.hicann",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_hicanncfgdata_tag,
			{ "HICANN Configuration Data Tag", "hicanncfgdata.tag",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_hicanncfgdata_write,
			{ "HICANN Configuration Data Write", "hicanncfgdata.write",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_hicanncfgdata_read,
			{ "HICANN Configuration Data Read", "hicanncfgdata.read",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_hicanncfgdata_data,
			{ "HICANN Configuration Data", "hicanncfgdata.data",
				FT_UINT64, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},


		/* Trace Data */
		{ &hf_nmpm1fcp_pdu_fpgatracedata_timestamp,
			{ "HICANN Trace Data Timestamp", "fpgatracedata.timestamp",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgatracedata_label,
			{ "HICANN Trace Data Label", "fpgatracedata.label",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgatracedata_overflow,
			{ "HICANN Trace Data Overflow", "fpgatracedata.overflow",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgatracedata_flags,
			{ "HICANN Trace Data Flags", "fpgatracedata.flags",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},

	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_nmpm1fcp
	};

	proto_nmpm1fcp = proto_register_protocol (
		"HBP NMPM1 FCP Protocol", /* name       */
		"NMPM1 FCP",              /* short name */
		"nmpm1fcp"                /* abbrev     */
	);

	proto_register_field_array(proto_nmpm1fcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	hostarq_dissector_table = register_dissector_table("nmpm1fcp.type",
	                                                   "NMPM1 FCP PDU Type",
	                                                   FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_nmpm1fcp(void)
{
	static dissector_handle_t nmpm1fcp_fpgaconfig_handle;
	static dissector_handle_t nmpm1fcp_fpgaplayback_handle;
	static dissector_handle_t nmpm1fcp_hicanncfgdata_handle;
	static dissector_handle_t nmpm1fcp_fpgatracedata_handle;

	nmpm1fcp_fpgaconfig_handle = create_dissector_handle(dissect_nmpm1fcp_fpgaconfig, proto_nmpm1fcp);
	dissector_add_uint("nmpm1fcp.type", FPGACONFIG, nmpm1fcp_fpgaconfig_handle);

	nmpm1fcp_fpgaplayback_handle = create_dissector_handle(dissect_nmpm1fcp_fpgaplayback, proto_nmpm1fcp);
	dissector_add_uint("nmpm1fcp.type", FPGAPLAYBACK, nmpm1fcp_fpgaplayback_handle);

	nmpm1fcp_hicanncfgdata_handle = create_dissector_handle(dissect_nmpm1fcp_hicanncfgdata, proto_nmpm1fcp);
	dissector_add_uint("nmpm1fcp.type", HICANNCONFIG, nmpm1fcp_hicanncfgdata_handle);
	
	nmpm1fcp_fpgatracedata_handle = create_dissector_handle(dissect_nmpm1fcp_fpgatracedata, proto_nmpm1fcp);
	dissector_add_uint("nmpm1fcp.type", FPGATRACE, nmpm1fcp_fpgatracedata_handle);
	// add other dissector foos here
}

static void
dissect_nmpm1fcp_fpgaconfig(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	gint offset = 0;
	guint32 tmp = 0;
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FPGACONFIG");

	tmp  = tvb_get_ntohl(tvb, 4); // skip type-len
	if (tmp) {
		col_append_str(pinfo->cinfo, COL_INFO, ", ");
		if (tmp & FPGACONFIG_STR) col_append_str(pinfo->cinfo, COL_INFO, "STR ");
		if (tmp & FPGACONFIG_EPL) col_append_str(pinfo->cinfo, COL_INFO, "EPL ");
		if (tmp & FPGACONFIG_STC) col_append_str(pinfo->cinfo, COL_INFO, "STC ");
		if (tmp & FPGACONFIG_STP) col_append_str(pinfo->cinfo, COL_INFO, "STP ");
		if (tmp & FPGACONFIG_SOT) col_append_str(pinfo->cinfo, COL_INFO, "SOT ");
		if (tmp & FPGACONFIG_STT) col_append_str(pinfo->cinfo, COL_INFO, "STT ");
		if (tmp & FPGACONFIG_STE) col_append_str(pinfo->cinfo, COL_INFO, "STE ");
		if (tmp & FPGACONFIG_CTM) col_append_str(pinfo->cinfo, COL_INFO, "CTM ");
		if (tmp & FPGACONFIG_CPM) col_append_str(pinfo->cinfo, COL_INFO, "CPM ");
	}

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *fpgaconfig_tree = NULL;

		ti = proto_tree_add_item(tree, proto_nmpm1fcp, tvb, 0, -1, ENC_NA); // consume all, nothing encapsulated here
		fpgaconfig_tree = proto_item_add_subtree(ti, ett_nmpm1fcp);
		
		offset += 4; // TYPLEN
		offset += 4; // upper bits of config frame are unused

		proto_tree_add_item(fpgaconfig_tree, hf_nmpm1fcp_pdu_fpgaconfig_str, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(fpgaconfig_tree, hf_nmpm1fcp_pdu_fpgaconfig_epl, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(fpgaconfig_tree, hf_nmpm1fcp_pdu_fpgaconfig_stc, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(fpgaconfig_tree, hf_nmpm1fcp_pdu_fpgaconfig_stp, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(fpgaconfig_tree, hf_nmpm1fcp_pdu_fpgaconfig_sot, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(fpgaconfig_tree, hf_nmpm1fcp_pdu_fpgaconfig_stt, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(fpgaconfig_tree, hf_nmpm1fcp_pdu_fpgaconfig_ste, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(fpgaconfig_tree, hf_nmpm1fcp_pdu_fpgaconfig_ctm, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(fpgaconfig_tree, hf_nmpm1fcp_pdu_fpgaconfig_cpm, tvb, offset, 4, ENC_BIG_ENDIAN);
		// skip second 32-bit entry: it's empty!
		offset += 8; // end of 8-byte payload entry
	}
}

static void
dissect_nmpm1fcp_fpgaplayback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	gint offset = 0;
	guint16 pbtype = 0;
	guint32 tmp = 0;
	//guint16 type = tvb_get_ntohs(tvb, 0);
	guint16 len = tvb_get_ntohs(tvb, 2);
	size_t i = 0, ii = 0;
	guint16 group_len = 0;
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FPGAPLAYBACK");

	//pbtype = tvb_get_ntohs(tvb, 4);
	//if ( ((pbtype & 0x1) == 0) && ((pbtype & (1<<15)) == 0) ) {
	//	/* Pulse entry */
	//	tmp = (pbtype & 0x7fff) >> 1; // get lower 15 bits and shift right once
	//	col_append_fstr(pinfo->cinfo, COL_INFO, " FPGA Time %u", tmp);
	//	tmp = (tvb_get_ntohs(tvb, 6) & 0x3fff); // lower 14 bits
	//	col_append_fstr(pinfo->cinfo, COL_INFO, " Count %u", tmp);
	//}
	offset += 4;

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *fpgaplayback_tree = NULL;

		ti = proto_tree_add_item(tree, proto_nmpm1fcp, tvb, 0, -1, ENC_NA); // consume all, nothing encapsulated here
		fpgaplayback_tree = proto_item_add_subtree(ti, ett_nmpm1fcp);
	

		for (i = 0; i < len; i++) {
			group_len = (tvb_get_ntohs(tvb, offset+4) >> 2) & 0x3fff;
			pbtype    = (tvb_get_ntohs(tvb, offset+6) >> 1) & 0x3fff;

			if ( ((pbtype & 0x1) == 0) && ((pbtype & (1<<15)) == 0) ) {
				/* Pulse group */
				i += group_len / 2; // 1 => +0, 2 => +1, 3 => +1, 4 => +2, ...

				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_label,     tvb, offset* 8+2, 12, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_timestamp, tvb, offset* 8, 15, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_fpgacount, tvb, offset* 8, 14, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_fpgatime,  tvb, offset* 8+1, 14, ENC_BIG_ENDIAN);
				offset += 2;

				for (ii = 1; ii < group_len; ii++) {
					proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_label,     tvb, offset* 8+2, 12, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_timestamp, tvb, offset* 8, 15, ENC_BIG_ENDIAN);
					offset += 2;
				}
				if ((group_len % 2) == 0) // if even, skip 2 bytes padding
					offset += 2;
					
			} else if ( ((pbtype & 0x1) == 0) && ((pbtype & (1<<15)) == 1) ) {
				/* HICANN configuration */
				i += group_len / 2;

				offset += 2;
				offset += 2;
				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_fpgacount, tvb, offset* 8, 14, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_fpgatime,  tvb, offset* 8+1, 14, ENC_BIG_ENDIAN);
				offset += 2;

				for (ii = 0; ii < group_len; ii++) {
					proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_hicanndest, tvb, offset* 8, 5, ENC_BIG_ENDIAN);
					offset += 1;
					// TODO: add tag!
					proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_hicanndata, tvb, offset* 8+7, 49, ENC_BIG_ENDIAN);
					offset += 7;
				}
			} else if ( ((pbtype & 0x1) == 1) && ((pbtype & 0x2) == 0) ) {
				/* Timestamp Overflow Indicator */
				offset += 4; // padding
				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_overflow, tvb, offset*8, 30, ENC_BIG_ENDIAN);
			} else if ( ((pbtype & 0x1) == 1) && ((pbtype & 0x2) == 1) ) {
				/* Wait for next experiment trigger */
				proto_tree_add_string(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_trigger, tvb, offset*8+2, 64, "Wait for next experiment");
			}
		}
	}
}

static void
dissect_nmpm1fcp_hicanncfgdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	//guint16 type = tvb_get_ntohs(tvb, 0);
	guint16 len = tvb_get_ntohs(tvb, 2);
	gint offset = 4;
	size_t ii = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HICANNCFGDATA");

	//col_append_fstr(pinfo->cinfo, COL_INFO, " DNC %u HICANN %u", (unsigned)dnc, (unsigned)hicann);

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *hicanncfgdata_tree = NULL;

		ti = proto_tree_add_item(tree, proto_nmpm1fcp, tvb, 0, -1, ENC_NA); // consume all, nothing encapsulated here
		hicanncfgdata_tree = proto_item_add_subtree(ti, ett_nmpm1fcp);
	
		for (ii = 0; ii < len; ii++) { 
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_dnc, tvb, offset*8, 2, ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_hicann, tvb, offset*8+2, 3, ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_tag,  tvb, offset*8+2+3+9, 1, ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_write,  tvb, offset*8+2+3+9+1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_read,  tvb, (offset+4)*8, 1, ENC_BIG_ENDIAN);
			//proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_data, tvb, offset*8, 49, ENC_BIG_ENDIAN);
			offset += 8;
		}
	}
}

static void
dissect_nmpm1fcp_fpgatracedata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	//guint16 type = tvb_get_ntohs(tvb, 0);
	guint16 len = tvb_get_ntohs(tvb, 2);
	gint offset = 4;
	guint8 tmp = 0;
	size_t ii = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FPGATRACE");

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *fpgatracedata_tree = NULL;

		ti = proto_tree_add_item(tree, proto_nmpm1fcp, tvb, 0, -1, ENC_NA); // consume all, nothing encapsulated here
		fpgatracedata_tree = proto_item_add_subtree(ti, ett_nmpm1fcp);
	
		for (ii = 0; ii < len*2; ii++) { // dword-wise!
			proto_tree_add_bits_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_flags, tvb, offset*8, 2, ENC_BIG_ENDIAN);
			tmp = tvb_get_guint8(tvb, offset) & 0x3;
			switch (tmp) {
				case 0:
					proto_tree_add_bits_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_label,     tvb, offset*8+5, 12, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_bits_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_timestamp, tvb, offset*8+1, 15, ENC_BIG_ENDIAN);
					offset += 2;
					break;
				case 1:
					// just padding...
					proto_tree_add_text(fpgatracedata_tree, tvb, offset, 4, "padding");
					offset += 4;
					break;
				case 2:
				case 3:
					//overflow because higher bit high
					proto_tree_add_bits_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_overflow, tvb, offset*8+1, 31, ENC_BIG_ENDIAN);
					offset += 4;
					break;
				default:
					break;
			}
		}
	}
}

#undef HOSTARQ_PORT
#undef JTAGBULK
#undef JTAGSINGLE
#undef I2C
#undef FPGATRACE
#undef HICANNREAD
#undef FPGAPLAYBACK
#undef FPGAROUTING
#undef FPGACONFIG
#undef FPGABWLIMIT
#undef DNCROUTING
#undef DNCCONFIG
#undef HICANNCONFIG
