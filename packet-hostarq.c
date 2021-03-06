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

#define HOSTARQ_LOOP 0x8001
#define HOSTARQ_CFG  0x8002

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
	{ HOSTARQ_CFG,  "HOSTARQ_CFG" },
	{ HOSTARQ_LOOP, "HOSTARQ_LOOP" },
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
		}/*,
		{ &hf_hostarq_pdu_valid,
			{ "HostARQ PDU Valid", "hostarq.valid",
				FT_UINT32, BASE_HEX,
				VALS(packettypenames), 0x0,
				NULL, HFILL }
		} */
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
	guint32 packet_seq;
	//guint32 packet_type = tvb_get_ntohl(tvb, 10);
	guint16 pdu_type = 0;
	guint16 pdu_len = 0;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HostARQ");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);
	if (tvb_reported_length(tvb) <= 4)
	//if (!packet_type)
		col_add_fstr(pinfo->cinfo, COL_INFO, "ack %5u", packet_ack);
	// ADD 4 < size < 12 => fail
	else {
		packet_seq = tvb_get_ntohl(tvb, 4);
		pdu_type = tvb_get_ntohs(tvb, 8);
		pdu_len  = tvb_get_ntohs(tvb, 10);
		col_add_fstr(pinfo->cinfo, COL_INFO, "ack %5u, seq %5u, type %14s, len %3u", /*, diff %u",*/
			packet_ack,
			packet_seq,
			val_to_str(pdu_type, pdutypenames, "Unknown (0x%02x)"),
			pdu_len/*,
			(packet_ack > packet_seq) ? packet_ack - packet_seq : packet_seq - packet_ack // DEBUG
			*/
		);
	}

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *hostarq_tree = NULL;

		ti = proto_tree_add_item(tree, proto_hostarq, tvb, 0, 12, ENC_BIG_ENDIAN); // just the hostarq header

		hostarq_tree = proto_item_add_subtree(ti, ett_hostarq);
		proto_tree_add_item(hostarq_tree, hf_hostarq_pdu_ack, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;


		// go to next dissector if valid data
		if (tvb_reported_length_remaining(tvb, offset)) {
			proto_tree_add_item(hostarq_tree, hf_hostarq_pdu_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

		//if (packet_type) {
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




/* special RESET type frames */
#define NMPM1FCPJTAG0_PORT 1700
#define NMPM1FCPJTAG1_PORT 1701
#define NMPM1FCPJTAG2_PORT 1702
#define NMPM1FCPJTAG3_PORT 1703
#define NMPM1FCPSYSSTART_PORT 1800
#define NMPM1FCPRESET_PORT 1801
#define NMPM1FCPHOSTARQRESET_PORT 45054

static int proto_nmpm1fcp_special = -1;

void
proto_reg_handoff_nmpm1fcp_special(void)
{
	static dissector_handle_t nmpm1fcp_jtag_handle;
	static dissector_handle_t nmpm1fcp_reset_handle;
	static dissector_handle_t nmpm1fcp_sysstart_handle;
	static dissector_handle_t nmpm1fcp_hostarqreset_handle;

	nmpm1fcp_jtag_handle = create_dissector_handle(dissect_nmpm1fcp_jtag, proto_nmpm1fcp_special);
	dissector_add_uint("udp.port", NMPM1FCPJTAG0_PORT, nmpm1fcp_jtag_handle);
	dissector_add_uint("udp.port", NMPM1FCPJTAG1_PORT, nmpm1fcp_jtag_handle);
	dissector_add_uint("udp.port", NMPM1FCPJTAG2_PORT, nmpm1fcp_jtag_handle);
	dissector_add_uint("udp.port", NMPM1FCPJTAG3_PORT, nmpm1fcp_jtag_handle);

	nmpm1fcp_reset_handle = create_dissector_handle(dissect_nmpm1fcp_reset, proto_nmpm1fcp_special);
	dissector_add_uint("udp.port", NMPM1FCPRESET_PORT, nmpm1fcp_reset_handle);

	nmpm1fcp_sysstart_handle = create_dissector_handle(dissect_nmpm1fcp_sysstart, proto_nmpm1fcp_special);
	dissector_add_uint("udp.port", NMPM1FCPSYSSTART_PORT, nmpm1fcp_sysstart_handle);

	nmpm1fcp_hostarqreset_handle = create_dissector_handle(dissect_nmpm1fcp_hostarqreset, proto_nmpm1fcp_special);
	dissector_add_uint("udp.port", NMPM1FCPHOSTARQRESET_PORT, nmpm1fcp_hostarqreset_handle);
}


static void
dissect_nmpm1fcp_jtag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FPGAJTAG");
	col_add_str(pinfo->cinfo, COL_INFO, "");
	// nothing yet
}

static void
dissect_nmpm1fcp_reset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	guint8 tmp;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FPGARESET");

	tmp = tvb_get_guint8(tvb, 0);
	if (tmp == 0x55) {
		tmp = tvb_get_guint8(tvb, 3);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Reset: Core %u FPGADNC %u DDR2 %u DDR2SODIMM %u ARQ %u",
			tmp>>0 & 0x1,
			tmp>>1 & 0x1,
			tmp>>2 & 0x1,
			tmp>>3 & 0x1,
			tmp>>4 & 0x1
		);
	} else
		col_add_str(pinfo->cinfo, COL_INFO, "incorrect, wrong magic number");
}

static void
dissect_nmpm1fcp_sysstart(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	guint8 tmp;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FPGASYSSTART");

	tmp = tvb_get_guint8(tvb, 0);
	if (tmp == 0x55) {
		tmp = tvb_get_guint8(tvb, 3);
		col_add_fstr(pinfo->cinfo, COL_INFO, "SysStart %s", tmp ? "on" : "off");
	} else if (tmp == 0xc0 && tvb_get_guint8(tvb, 1) == 0x07) {
		tmp = tvb_get_guint8(tvb, 3);
		col_add_fstr(pinfo->cinfo, COL_INFO, "SysStart Ack (deprecated): %s", tmp ? "on" : "off");
	} else
		col_add_str(pinfo->cinfo, COL_INFO, "incorrect, wrong magic number");
}

static void
dissect_nmpm1fcp_hostarqreset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HostARQ Reset");
	col_add_str(pinfo->cinfo, COL_INFO, "");
	/* other stuff was moved to HostARQ Cfg type */
}







/* payload starting here */

static int proto_nmpm1fcp = -1;
static gint ett_nmpm1fcp = -1;

#define FPGACONFIG_PTR       1<<(32-9)
#define FPGACONFIG_FPL       1<<(32-8)
#define FPGACONFIG_STC       1<<(32-7)
#define FPGACONFIG_STP       1<<(32-6)
#define FPGACONFIG_SOT       1<<(32-5)
#define FPGACONFIG_STT       1<<(32-4)
#define FPGACONFIG_STE       1<<(32-3)
#define FPGACONFIG_CTM       1<<(32-2)
#define FPGACONFIG_CPM       1<<(32-1)

#define FPGAPLAYBACK_HICANN_WRITE 0x1
#define FPGAPLAYBACK_HICANN_READ  0x80

#define FPGATRACEDATA_OVERFLOW 1 << 7
#define FPGATRACEDATA_INVALID    1 << 6
#define FPGATRACEDATA_FM       1 << 5

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

static int hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_dnc = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_dest = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_tag = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_write = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_read = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_payload = -1;

static int hf_nmpm1fcp_pdu_fpgaplayback_overflow = -1;
static int hf_nmpm1fcp_pdu_fpgaplayback_trigger = -1;

static int hf_nmpm1fcp_pdu_hicanncfgdata_dnc = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_hicann = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_tag = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_write = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_read = -1;
static int hf_nmpm1fcp_pdu_hicanncfgdata_payload = -1;

static int hf_nmpm1fcp_pdu_fpgatracedata_timestamp = -1;
static int hf_nmpm1fcp_pdu_fpgatracedata_label = -1;
static int hf_nmpm1fcp_pdu_fpgatracedata_overflows = -1;
static int hf_nmpm1fcp_pdu_fpgatracedata_fm = -1;
static int hf_nmpm1fcp_pdu_fpgatracedata_invalid = -1;
static int hf_nmpm1fcp_pdu_fpgatracedata_overflow = -1;




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
				NULL, FPGACONFIG_PTR,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaconfig_epl,
			{ "FPGA Config Enable Loopback", "fpgaconfig.epl",
				FT_BOOLEAN, 32,
				NULL, FPGACONFIG_FPL,
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
		{ &hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_dnc,
			{ "FPGA Playback HICANN CfgData DNC", "fpgaplayback.hicanncfgdata.dnc",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_dest,
			{ "FPGA Playback HICANN CfgData Dest", "fpgaplayback.hicanncfgdata.dest",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_tag,
			{ "FPGA Playback HICANN CfgData Tag", "fpgaplayback.hicanncfgdata.tag",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_write,
			{ "FPGA Playback HICANN CfgData Write", "fpgaplayback.hicanncfgdata.write",
				FT_BOOLEAN, 8,
				NULL, FPGAPLAYBACK_HICANN_WRITE,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_read,
			{ "FPGA Playback HICANN CfgData Read", "fpgaplayback.hicanncfgdata.read",
				FT_BOOLEAN, 8,
				NULL, FPGAPLAYBACK_HICANN_READ,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_payload,
			{ "FPGA Playback HICANN CfgData Payload", "fpgaplayback.hicanncfgdata.payload",
				FT_UINT64, BASE_DEC,
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
		{ &hf_nmpm1fcp_pdu_hicanncfgdata_payload,
			{ "HICANN Configuration Data", "hicanncfgdata.payload",
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
		{ &hf_nmpm1fcp_pdu_fpgatracedata_overflows,
			{ "HICANN Trace Data Overflow", "fpgatracedata.overflows",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgatracedata_fm,
			{ "HICANN Trace Data FM", "fpgatracedata.fm",
				FT_BOOLEAN, 8,
				NULL, FPGATRACEDATA_FM,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgatracedata_invalid,
			{ "HICANN Trace Data Invalid Marker", "fpgatracedata.invalid",
				FT_BOOLEAN, 8,
				NULL, FPGATRACEDATA_INVALID,
				NULL, HFILL }
		},
		{ &hf_nmpm1fcp_pdu_fpgatracedata_overflow,
			{ "HICANN Trace Data Overflow Marker", "fpgatracedata.overflow",
				FT_BOOLEAN, 8,
				NULL, FPGATRACEDATA_OVERFLOW,
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
	static dissector_handle_t nmpm1fcp_hostarqcfg_handle;
	static dissector_handle_t nmpm1fcp_fpgaconfig_handle;
	static dissector_handle_t nmpm1fcp_fpgaplayback_handle;
	static dissector_handle_t nmpm1fcp_hicanncfgdata_handle;
	static dissector_handle_t nmpm1fcp_fpgatracedata_handle;

	nmpm1fcp_hostarqcfg_handle = create_dissector_handle(dissect_nmpm1fcp_hostarqcfg, proto_nmpm1fcp);
	dissector_add_uint("nmpm1fcp.type", HOSTARQ_CFG, nmpm1fcp_hostarqcfg_handle);

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
dissect_nmpm1fcp_hostarqcfg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	guint64 max_nrframes = 0, max_winsiz = 0, max_pduwords = 0;
	guint offset = 4; // skip typelen

	max_nrframes = tvb_get_ntoh64(tvb, offset);
	offset += 8;
	max_winsiz = tvb_get_ntoh64(tvb, offset);
	offset += 8;
	max_pduwords = tvb_get_ntoh64(tvb, offset);
	offset += 8;

	col_set_str(pinfo->cinfo, COL_INFO, "HostARQ Config");
	col_append_fstr(pinfo->cinfo, COL_INFO,
					": MAX_NRFRAMES %llu MAX_WINSIZ %llu MAX_PDUWORDS %llu",
					(long long unsigned) max_nrframes,
					(long long unsigned) max_winsiz,
					(long long unsigned) max_pduwords);
}


static void
dissect_nmpm1fcp_fpgaconfig(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	gint offset = 0;
	guint32 tmp = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FPGACONFIG");

	tmp  = tvb_get_ntohl(tvb, 8); // skip type-len
	if (tmp) {
		col_append_str(pinfo->cinfo, COL_INFO, ", ");
		if (tmp & FPGACONFIG_PTR) col_append_str(pinfo->cinfo, COL_INFO, "PTR ");
		if (tmp & FPGACONFIG_FPL) col_append_str(pinfo->cinfo, COL_INFO, "FPL ");
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
	gboolean is_data = 0;
	gboolean is_pulse = 0;
	gboolean is_overflow = 0;
	guint32 tmp = 0;
	guint64 tmp64 = 0;
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

		// we should check for nodata here!

		for (i = 0; i < len; i++) {

			group_len = (tvb_get_ntohs(tvb, offset+4) >> 2) & 0x3fff;
			is_pulse    = !((tvb_get_ntohs(tvb, offset+4)) & 0x1);
			is_data     = !((tvb_get_ntohs(tvb, offset+6)) & 0x1);
			is_overflow = !(((tvb_get_ntohs(tvb, offset+6)) & 0x2) >> 1);

			if (is_data && is_pulse) {
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
					guint const endian_shitfuck = (ii % 2) == 1 ? 4 : 0;
					proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_label,     tvb, (offset + endian_shitfuck) * 8+2, 12, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_timestamp, tvb, (offset + endian_shitfuck) * 8, 15, ENC_BIG_ENDIAN);
					offset += 2;
				}
				if ((group_len % 2) == 0) // if even, we have to skip 4 bytes (endian_shitfuck is only for lookup not applied to offset)
					offset += 4;

			} else if (is_data && !is_pulse) {
				/* HICANN configuration */
				i += group_len;

				offset += 2;
				offset += 2;
				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_fpgacount, tvb, offset* 8, 14, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_fpgatime,  tvb, offset* 8+1, 14, ENC_BIG_ENDIAN);
				offset += 2;

				for (ii = 0; ii < group_len; ii++) {
					tmp64    = tvb_get_ntoh64(tvb, offset) & 0x1ffffFFFFffff; // lower 49 bits are OCP payload
					proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_dnc, tvb, offset*8, 2, ENC_BIG_ENDIAN);
					proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_dest, tvb, offset*8+2, 3, ENC_BIG_ENDIAN);
					offset += 1; // 1 byte => 63..56 taken, now MSB == bit 55
					proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_tag, tvb, offset*8+5, 2, ENC_BIG_ENDIAN); // bit 49
					proto_tree_add_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_write, tvb, offset, 1, ENC_BIG_ENDIAN); // bit 48
					proto_tree_add_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_read, tvb, offset+3, 1, ENC_BIG_ENDIAN);
					proto_tree_add_uint64_format(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_hicanncfgdata_payload, tvb, offset, 7, tmp64, "HICANN CfgData Payload: 0x%llx", (long long unsigned)tmp64);
					offset += 7;
				}
			} else if (!is_data && is_overflow) {
				i += 1;
				/* Timestamp Overflow Indicator */
				proto_tree_add_bits_item(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_overflow, tvb, (offset+4)*8, 30, ENC_BIG_ENDIAN);
				offset += 8;
			} else if (!is_data && !is_overflow) {
				i += 1;
				/* Wait for next experiment trigger */
				proto_tree_add_string(fpgaplayback_tree, hf_nmpm1fcp_pdu_fpgaplayback_trigger, tvb, offset*8, 64, "Wait for next experiment");
				offset += 8;
			} else {
				// WTF
			}
		}
	}
}

static void
dissect_nmpm1fcp_hicanncfgdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	guint16 len = tvb_get_ntohs(tvb, 2);
	guint64 tmp64 = 0;
	gint offset = 4;
	size_t ii = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HICANNCONFIG");

	//col_append_fstr(pinfo->cinfo, COL_INFO, " DNC %u HICANN %u", (unsigned)dnc, (unsigned)hicann);

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *hicanncfgdata_tree = NULL;

		ti = proto_tree_add_item(tree, proto_nmpm1fcp, tvb, 0, -1, ENC_NA); // consume all, nothing encapsulated here
		hicanncfgdata_tree = proto_item_add_subtree(ti, ett_nmpm1fcp);

		for (ii = 0; ii < len; ii++) {
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_dnc, tvb, offset*8, 2, ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_hicann, tvb, offset*8+2, 3, ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_tag,  tvb, offset*8+2+3+8, 2, ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_write,  tvb, offset*8+2+3+9+1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_read,  tvb, (offset+4)*8, 1, ENC_BIG_ENDIAN);
			tmp64    = tvb_get_ntoh64(tvb, offset) & 0xFFFffffFFFFffff; // remaining 49 bits
			proto_tree_add_uint64_format(hicanncfgdata_tree, hf_nmpm1fcp_pdu_hicanncfgdata_payload, tvb, offset, 8, tmp64, "HICANN CfgData Payload: 0x%llx", (long long unsigned)tmp64);
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
			tmp = (tvb_get_guint8(tvb, offset) >> 5) & 0x7;
			switch (tmp) {
				case 0: // FM off
				case 1: // FM on
					proto_tree_add_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_overflow, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_invalid, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_fm, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_bits_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_label,     tvb, offset*8+5, 12, ENC_BIG_ENDIAN);
					proto_tree_add_bits_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_timestamp, tvb, offset*8+5+12, 15, ENC_BIG_ENDIAN);
					offset += 4;
					break;
				case 2: // just padding in overflow marker... dont tell the user...
				case 3:
					proto_tree_add_text(fpgatracedata_tree, tvb, offset, 4, "padding");
					offset += 4;
					break;
				default:
					//overflow because higher bits high
					proto_tree_add_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_overflow, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_bits_item(fpgatracedata_tree, hf_nmpm1fcp_pdu_fpgatracedata_overflows, tvb, offset*8+1, 31, ENC_BIG_ENDIAN);
					offset += 4;
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
