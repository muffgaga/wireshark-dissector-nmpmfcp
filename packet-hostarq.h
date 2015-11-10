static void dissect_hostarq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_nmpm1fcp_jtag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_nmpm1fcp_reset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_nmpm1fcp_sysstart(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_nmpm1fcp_hostarqreset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_nmpm1fcp_hostarqcfg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_nmpm1fcp_fpgaconfig(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_nmpm1fcp_fpgaplayback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_nmpm1fcp_hicanncfgdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_nmpm1fcp_fpgatracedata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
