// This is an auto-generated file.
// DON'T manually modify the file but use cmdRspDictGenSrc.exe.

#include "tlv2Inc.h"

//Commands
CMD_DICT CmdDict[] = {
    {CMD_SYNC_RAND},
    {CMD_TPCCAL_RAND},
    {CMD_TPCCALRSP_RAND},
    {CMD_TPCCALPWR_RAND},
    {CMD_TPCCALDATA_RAND},
    {CMD_RXGAINCAL_RAND},
    {CMD_RXGAINCALRSP_RAND},
    {CMD_RXGAINCAL_SIGL_DONE_RAND},
    {CMD_RXGAINCALRSP_DONE_RAND},
    {CMD_REGREAD_RAND},
    {CMD_REGREADRSP_RAND},
    {CMD_REGWRITE_RAND},
    {CMD_REGWRITERSP_RAND},
    {CMD_BASICRSP_RAND},
    {CMD_TX_RAND},
    {CMD_TXSTATUS_RAND},
    {CMD_TXSTATUSRSP_RAND},
    {CMD_RX_RAND},
    {CMD_RXSTATUS_RAND},
    {CMD_RXSTATUSRSP_RAND},
    {CMD_HWCAL_RAND},
    {CMD_RXRSP_RAND},
    {CMD_XTALCALPROC_RAND},
    {CMD_XTALCALPROCRSP_RAND},
    {CMD_READCUSTOTPSPACE_RAND},
    {CMD_READCUSTOTPSPACERSP_RAND},
    {CMD_WRITECUSTOTPSPACE_RAND},
    {CMD_WRITECUSTOTPSPACERSP_RAND},
    {CMD_GETCUSTOTPSIZE_RAND},
    {CMD_GETCUSTOTPSIZERSP_RAND},
    {CMD_GETDPDCOMPLETE_RAND},
    {CMD_GETDPDCOMPLETERSP_RAND},
    {CMD_GETTGTPWR_RAND},
    {CMD_GETTGTPWRRSP_RAND},
    {CMD_SETPCIECONFIGPARAMS_RAND},
    {CMD_SETPCIECONFIGPARAMSRSP_RAND},
    {CMD_COMMITOTPSTREAM_RAND},
    {CMD_COMMITOTPSTREAMRSP_RAND},
    {CMD_SETREGDMN_RAND},
    {CMD_SETREGDMNRSP_RAND},
    {CMD_MEMWRITE_RAND},
    {CMD_MEMWRITERSP_RAND},
    {CMD_MEMREAD_RAND},
    {CMD_MEMREADRSP_RAND},
    {CMD_CONFIG_RAND},
    {CMD_DPDLOOPBACKTIMING_RAND},
    {CMD_DPDLOOPBACKTIMINGRSP_RAND},
    {CMD_DPDLOOPBACKATTN_RAND},
    {CMD_DPDLOOPBACKATTNRSP_RAND},
    {CMD_DPDTRAININGQUALITY_RAND},
    {CMD_DPDTRAININGQUALITYRSP_RAND},
    {CMD_DPDAGC2PWR_RAND},
    {CMD_DPDAGC2PWRRSP_RAND},
    {CMD_LMHWCAL_RAND},
    {CMD_LMHWCALRSP_RAND},
    {CMD_LMTX_RAND},
    {CMD_MORESEGMENT_RAND},
    {CMD_MORESEGMENTRSP_RAND},
    {CMD_LMRX_RAND},
    {CMD_ADCCAPTURE_RAND},
    {CMD_ADCCAPTURERSP_RAND},
    {CMD_GENWAVEFORM_RAND},
    {CMD_GENWAVEFORMRSP_RAND},
    {CMD_ENABLEDFE_RAND},
    {CMD_ENABLEDFERSP_RAND},
    {CMD_CALCALTIME_RAND},
    {CMD_CALCALTIMERSP_RAND},
    {CMD_RXDCOGROUP_RAND},
    {CMD_RXDCOGROUPRSP_RAND},
    {CMD_SETPHYRFMODE_RAND},
    {CMD_LMCHANNELLIST_RAND},
    {CMD_LMCHANNELLISTRSP_RAND},
    {CMD_LMTXINIT_RAND},
    {CMD_LMTXINITRSP_RAND},
    {CMD_LMGO_RAND},
    {CMD_LMGORSP_RAND},
    {CMD_LMQUERY_RAND},
    {CMD_LMQUERYRSP_RAND},
    {CMD_GENERICUTFCMD_RAND},
    {CMD_GENERICUTFCMDRSP_RAND},
	{CMD_LMRXINIT_RAND},
    {CMD_LMRXINITRSP_RAND},
    {CMD_NOISEFLOORREAD_RAND},
    {CMD_NOISEFLOORREADRSP_RAND},
};

int MaxCmdDictEntries = (sizeof(CmdDict) / sizeof(CMD_DICT));

// Global parameter list
#include "src/u8Array.s"
#include "src/u16Array.s"
#include "src/u32Array.s"
#include "src/s8Array.s"
#include "src/s16Array.s"
#include "src/s32Array.s"
#include "src/u8Data.s"

//Parameters
PARM_DICT ParmDict[] = {
    {PARM_RESERVED_RAND, {(A_UINT32)255}, 0, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_RADIOID_RAND, {(A_UINT32)0}, 0, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_NUMFREQ2G_RAND, {(A_UINT32)3}, 2, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_FREQ2G_RAND, {(A_UINTL)PARM_FREQ2GArray}, 15, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_NUMFREQ5G_RAND, {(A_UINT32)8}, 13, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_FREQ5G_RAND, {(A_UINTL)PARM_FREQ5GArray}, 22, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_NUMCHAIN_RAND, {(A_UINT32)2}, 16, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_NUMCALPT2G_RAND, {(A_UINT32)13}, 11, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_MEASUREDPWR_RAND, {(A_UINTL)PARM_MEASUREDPWRArray}, 1, DATATYPE(PARM_S16, TYPE_ARRAY)},
    {PARM_NUMMEASUREDPWR_RAND, {(A_UINT32)32}, 11, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CALDATA2G_RAND, {(A_UINTL)NULL}, 6, DATATYPE(PARM_DATA_256, TYPE_DATA)},
    {PARM_CALDATA2GOFFSET_RAND, {(A_UINT32)10}, 17, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_CALDATA5G_RAND, {(A_UINTL)NULL}, 27, DATATYPE(PARM_DATA_512, TYPE_DATA)},
    {PARM_CALDATA5GOFFSET_RAND, {(A_UINT32)20}, 6, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_CALDATA2GLENGTH_RAND, {(A_UINT32)33}, 28, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_CALDATA5GLENGTH_RAND, {(A_UINT32)55}, 17, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_CALPT2G_RAND, {(A_UINTL)parm_calPt}, 11, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_NUMTXGAINS2G_RAND, {(A_UINT32)13}, 11, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_TXGAINS2G_RAND, {(A_UINTL)parm_txGains}, 13, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_NUMDACGAINS2G_RAND, {(A_UINT32)13}, 9, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_DACGAINS2G_RAND, {(A_UINTL)parm_dacGains}, 11, DATATYPE(PARM_U8, TYPE_ARRAY)}, 
    {PARM_NUMPACFG2G_RAND, {(A_UINT32)13}, 18, DATATYPE(PARM_U8, TYPE_SINGULAR)},  
    {PARM_PACFG2G_RAND, {(A_UINTL)parm_paCfg}, 12, DATATYPE(PARM_U8, TYPE_ARRAY)}, 
    {PARM_CHAINMASKS_RAND, {(A_UINTL)parm_chainMasks}, 2, DATATYPE(PARM_U8, TYPE_ARRAY)}, 
    {PARM_NUMCALPT5G_RAND, {(A_UINT32)13}, 2, DATATYPE(PARM_U8, TYPE_SINGULAR)}, 
    {PARM_CALPT5G_RAND, {(A_UINTL)parm_calPt}, 32, DATATYPE(PARM_U8, TYPE_ARRAY)}, 
    {PARM_NUMTXGAINS5G_RAND, {(A_UINT32)13}, 32, DATATYPE(PARM_U8, TYPE_SINGULAR)}, 
    {PARM_TXGAINS5G_RAND, {(A_UINTL)parm_txGains5G}, 34, DATATYPE(PARM_U8, TYPE_ARRAY)}, 
    {PARM_NUMDACGAINS5G_RAND, {(A_UINT32)13}, 30, DATATYPE(PARM_U8, TYPE_SINGULAR)}, 
    {PARM_DACGAINS5G_RAND, {(A_UINTL)parm_dacGains5G}, 32, DATATYPE(PARM_U8, TYPE_ARRAY)}, 
    {PARM_NUMPACFG5G_RAND, {(A_UINT32)13}, 3, DATATYPE(PARM_U8, TYPE_SINGULAR)}, 
    {PARM_PACFG5G_RAND, {(A_UINTL)parm_paCfg5G}, 33, DATATYPE(PARM_U8, TYPE_ARRAY)}, 
    {PARM_MISCFLAGS_RAND, {(A_UINT32)0x80}, 27, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_TGTPWR2G_RAND, {(A_UINTL)parm_tgtPwr2G}, 19, DATATYPE(PARM_S16, TYPE_ARRAY)},
    {PARM_TGTPWR5G_RAND, {(A_UINTL)parm_tgtPwr5G}, 4, DATATYPE(PARM_S16, TYPE_ARRAY)},
    {PARM_CALDATA2G_CLPC_RAND, {(A_UINTL)NULL}, 33, DATATYPE(PARM_DATA_256, TYPE_DATA)},
    {PARM_CALDATA2GOFFSET_CLPC_RAND, {(A_UINT32)40}, 10, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_CALDATA5G_CLPC_RAND, {(A_UINTL)NULL}, 0, DATATYPE(PARM_DATA_512, TYPE_DATA)},
    {PARM_CALDATA5GOFFSET_CLPC_RAND, {(A_UINT32)20}, 1, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_CALDATA2GLENGTH_CLPC_RAND, {(A_UINT32)33}, 11, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_CALDATA5GLENGTH_CLPC_RAND, {(A_UINT32)55}, 6, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_STATUS_RAND, {(A_UINT32)0}, 5, DATATYPE(PARM_U8, TYPE_SINGULAR)}, 
    {PARM_BAND_RAND, {(A_UINT32)0}, 7, DATATYPE(PARM_U8, TYPE_SINGULAR)},  
    {PARM_REFISS_RAND, {(A_UINT32)0}, 17, DATATYPE(PARM_S8, TYPE_SINGULAR)},      
    {PARM_RATE_RAND, {(A_UINT32)0}, 29, DATATYPE(PARM_U8, TYPE_SINGULAR)},   
    {PARM_BANDWIDTH_RAND, {(A_UINT32)0}, 27, DATATYPE(PARM_U8, TYPE_SINGULAR)},    
    {PARM_CHANIDX_RAND, {(A_UINT32)0}, 11, DATATYPE(PARM_U8, TYPE_SINGULAR)},    
    {PARM_CHAINIDX_RAND, {(A_UINT32)0}, 7, DATATYPE(PARM_U8, TYPE_SINGULAR)},  	
    {PARM_NUMPACKETS_RAND, {(A_UINT32)100}, 15, DATATYPE(PARM_U16, TYPE_SINGULAR)}, 
    {PARM_CHAIN2CAL_RAND, {(A_UINT32)0x0}, 31, DATATYPE(PARM_U8, TYPE_SINGULAR)},  
    {PARM_REGADDRESS_RAND, {(A_UINT32)0x0}, 24, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_REGVALUE_RAND, {(A_UINT32)0x0}, 6, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_CMDID_RAND, {(A_UINT32)0}, 27, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_TXMODE_RAND, {(A_UINT32)2}, 32, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_FREQ_RAND, {(A_UINT32)2412}, 18, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_CHAINMASK_RAND, {(A_UINT32)0x5}, 10, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_WLANMODE_RAND, {(A_UINT32)1}, 17, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_GI_RAND, {(A_UINT32)0}, 20, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_ANTENNA_RAND, {(A_UINT32)0}, 0, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_ENANI_RAND, {(A_UINT32)0}, 17, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_SCRAMBLEROFF_RAND, {(A_UINT32)0}, 7, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_AIFSN_RAND, {(A_UINT32)0}, 20, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_BROADCAST_RAND, {(A_UINT32)0}, 21, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_AGG_RAND, {(A_UINT32)1}, 18, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_SHORTGUARD_RAND, {(A_UINT32)0}, 25, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_DUTYCYCLE_RAND, {(A_UINT32)0}, 33, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_FLAGS_RAND, {(A_UINT32)0x0}, 3, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_IR_RAND, {(A_UINT32)0}, 12, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_PKTSZ_RAND, {(A_UINT32)0}, 24, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_DATAPATTERN_RAND, {(A_UINTL)PARM_DATAPATTERNArray}, 27, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_TXNUMPACKETS_RAND, {(A_UINT32)0}, 31, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_TXPATTERN_RAND, {(A_UINT32)0}, 28, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_NPATTERN_RAND, {(A_UINT32)0}, 33, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_TPCM_RAND, {(A_UINT32)0}, 18, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_GAINIDX_RAND, {(A_UINT32)15}, 1, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_DACGAIN_RAND, {(A_UINT32)0}, 35, DATATYPE(PARM_S8, TYPE_SINGULAR)},
    {PARM_DACGAINEND_RAND, {(A_UINT32)0}, 9, DATATYPE(PARM_S8, TYPE_SINGULAR)},
    {PARM_DACGAINSTEP_RAND, {(A_UINT32)0}, 13, DATATYPE(PARM_S8, TYPE_SINGULAR)},
    {PARM_PACONFIG_RAND, {(A_UINT32)0}, 30, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_PACONFIGEND_RAND, {(A_UINT32)0}, 8, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_PACONFIGSTEP_RAND, {(A_UINT32)1}, 12, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_PAD3_RAND, {(A_UINTL)PARM_PAD3Array}, 9, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_RATEMASK_RAND, {(A_UINTL)PARM_RATEMASKArray}, 2, DATATYPE(PARM_U32, TYPE_ARRAY)},
    {PARM_RATEMASK11AC_RAND, {(A_UINTL)PARM_RATEMASK11ACArray}, 13, DATATYPE(PARM_U32, TYPE_ARRAY)},
    {PARM_PWRGAINSTART_RAND, {(A_UINTL)PARM_PWRGAINSTARTArray}, 4, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_PWRGAINEND_RAND, {(A_UINTL)PARM_PWRGAINENDArray}, 24, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_PWRGAINSTEP_RAND, {(A_UINTL)PARM_PWRGAINSTEPArray}, 26, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_PWRGAINSTART11AC_RAND, {(A_UINTL)PARM_PWRGAINSTART11ACArray}, 5, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_PWRGAINEND11AC_RAND, {(A_UINTL)PARM_PWRGAINEND11ACArray}, 21, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_PWRGAINSTEP11AC_RAND, {(A_UINTL)PARM_PWRGAINSTEP11ACArray}, 23, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_BSSID_RAND, {(A_UINTL)PARM_BSSIDArray}, 15, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_TXSTATION_RAND, {(A_UINTL)PARM_TXSTATIONArray}, 10, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_RXSTATION_RAND, {(A_UINTL)PARM_RXSTATIONArray}, 1, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_NUMOFREPORTS_RAND, {(A_UINT32)0}, 28, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_THERMCAL_RAND, {(A_UINT32)0}, 1, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_PDADC_RAND, {(A_UINT32)0}, 10, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_PACFG_RAND, {(A_UINT32)0}, 10, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_TOTALPACKETS_RAND, {(A_UINT32)0}, 15, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_GOODPACKETS_RAND, {(A_UINT32)0}, 13, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_UNDERRUNS_RAND, {(A_UINT32)0}, 25, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_OTHERERROR_RAND, {(A_UINT32)0}, 28, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_EXCESSRETRIES_RAND, {(A_UINT32)0}, 34, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_RATEBIT_RAND, {(A_UINT32)0}, 27, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_SHORTRETRY_RAND, {(A_UINT32)0}, 15, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_LONGRETRY_RAND, {(A_UINT32)0}, 30, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_STARTTIME_RAND, {(A_UINT32)0}, 20, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_ENDTIME_RAND, {(A_UINT32)0}, 12, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_BYTECOUNT_RAND, {(A_UINT32)0}, 2, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_DONTCOUNT_RAND, {(A_UINT32)0}, 24, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_RSSI_RAND, {(A_UINT32)0}, 31, DATATYPE(PARM_S32, TYPE_SINGULAR)},
    {PARM_RSSIC_RAND, {(A_UINTL)PARM_RSSICArray}, 1, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_RSSIE_RAND, {(A_UINTL)PARM_RSSIEArray}, 20, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_RXMODE_RAND, {(A_UINT32)1}, 18, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_ACK_RAND, {(A_UINT32)1}, 35, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_LPL_RAND, {(A_UINT32)0}, 1, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_ANTSWITCH1_RAND, {(A_UINT32)0}, 30, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_ANTSWITCH2_RAND, {(A_UINT32)0}, 15, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_PAD2_RAND, {(A_UINTL)PARM_PAD2Array}, 11, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_SPECTRALSCAN_RAND, {(A_UINT32)0}, 34, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_NOISEFLOOR_RAND, {(A_UINT32)0}, 6, DATATYPE(PARM_S16, TYPE_SINGULAR)},
    {PARM_REGDMN_RAND, {(A_UINTL)PARM_REGDMNArray}, 24, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_EXPECTEDPKTS_RAND, {(A_UINT32)1}, 12, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_OTPWRITEFLAG_RAND, {(A_UINT32)0x0}, 35, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_STAADDR_RAND, {(A_UINTL)PARM_STAADDRArray}, 26, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_BTADDR_RAND, {(A_UINTL)PARM_BTADDRArray}, 27, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_CRCPACKETS_RAND, {(A_UINT32)0}, 9, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_DECRYPERRORS_RAND, {(A_UINT32)0}, 25, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_BADRSSI_RAND, {(A_UINT32)0}, 19, DATATYPE(PARM_S32, TYPE_SINGULAR)},
    {PARM_BADRSSIC_RAND, {(A_UINTL)PARM_BADRSSICArray}, 19, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_BADRSSIE_RAND, {(A_UINTL)PARM_BADRSSIEArray}, 34, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_EVM_RAND, {(A_UINT32)0}, 2, DATATYPE(PARM_S32, TYPE_SINGULAR)},
    {PARM_BADEVM_RAND, {(A_UINTL)PARM_BADEVMArray}, 27, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_STOPTX_RAND, {(A_UINT32)1}, 31, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_NEEDREPORT_RAND, {(A_UINT32)1}, 28, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_STOPRX_RAND, {(A_UINT32)0}, 13, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CALOP_RAND, {(A_UINT32)0}, 14, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_LOOPCNT_RAND, {(A_UINT32)1}, 21, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_RSSIINDBM1_RAND, {(A_UINT32)0}, 26, DATATYPE(PARM_S32, TYPE_SINGULAR)},
    {PARM_SECERRPKT_RAND, {(A_UINT32)0}, 30, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_RATECNT_RAND, {(A_UINTL)NULL}, 24, DATATYPE(PARM_U32, TYPE_ARRAY)},
    {PARM_RATECNT11AC_RAND, {(A_UINTL)NULL}, 23, DATATYPE(PARM_U32, TYPE_ARRAY)},
    {PARM_LOOPBACK_RAND, {(A_UINT32)0}, 11, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_SAVECAL_RAND, {(A_UINT32)0}, 0, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_NOISEFLOORCAL_RAND, {(A_UINT32)0}, 0, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CAPIN_RAND, {(A_UINT32)45}, 25, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CAPOUT_RAND, {(A_UINT32)15}, 21, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CTRLFLAG_RAND, {(A_UINT32)0}, 17, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CAPVALMIN_RAND, {(A_UINT32)0}, 30, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CAPVALMAX_RAND, {(A_UINT32)0}, 21, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_PLLLOCKED_RAND, {(A_UINT32)0}, 33, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CUSTDATA_RAND, {(A_UINTL)NULL}, 5, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_OFFSETADDR_RAND, {(A_UINT32)0}, 28, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CUSTDATASIZE_RAND, {(A_UINT32)0}, 24, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_WRITESTATUS_RAND, {(A_UINT32)0}, 7, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_OTPCUSTSIZE_RAND, {(A_UINT32)0}, 17, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_DPDCOMPLETE_RAND, {(A_UINT32)0}, 11, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_USERMODE_RAND, {(A_UINT32)0}, 8, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_TGTPWR_RAND, {(A_UINT32)0}, 2, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_PCIEADDR_RAND, {(A_UINT32)0}, 20, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_PCIEVALUE_RAND, {(A_UINT32)0}, 29, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_OPERATION_RAND, {(A_UINT32)0}, 31, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_SIZE_RAND, {(A_UINT32)0}, 8, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_MEMADDRESS_RAND, {(A_UINT32)0x0}, 7, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_NUMBYTES_RAND, {(A_UINT32)0}, 10, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_MEMVALUE_RAND, {(A_UINTL)NULL}, 2, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_VALUETYPE_RAND, {(A_UINT32)1}, 24, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_PHYID_RAND, {(A_UINT32)0}, 2, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CALOPFLAG_RAND, {(A_UINT32)0x0}, 23, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CALOPORDER_RAND, {(A_UINTL)NULL}, 7, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_PAD1_RAND, {(A_UINT32)0x0}, 9, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_RATESHORTG_RAND, {(A_UINTL)NULL}, 22, DATATYPE(PARM_U32, TYPE_ARRAY)},
    {PARM_RATESHORTG11AC_RAND, {(A_UINTL)NULL}, 17, DATATYPE(PARM_U32, TYPE_ARRAY)},
    {PARM_CHANFREQ_RAND, {(A_UINT32)0}, 3, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_DPDTIMINGIDX_RAND, {(A_UINT32)0}, 7, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_DPDLOOPBACKATTN_RAND, {(A_UINT32)0}, 35, DATATYPE(PARM_S8, TYPE_SINGULAR)},
    {PARM_GLUTIDX_RAND, {(A_UINT32)0}, 21, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_DPDTRAINQUAL_RAND, {(A_UINT32)0}, 15, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_DPDAGC2PWR_RAND, {(A_UINT32)0}, 10, DATATYPE(PARM_S8, TYPE_SINGULAR)},
    {PARM_FREQ2_RAND, {(A_UINT32)2412}, 11, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_RATEMASKAC160_RAND, {(A_UINT32)0x0}, 22, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_WLANMODEMASK_RAND, {(A_UINTL)PARM_WLANMODEMASKArray}, 26, DATATYPE(PARM_U32, TYPE_ARRAY)},
    {PARM_FLAG_RAND, {(A_UINT32)1}, 25, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_LM_RESVD0_RAND, {(A_UINTL)NULL}, 19, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_LM_FREQ_RAND, {(A_UINTL)PARM_LM_FREQArray}, 34, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_LM_FREQ2_RAND, {(A_UINTL)PARM_LM_FREQ2Array}, 7, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_LM_CHAINMASK_RAND, {(A_UINTL)PARM_LM_CHAINMASKArray}, 11, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_LM_BANDWIDTH_RAND, {(A_UINTL)PARM_LM_BANDWIDTHArray}, 1, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_LM_RESVD1_RAND, {(A_UINTL)NULL}, 29, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_RSSIINDBM_RAND, {(A_UINT32)0}, 9, DATATYPE(PARM_S32, TYPE_SINGULAR)},
    {PARM_PWRGAINSTARTAC160_RAND, {(A_UINTL)PARM_PWRGAINSTARTAC160Array}, 6, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_PWRGAINENDAC160_RAND, {(A_UINTL)PARM_PWRGAINENDAC160Array}, 4, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_PWRGAINSTEPAC160_RAND, {(A_UINTL)PARM_PWRGAINSTEPAC160Array}, 20, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_HWCALTIME_RAND, {(A_UINT32)0}, 20, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_WLANMODEMASKEXT_RAND, {(A_UINTL)PARM_WLANMODEMASKEXTArray}, 4, DATATYPE(PARM_U32, TYPE_ARRAY)},
    {PARM_LENGTH_RAND, {(A_UINT32)1024}, 14, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_ADCID_RAND, {(A_UINT32)0}, 19, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_MODEID_RAND, {(A_UINT32)0}, 5, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_DATAI_RAND, {(A_UINTL)NULL}, 33, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_DATAQ_RAND, {(A_UINTL)NULL}, 34, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_WAVEFORMINDEX_RAND, {(A_UINT32)0}, 11, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_ENABLE_RAND, {(A_UINT32)1}, 12, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_ELAPSEDTIME_RAND, {(A_UINT32)0}, 7, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_BBDCOCRANGE_RAND, {(A_UINT32)0}, 6, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_RFDCOCRANGE_RAND, {(A_UINT32)0}, 3, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_LPBKMODE_RAND, {(A_UINT32)0}, 13, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_RFFIRST_RAND, {(A_UINT32)0}, 16, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_INITLUT_RAND, {(A_UINT32)0}, 8, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_RFOVRD_RAND, {(A_UINT32)0}, 1, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_BBOVRD_RAND, {(A_UINT32)0}, 6, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_NUMGAIN_RAND, {(A_UINT32)0}, 20, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_CHAIN_RAND, {(A_UINT32)0}, 18, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_RFBB_RAND, {(A_UINT32)0}, 30, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_DEPTH_RAND, {(A_UINT32)0}, 6, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_USECOSIMSETTING_RAND, {(A_UINT32)0}, 2, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_GAINLUT_RAND, {(A_UINTL)NULL}, 35, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_RFDOCLUT_RAND, {(A_UINTL)NULL}, 23, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_BBDOCLUT_RAND, {(A_UINTL)NULL}, 32, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_INPUTTABLE2SWPROCESSING_RAND, {(A_UINTL)NULL}, 13, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_SLEEPTIME_RAND, {(A_UINT32)0}, 32, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_THRESHOLD_RAND, {(A_UINT32)0}, 10, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_PADDING_RAND, {(A_UINT32)0}, 13, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_EXECUTIONTIME_RAND, {(A_UINT32)0}, 30, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_DCOI_RAND, {(A_UINT32)0}, 2, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_DCOQ_RAND, {(A_UINT32)0}, 35, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_HWPROCESSEDTABLE_RAND, {(A_UINTL)NULL}, 1, DATATYPE(PARM_U16, TYPE_ARRAY)},    
    {PARM_CMDIDRXDCOGROUP_RAND, {(A_UINT32)0}, 24, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_NOISEFLOORARR_RAND, {(A_UINTL)NULL}, 10, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_PILOTEVM_RAND, {(A_UINTL)NULL}, 28, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_PHYRFMODE_RAND, {(A_UINT32)0}, 14, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_RATEBITINDEX_RAND, {(A_UINT32)8}, 10, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_TXPOWER_RAND, {(A_UINT32)0x1c}, 22, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_LM_FLAG_RAND, {(A_UINT32)0x1}, 8, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_LM_ITEMNUM_RAND, {(A_UINT32)1}, 14, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_LM_CBSTATE_RAND, {(A_UINTL)NULL}, 19, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_LM_TXPOWER_RAND, {(A_UINTL)NULL}, 28, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_LM_PHYID_RAND, {(A_UINTL)NULL}, 24, DATATYPE(PARM_U8, TYPE_ARRAY)},
    {PARM_LM_RATEINDEX_RAND, {(A_UINTL)NULL}, 21, DATATYPE(PARM_U16, TYPE_ARRAY)},
    {PARM_TOTALHWCALNUM_RAND, {(A_UINTL)1}, 18, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_TOTALITEMNUM_RAND, {(A_UINTL)1}, 21, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_LM_CMDID_RAND, {(A_UINT32)0}, 7, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_TIMEON_RAND, {(A_UINT32)800}, 2, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_TIMEOFF_RAND, {(A_UINT32)800}, 19, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_MEASUREMENT_RAND, {(A_UINT32)0}, 22, DATATYPE(PARM_U32, TYPE_SINGULAR)},
    {PARM_INPARAMS_RAND, {(A_UINTL)NULL}, 0, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_GENERICUTFCMDID_RAND, {(A_UINT32)0}, 9, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_GENERICUTFCMDDONE_RAND, {(A_UINT32)0}, 10, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_NUMGENERICUTFCMDRETDATA_RAND, {(A_UINT32)0}, 34, DATATYPE(PARM_U8, TYPE_SINGULAR)},
    {PARM_GENERICUTFCMDSTATUS_RAND, {(A_UINT32)0}, 0, DATATYPE(PARM_U16, TYPE_SINGULAR)},
    {PARM_GENERICUTFCMDRETDATA_RAND, {(A_UINTL)NULL}, 16, DATATYPE(PARM_S32, TYPE_ARRAY)},
    {PARM_NFVALUES_RAND, {(A_UINTL)NULL}, 14, DATATYPE(PARM_U32, TYPE_ARRAY)},
};

int MaxParmDictEntries = (sizeof(ParmDict) / sizeof(PARM_DICT));
