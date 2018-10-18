// Copyright (c) 2014 Qualcomm Atheros, Inc.  All rights reserved.
// $ATH_LICENSE_HW_HDR_C$
//
// DO NOT EDIT!  This file is automatically generated
//               These definitions are tied to a particular hardware layout


#ifndef _PDG_BYPASS_H_
#define _PDG_BYPASS_H_
#if !defined(__ASSEMBLER__)
#endif

// ################ START SUMMARY #################
//
//	Dword	Fields
//	0	overwrite_scrambler_seed[0], overwrite_lower_only[1], overwrite_lsig_parity[2], overwrite_crc[3], mprot_scrambler_seed_mode[5:4], ppdu_scrambler_seed_mode[7:6], reserved_0[31:8]
//
// ################ END SUMMARY #################

#define NUM_OF_DWORDS_PDG_BYPASS 1

struct pdg_bypass {
    volatile uint32_t overwrite_scrambler_seed        :  1, //[0]
                      overwrite_lower_only            :  1, //[1]
                      overwrite_lsig_parity           :  1, //[2]
                      overwrite_crc                   :  1, //[3]
                      mprot_scrambler_seed_mode       :  2, //[5:4]
                      ppdu_scrambler_seed_mode        :  2, //[7:6]
                      reserved_0                      : 24; //[31:8]
};

/*

overwrite_scrambler_seed
			
			Field only valid in SW_transmit_mode.
			
			
			
			Only when mprot_scrambler_seed_mode and
			ppdu_scrambler_seed_mode are both zero, PDG will use
			overwrite_scrambler_seed and overwrite_lower_only fields.  
			
			
			
			When set, the PDG will insert/overwrite the scrambler
			seed value based on it's internal scrambler seed generation
			logic.
			
			
			
			<legal all>

overwrite_lower_only
			
			Field only valid in SW_transmit_mode.
			
			
			
			Field only valid when overwrite_scrambler_seed is set.
			
			
			
			When set, scrambler seed, low 4 bits will be
			overwritten. 
			
			When not set, PDG overwrites all 7 scrambler bits
			
			<legal all>

overwrite_lsig_parity
			
			Field only valid in SW_transmit_mode.
			
			
			
			When set, the PDG will insert/overwrite the lsig parity
			field with the proper value.
			
			
			
			<legal all>

overwrite_crc
			
			Field only valid in SW_transmit_mode.
			
			
			
			When set, the PDG will insert/overwrite the HT SIG, VHT
			SIG A, VHT SIG B CRC field with the proper value. 
			
			
			
			<legal all>

mprot_scrambler_seed_mode
			
			Field only valid in SW_transmit_mode.
			
			
			
			For the scrambler seed of mprot frame, 
			
			<enum 0 no_action> PDG doesn't touch at all
			
			<enum 1 generate_lower_4bit> PDG generates lower 4 bits
			
			<enum 2 generate_lower_5bit> PDG generates lower 5 bits
			
			<enum 3 generate_all_7bit> PDG generates lower all 7
			bits
			
			<legal all>

ppdu_scrambler_seed_mode
			
			Field only valid in SW_transmit_mode.
			
			
			
			For the scrambler seed of PPDU frame, 
			
			<enum 0 no_action> PDG doesn't touch at all
			
			<enum 1 generate_lower_4bit> PDG generates lower 4 bits
			
			<enum 2 generate_lower_5bit> PDG generates lower 5 bits
			
			<enum 3 generate_all_7bit> PDG generates lower all 7
			bits <legal all>

reserved_0
			
			<legal 0>
*/


/* Description		PDG_BYPASS_0_OVERWRITE_SCRAMBLER_SEED
			
			Field only valid in SW_transmit_mode.
			
			
			
			Only when mprot_scrambler_seed_mode and
			ppdu_scrambler_seed_mode are both zero, PDG will use
			overwrite_scrambler_seed and overwrite_lower_only fields.  
			
			
			
			When set, the PDG will insert/overwrite the scrambler
			seed value based on it's internal scrambler seed generation
			logic.
			
			
			
			<legal all>
*/
#define PDG_BYPASS_0_OVERWRITE_SCRAMBLER_SEED_OFFSET                 0x00000000
#define PDG_BYPASS_0_OVERWRITE_SCRAMBLER_SEED_LSB                    0
#define PDG_BYPASS_0_OVERWRITE_SCRAMBLER_SEED_MASK                   0x00000001

/* Description		PDG_BYPASS_0_OVERWRITE_LOWER_ONLY
			
			Field only valid in SW_transmit_mode.
			
			
			
			Field only valid when overwrite_scrambler_seed is set.
			
			
			
			When set, scrambler seed, low 4 bits will be
			overwritten. 
			
			When not set, PDG overwrites all 7 scrambler bits
			
			<legal all>
*/
#define PDG_BYPASS_0_OVERWRITE_LOWER_ONLY_OFFSET                     0x00000000
#define PDG_BYPASS_0_OVERWRITE_LOWER_ONLY_LSB                        1
#define PDG_BYPASS_0_OVERWRITE_LOWER_ONLY_MASK                       0x00000002

/* Description		PDG_BYPASS_0_OVERWRITE_LSIG_PARITY
			
			Field only valid in SW_transmit_mode.
			
			
			
			When set, the PDG will insert/overwrite the lsig parity
			field with the proper value.
			
			
			
			<legal all>
*/
#define PDG_BYPASS_0_OVERWRITE_LSIG_PARITY_OFFSET                    0x00000000
#define PDG_BYPASS_0_OVERWRITE_LSIG_PARITY_LSB                       2
#define PDG_BYPASS_0_OVERWRITE_LSIG_PARITY_MASK                      0x00000004

/* Description		PDG_BYPASS_0_OVERWRITE_CRC
			
			Field only valid in SW_transmit_mode.
			
			
			
			When set, the PDG will insert/overwrite the HT SIG, VHT
			SIG A, VHT SIG B CRC field with the proper value. 
			
			
			
			<legal all>
*/
#define PDG_BYPASS_0_OVERWRITE_CRC_OFFSET                            0x00000000
#define PDG_BYPASS_0_OVERWRITE_CRC_LSB                               3
#define PDG_BYPASS_0_OVERWRITE_CRC_MASK                              0x00000008

/* Description		PDG_BYPASS_0_MPROT_SCRAMBLER_SEED_MODE
			
			Field only valid in SW_transmit_mode.
			
			
			
			For the scrambler seed of mprot frame, 
			
			<enum 0 no_action> PDG doesn't touch at all
			
			<enum 1 generate_lower_4bit> PDG generates lower 4 bits
			
			<enum 2 generate_lower_5bit> PDG generates lower 5 bits
			
			<enum 3 generate_all_7bit> PDG generates lower all 7
			bits
			
			<legal all>
*/
#define PDG_BYPASS_0_MPROT_SCRAMBLER_SEED_MODE_OFFSET                0x00000000
#define PDG_BYPASS_0_MPROT_SCRAMBLER_SEED_MODE_LSB                   4
#define PDG_BYPASS_0_MPROT_SCRAMBLER_SEED_MODE_MASK                  0x00000030

/* Description		PDG_BYPASS_0_PPDU_SCRAMBLER_SEED_MODE
			
			Field only valid in SW_transmit_mode.
			
			
			
			For the scrambler seed of PPDU frame, 
			
			<enum 0 no_action> PDG doesn't touch at all
			
			<enum 1 generate_lower_4bit> PDG generates lower 4 bits
			
			<enum 2 generate_lower_5bit> PDG generates lower 5 bits
			
			<enum 3 generate_all_7bit> PDG generates lower all 7
			bits <legal all>
*/
#define PDG_BYPASS_0_PPDU_SCRAMBLER_SEED_MODE_OFFSET                 0x00000000
#define PDG_BYPASS_0_PPDU_SCRAMBLER_SEED_MODE_LSB                    6
#define PDG_BYPASS_0_PPDU_SCRAMBLER_SEED_MODE_MASK                   0x000000c0

/* Description		PDG_BYPASS_0_RESERVED_0
			
			<legal 0>
*/
#define PDG_BYPASS_0_RESERVED_0_OFFSET                               0x00000000
#define PDG_BYPASS_0_RESERVED_0_LSB                                  8
#define PDG_BYPASS_0_RESERVED_0_MASK                                 0xffffff00


#endif // _PDG_BYPASS_H_
