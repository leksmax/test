// Copyright (c) 2014 Qualcomm Atheros, Inc.  All rights reserved.
// $ATH_LICENSE_HW_HDR_C$
//
// DO NOT EDIT!  This file is automatically generated
//               These definitions are tied to a particular hardware layout


#ifndef _DELETE_MPDU_CMD_H_
#define _DELETE_MPDU_CMD_H_
#if !defined(__ASSEMBLER__)
#endif

// ################ START SUMMARY #################
//
//	Dword	Fields
//	0	cmd_id[3:0], reserved_0a[7:4], sw_cmd_ref[15:8], qid[29:16], reserved_0b[31:30]
//	1	start_seq_num[11:0], reserved_0c[31:12]
//	2	delete_bitmap_31_0[31:0]
//	3	delete_bitmap_63_32[31:0]
//
// ################ END SUMMARY #################

#define NUM_OF_DWORDS_DELETE_MPDU_CMD 4

struct delete_mpdu_cmd {
    volatile uint32_t cmd_id                          :  4, //[3:0]
                      reserved_0a                     :  4, //[7:4]
                      sw_cmd_ref                      :  8, //[15:8]
                      qid                             : 14, //[29:16]
                      reserved_0b                     :  2; //[31:30]
    volatile uint32_t start_seq_num                   : 12, //[11:0]
                      reserved_0c                     : 20; //[31:12]
    volatile uint32_t delete_bitmap_31_0              : 32; //[31:0]
    volatile uint32_t delete_bitmap_63_32             : 32; //[31:0]
};

/*

cmd_id
			
			Command ID:
			
			Set to 0x1 (which indicates Delete MPDU cmd) <legal 1>

reserved_0a
			
			FW will set to 0, MAC will ignore.  <legal 0>

sw_cmd_ref
			
			SW command reference. A field only used by SW and
			ignored by QM. This field can aid SW to map this command to
			its originator and is used for tracking/debugging purposes. 
			<legal all>

qid
			
			Queue ID:  The Index of the MPDU transmit queue from
			which the frame are deleted

reserved_0b
			
			FW will set to 0, MAC will ignore.  <legal 0>

start_seq_num
			
			Indicates the start sequence number of delete bitmap. 
			
			<legal all>

reserved_0c
			
			FW will set to 0, MAC will ignore.  <legal 0>

delete_bitmap_31_0
			
			Each bit in the bitmap corresponds to a frame in the
			transmit queue. Bit 0 corresponds with the frame at the head
			of the queue, bit 1 with the next frame, etc. If the number
			of frames in the queue is less then the number of bits in
			the bitmap, the setting of the bitmap bits with no frame is
			ignored.
			
			Bit value 0: Do not remove the corresponding MPDU frame
			from the queue
			
			Bit value 1: Remove the corresponding MPDU frame from
			the queue
			
			<legal all>

delete_bitmap_63_32
			
			Each bit in the bitmap corresponds to a frame in the
			transmit queue. Bit 0 corresponds with the frame at the 32nd
			location (counting from the head)  of the queue, bit 1 with
			the 33rd frame, etc. If the number of frames in the queue is
			less then the number of bits in the bitmap, the setting of
			the bitmap bits with no frame is ignored.
			
			Bit value 0: Do not remove the corresponding MPDU frame
			from the queue
			
			Bit value 1: Remove the corresponding MPDU frame from
			the queue
			
			<legal all>
*/


/* Description		DELETE_MPDU_CMD_0_CMD_ID
			
			Command ID:
			
			Set to 0x1 (which indicates Delete MPDU cmd) <legal 1>
*/
#define DELETE_MPDU_CMD_0_CMD_ID_OFFSET                              0x00000000
#define DELETE_MPDU_CMD_0_CMD_ID_LSB                                 0
#define DELETE_MPDU_CMD_0_CMD_ID_MASK                                0x0000000f

/* Description		DELETE_MPDU_CMD_0_RESERVED_0A
			
			FW will set to 0, MAC will ignore.  <legal 0>
*/
#define DELETE_MPDU_CMD_0_RESERVED_0A_OFFSET                         0x00000000
#define DELETE_MPDU_CMD_0_RESERVED_0A_LSB                            4
#define DELETE_MPDU_CMD_0_RESERVED_0A_MASK                           0x000000f0

/* Description		DELETE_MPDU_CMD_0_SW_CMD_REF
			
			SW command reference. A field only used by SW and
			ignored by QM. This field can aid SW to map this command to
			its originator and is used for tracking/debugging purposes. 
			<legal all>
*/
#define DELETE_MPDU_CMD_0_SW_CMD_REF_OFFSET                          0x00000000
#define DELETE_MPDU_CMD_0_SW_CMD_REF_LSB                             8
#define DELETE_MPDU_CMD_0_SW_CMD_REF_MASK                            0x0000ff00

/* Description		DELETE_MPDU_CMD_0_QID
			
			Queue ID:  The Index of the MPDU transmit queue from
			which the frame are deleted
*/
#define DELETE_MPDU_CMD_0_QID_OFFSET                                 0x00000000
#define DELETE_MPDU_CMD_0_QID_LSB                                    16
#define DELETE_MPDU_CMD_0_QID_MASK                                   0x3fff0000

/* Description		DELETE_MPDU_CMD_0_RESERVED_0B
			
			FW will set to 0, MAC will ignore.  <legal 0>
*/
#define DELETE_MPDU_CMD_0_RESERVED_0B_OFFSET                         0x00000000
#define DELETE_MPDU_CMD_0_RESERVED_0B_LSB                            30
#define DELETE_MPDU_CMD_0_RESERVED_0B_MASK                           0xc0000000

/* Description		DELETE_MPDU_CMD_1_START_SEQ_NUM
			
			Indicates the start sequence number of delete bitmap. 
			
			<legal all>
*/
#define DELETE_MPDU_CMD_1_START_SEQ_NUM_OFFSET                       0x00000004
#define DELETE_MPDU_CMD_1_START_SEQ_NUM_LSB                          0
#define DELETE_MPDU_CMD_1_START_SEQ_NUM_MASK                         0x00000fff

/* Description		DELETE_MPDU_CMD_1_RESERVED_0C
			
			FW will set to 0, MAC will ignore.  <legal 0>
*/
#define DELETE_MPDU_CMD_1_RESERVED_0C_OFFSET                         0x00000004
#define DELETE_MPDU_CMD_1_RESERVED_0C_LSB                            12
#define DELETE_MPDU_CMD_1_RESERVED_0C_MASK                           0xfffff000

/* Description		DELETE_MPDU_CMD_2_DELETE_BITMAP_31_0
			
			Each bit in the bitmap corresponds to a frame in the
			transmit queue. Bit 0 corresponds with the frame at the head
			of the queue, bit 1 with the next frame, etc. If the number
			of frames in the queue is less then the number of bits in
			the bitmap, the setting of the bitmap bits with no frame is
			ignored.
			
			Bit value 0: Do not remove the corresponding MPDU frame
			from the queue
			
			Bit value 1: Remove the corresponding MPDU frame from
			the queue
			
			<legal all>
*/
#define DELETE_MPDU_CMD_2_DELETE_BITMAP_31_0_OFFSET                  0x00000008
#define DELETE_MPDU_CMD_2_DELETE_BITMAP_31_0_LSB                     0
#define DELETE_MPDU_CMD_2_DELETE_BITMAP_31_0_MASK                    0xffffffff

/* Description		DELETE_MPDU_CMD_3_DELETE_BITMAP_63_32
			
			Each bit in the bitmap corresponds to a frame in the
			transmit queue. Bit 0 corresponds with the frame at the 32nd
			location (counting from the head)  of the queue, bit 1 with
			the 33rd frame, etc. If the number of frames in the queue is
			less then the number of bits in the bitmap, the setting of
			the bitmap bits with no frame is ignored.
			
			Bit value 0: Do not remove the corresponding MPDU frame
			from the queue
			
			Bit value 1: Remove the corresponding MPDU frame from
			the queue
			
			<legal all>
*/
#define DELETE_MPDU_CMD_3_DELETE_BITMAP_63_32_OFFSET                 0x0000000c
#define DELETE_MPDU_CMD_3_DELETE_BITMAP_63_32_LSB                    0
#define DELETE_MPDU_CMD_3_DELETE_BITMAP_63_32_MASK                   0xffffffff


#endif // _DELETE_MPDU_CMD_H_
