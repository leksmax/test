/*
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _PHY_SM1_REG_MAP_H_
#define _PHY_SM1_REG_MAP_H_


#ifndef __PHY_SM1_REG_MAP_BASE_ADDRESS
#define __PHY_SM1_REG_MAP_BASE_ADDRESS (0x11600)
#endif


// 0x84 (PHY_BB_SWITCH_TABLE_CHN_B1)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_LSB                        10
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_MSB                        11
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_MASK                       0xc00
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_GET(x)                     (((x) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_MASK) >> PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_LSB)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_SET(x)                     (((0 | (x)) << PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_LSB) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_MASK)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_B_1_RESET                      0x0
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_LSB                     8
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_MSB                     9
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_MASK                    0x300
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_GET(x)                  (((x) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_MASK) >> PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_LSB)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_SET(x)                  (((0 | (x)) << PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_LSB) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_MASK)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX12_1_RESET                   0x0
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_LSB                      6
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_MSB                      7
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_MASK                     0xc0
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_GET(x)                   (((x) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_MASK) >> PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_LSB)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_SET(x)                   (((0 | (x)) << PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_LSB) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_MASK)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_RX1_1_RESET                    0x0
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_LSB                        4
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_MSB                        5
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_MASK                       0x30
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_GET(x)                     (((x) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_MASK) >> PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_LSB)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_SET(x)                     (((0 | (x)) << PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_LSB) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_MASK)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_R_1_RESET                      0x0
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_LSB                        2
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_MSB                        3
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_MASK                       0xc
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_GET(x)                     (((x) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_MASK) >> PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_LSB)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_SET(x)                     (((0 | (x)) << PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_LSB) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_MASK)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_T_1_RESET                      0x0
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_LSB                     0
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_MSB                     1
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_MASK                    0x3
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_GET(x)                  (((x) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_MASK) >> PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_LSB)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_SET(x)                  (((0 | (x)) << PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_LSB) & PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_MASK)
#define PHY_BB_SWITCH_TABLE_CHN_B1_SWITCH_TABLE_IDLE_1_RESET                   0x0
#define PHY_BB_SWITCH_TABLE_CHN_B1_ADDRESS                                     (0x84 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_SWITCH_TABLE_CHN_B1_RSTMASK                                     0xfff
#define PHY_BB_SWITCH_TABLE_CHN_B1_RESET                                       0x0

// 0xd0 (PHY_BB_FCAL_2_B1)
#define PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_LSB                              20
#define PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_MSB                              24
#define PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_MASK                             0x1f00000
#define PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_GET(x)                           (((x) & PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_MASK) >> PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_LSB)
#define PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_SET(x)                           (((0 | (x)) << PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_LSB) & PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_MASK)
#define PHY_BB_FCAL_2_B1_FLC_CAP_VAL_STATUS_1_RESET                            0x0
#define PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_LSB                                  3
#define PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_MSB                                  7
#define PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_MASK                                 0xf8
#define PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_GET(x)                               (((x) & PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_MASK) >> PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_LSB)
#define PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_SET(x)                               (((0 | (x)) << PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_LSB) & PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_MASK)
#define PHY_BB_FCAL_2_B1_FLC_SW_CAP_VAL_1_RESET                                0xf
#define PHY_BB_FCAL_2_B1_ADDRESS                                               (0xd0 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_FCAL_2_B1_RSTMASK                                               0x1f000f8
#define PHY_BB_FCAL_2_B1_RESET                                                 0x78

// 0xd4 (PHY_BB_DFT_TONE_CTRL_B1)
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_LSB                        4
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_MSB                        12
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_MASK                       0x1ff0
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_GET(x)                     (((x) & PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_MASK) >> PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_LSB)
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_SET(x)                     (((0 | (x)) << PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_LSB) & PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_MASK)
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_FREQ_ANG_1_RESET                      0x0
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_LSB                         2
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_MSB                         3
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_MASK                        0xc
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_GET(x)                      (((x) & PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_MASK) >> PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_LSB)
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_SET(x)                      (((0 | (x)) << PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_LSB) & PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_MASK)
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_AMP_SEL_1_RESET                       0x0
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_LSB                              0
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_MSB                              0
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_MASK                             0x1
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_GET(x)                           (((x) & PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_MASK) >> PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_LSB)
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_SET(x)                           (((0 | (x)) << PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_LSB) & PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_MASK)
#define PHY_BB_DFT_TONE_CTRL_B1_DFT_TONE_EN_1_RESET                            0x0
#define PHY_BB_DFT_TONE_CTRL_B1_ADDRESS                                        (0xd4 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_DFT_TONE_CTRL_B1_RSTMASK                                        0x1ffd
#define PHY_BB_DFT_TONE_CTRL_B1_RESET                                          0x0

// 0xdc (PHY_BB_CL_MAP_0_B1)
#define PHY_BB_CL_MAP_0_B1_CL_MAP_0_LSB                                        0
#define PHY_BB_CL_MAP_0_B1_CL_MAP_0_MSB                                        31
#define PHY_BB_CL_MAP_0_B1_CL_MAP_0_MASK                                       0xffffffff
#define PHY_BB_CL_MAP_0_B1_CL_MAP_0_GET(x)                                     (((x) & PHY_BB_CL_MAP_0_B1_CL_MAP_0_MASK) >> PHY_BB_CL_MAP_0_B1_CL_MAP_0_LSB)
#define PHY_BB_CL_MAP_0_B1_CL_MAP_0_SET(x)                                     (((0 | (x)) << PHY_BB_CL_MAP_0_B1_CL_MAP_0_LSB) & PHY_BB_CL_MAP_0_B1_CL_MAP_0_MASK)
#define PHY_BB_CL_MAP_0_B1_CL_MAP_0_RESET                                      0x0
#define PHY_BB_CL_MAP_0_B1_ADDRESS                                             (0xdc + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_MAP_0_B1_RSTMASK                                             0xffffffff
#define PHY_BB_CL_MAP_0_B1_RESET                                               0x0

// 0xe0 (PHY_BB_CL_MAP_1_B1)
#define PHY_BB_CL_MAP_1_B1_CL_MAP_1_LSB                                        0
#define PHY_BB_CL_MAP_1_B1_CL_MAP_1_MSB                                        31
#define PHY_BB_CL_MAP_1_B1_CL_MAP_1_MASK                                       0xffffffff
#define PHY_BB_CL_MAP_1_B1_CL_MAP_1_GET(x)                                     (((x) & PHY_BB_CL_MAP_1_B1_CL_MAP_1_MASK) >> PHY_BB_CL_MAP_1_B1_CL_MAP_1_LSB)
#define PHY_BB_CL_MAP_1_B1_CL_MAP_1_SET(x)                                     (((0 | (x)) << PHY_BB_CL_MAP_1_B1_CL_MAP_1_LSB) & PHY_BB_CL_MAP_1_B1_CL_MAP_1_MASK)
#define PHY_BB_CL_MAP_1_B1_CL_MAP_1_RESET                                      0x0
#define PHY_BB_CL_MAP_1_B1_ADDRESS                                             (0xe0 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_MAP_1_B1_RSTMASK                                             0xffffffff
#define PHY_BB_CL_MAP_1_B1_RESET                                               0x0

// 0xe4 (PHY_BB_CL_MAP_2_B1)
#define PHY_BB_CL_MAP_2_B1_CL_MAP_2_LSB                                        0
#define PHY_BB_CL_MAP_2_B1_CL_MAP_2_MSB                                        31
#define PHY_BB_CL_MAP_2_B1_CL_MAP_2_MASK                                       0xffffffff
#define PHY_BB_CL_MAP_2_B1_CL_MAP_2_GET(x)                                     (((x) & PHY_BB_CL_MAP_2_B1_CL_MAP_2_MASK) >> PHY_BB_CL_MAP_2_B1_CL_MAP_2_LSB)
#define PHY_BB_CL_MAP_2_B1_CL_MAP_2_SET(x)                                     (((0 | (x)) << PHY_BB_CL_MAP_2_B1_CL_MAP_2_LSB) & PHY_BB_CL_MAP_2_B1_CL_MAP_2_MASK)
#define PHY_BB_CL_MAP_2_B1_CL_MAP_2_RESET                                      0x0
#define PHY_BB_CL_MAP_2_B1_ADDRESS                                             (0xe4 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_MAP_2_B1_RSTMASK                                             0xffffffff
#define PHY_BB_CL_MAP_2_B1_RESET                                               0x0

// 0xe8 (PHY_BB_CL_MAP_3_B1)
#define PHY_BB_CL_MAP_3_B1_CL_MAP_3_LSB                                        0
#define PHY_BB_CL_MAP_3_B1_CL_MAP_3_MSB                                        31
#define PHY_BB_CL_MAP_3_B1_CL_MAP_3_MASK                                       0xffffffff
#define PHY_BB_CL_MAP_3_B1_CL_MAP_3_GET(x)                                     (((x) & PHY_BB_CL_MAP_3_B1_CL_MAP_3_MASK) >> PHY_BB_CL_MAP_3_B1_CL_MAP_3_LSB)
#define PHY_BB_CL_MAP_3_B1_CL_MAP_3_SET(x)                                     (((0 | (x)) << PHY_BB_CL_MAP_3_B1_CL_MAP_3_LSB) & PHY_BB_CL_MAP_3_B1_CL_MAP_3_MASK)
#define PHY_BB_CL_MAP_3_B1_CL_MAP_3_RESET                                      0x0
#define PHY_BB_CL_MAP_3_B1_ADDRESS                                             (0xe8 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_MAP_3_B1_RSTMASK                                             0xffffffff
#define PHY_BB_CL_MAP_3_B1_RESET                                               0x0

// 0x100 (PHY_BB_CL_TAB_B1)
#define PHY_BB_CL_TAB_B1_BB_GAIN_LSB                                           27
#define PHY_BB_CL_TAB_B1_BB_GAIN_MSB                                           30
#define PHY_BB_CL_TAB_B1_BB_GAIN_MASK                                          0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_GET(x)                                        (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_SET(x)                                        (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_RESET                                         0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_LSB                                  16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_MSB                                  26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_MASK                                 0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_GET(x)                               (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_SET(x)                               (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_RESET                                0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_LSB                                  5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_MSB                                  15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_MASK                                 0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_GET(x)                               (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_SET(x)                               (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_RESET                                0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_LSB                                       0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_MSB                                       4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_MASK                                      0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_GET(x)                                    (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_SET(x)                                    (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_RESET                                     0x0
#define PHY_BB_CL_TAB_B1_ADDRESS                                               (0x100 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_RSTMASK                                               0x7fffffff
#define PHY_BB_CL_TAB_B1_RESET                                                 0x0

// 0x100 (PHY_BB_CL_TAB_B1_0)
#define PHY_BB_CL_TAB_B1_BB_GAIN_0_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_0_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_0_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_0_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_0_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_0_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_0_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_0_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_0_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_0_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_0_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_0_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_0_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_0_ADDRESS                                             (0x100 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_0_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_0_RESET                                               0x0

// 0x104 (PHY_BB_CL_TAB_B1_1)
#define PHY_BB_CL_TAB_B1_BB_GAIN_1_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_1_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_1_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_1_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_1_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_1_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_1_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_1_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_1_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_1_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_1_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_1_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_1_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_1_ADDRESS                                             (0x104 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_1_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_1_RESET                                               0x0

// 0x108 (PHY_BB_CL_TAB_B1_2)
#define PHY_BB_CL_TAB_B1_BB_GAIN_2_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_2_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_2_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_2_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_2_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_2_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_2_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_2_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_2_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_2_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_2_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_2_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_2_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_2_ADDRESS                                             (0x108 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_2_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_2_RESET                                               0x0

// 0x10c (PHY_BB_CL_TAB_B1_3)
#define PHY_BB_CL_TAB_B1_BB_GAIN_3_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_3_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_3_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_3_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_3_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_3_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_3_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_3_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_3_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_3_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_3_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_3_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_3_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_3_ADDRESS                                             (0x10c + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_3_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_3_RESET                                               0x0

// 0x110 (PHY_BB_CL_TAB_B1_4)
#define PHY_BB_CL_TAB_B1_BB_GAIN_4_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_4_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_4_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_4_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_4_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_4_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_4_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_4_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_4_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_4_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_4_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_4_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_4_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_4_ADDRESS                                             (0x110 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_4_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_4_RESET                                               0x0

// 0x114 (PHY_BB_CL_TAB_B1_5)
#define PHY_BB_CL_TAB_B1_BB_GAIN_5_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_5_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_5_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_5_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_5_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_5_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_5_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_5_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_5_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_5_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_5_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_5_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_5_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_5_ADDRESS                                             (0x114 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_5_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_5_RESET                                               0x0

// 0x118 (PHY_BB_CL_TAB_B1_6)
#define PHY_BB_CL_TAB_B1_BB_GAIN_6_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_6_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_6_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_6_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_6_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_6_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_6_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_6_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_6_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_6_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_6_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_6_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_6_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_6_ADDRESS                                             (0x118 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_6_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_6_RESET                                               0x0

// 0x11c (PHY_BB_CL_TAB_B1_7)
#define PHY_BB_CL_TAB_B1_BB_GAIN_7_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_7_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_7_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_7_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_7_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_7_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_7_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_7_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_7_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_7_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_7_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_7_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_7_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_7_ADDRESS                                             (0x11c + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_7_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_7_RESET                                               0x0

// 0x120 (PHY_BB_CL_TAB_B1_8)
#define PHY_BB_CL_TAB_B1_BB_GAIN_8_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_8_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_8_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_8_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_8_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_8_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_8_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_8_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_8_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_8_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_8_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_8_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_8_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_8_ADDRESS                                             (0x120 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_8_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_8_RESET                                               0x0

// 0x124 (PHY_BB_CL_TAB_B1_9)
#define PHY_BB_CL_TAB_B1_BB_GAIN_9_LSB                                         27
#define PHY_BB_CL_TAB_B1_BB_GAIN_9_MSB                                         30
#define PHY_BB_CL_TAB_B1_BB_GAIN_9_MASK                                        0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_9_GET(x)                                      (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_9_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_9_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_9_SET(x)                                      (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_9_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_9_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_9_RESET                                       0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_LSB                                16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_MSB                                26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_MASK                               0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_9_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_LSB                                5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_MSB                                15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_MASK                               0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_GET(x)                             (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_SET(x)                             (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_9_RESET                              0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_LSB                                     0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_MSB                                     4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_MASK                                    0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_GET(x)                                  (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_SET(x)                                  (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_9_RESET                                   0x0
#define PHY_BB_CL_TAB_B1_9_ADDRESS                                             (0x124 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_9_RSTMASK                                             0x7fffffff
#define PHY_BB_CL_TAB_B1_9_RESET                                               0x0

// 0x128 (PHY_BB_CL_TAB_B1_10)
#define PHY_BB_CL_TAB_B1_BB_GAIN_10_LSB                                        27
#define PHY_BB_CL_TAB_B1_BB_GAIN_10_MSB                                        30
#define PHY_BB_CL_TAB_B1_BB_GAIN_10_MASK                                       0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_10_GET(x)                                     (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_10_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_10_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_10_SET(x)                                     (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_10_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_10_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_10_RESET                                      0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_LSB                               16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_MSB                               26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_MASK                              0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_10_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_LSB                               5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_MSB                               15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_MASK                              0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_10_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_LSB                                    0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_MSB                                    4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_MASK                                   0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_GET(x)                                 (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_SET(x)                                 (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_10_RESET                                  0x0
#define PHY_BB_CL_TAB_B1_10_ADDRESS                                            (0x128 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_10_RSTMASK                                            0x7fffffff
#define PHY_BB_CL_TAB_B1_10_RESET                                              0x0

// 0x12c (PHY_BB_CL_TAB_B1_11)
#define PHY_BB_CL_TAB_B1_BB_GAIN_11_LSB                                        27
#define PHY_BB_CL_TAB_B1_BB_GAIN_11_MSB                                        30
#define PHY_BB_CL_TAB_B1_BB_GAIN_11_MASK                                       0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_11_GET(x)                                     (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_11_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_11_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_11_SET(x)                                     (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_11_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_11_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_11_RESET                                      0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_LSB                               16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_MSB                               26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_MASK                              0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_11_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_LSB                               5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_MSB                               15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_MASK                              0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_11_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_LSB                                    0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_MSB                                    4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_MASK                                   0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_GET(x)                                 (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_SET(x)                                 (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_11_RESET                                  0x0
#define PHY_BB_CL_TAB_B1_11_ADDRESS                                            (0x12c + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_11_RSTMASK                                            0x7fffffff
#define PHY_BB_CL_TAB_B1_11_RESET                                              0x0

// 0x130 (PHY_BB_CL_TAB_B1_12)
#define PHY_BB_CL_TAB_B1_BB_GAIN_12_LSB                                        27
#define PHY_BB_CL_TAB_B1_BB_GAIN_12_MSB                                        30
#define PHY_BB_CL_TAB_B1_BB_GAIN_12_MASK                                       0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_12_GET(x)                                     (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_12_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_12_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_12_SET(x)                                     (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_12_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_12_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_12_RESET                                      0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_LSB                               16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_MSB                               26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_MASK                              0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_12_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_LSB                               5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_MSB                               15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_MASK                              0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_12_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_LSB                                    0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_MSB                                    4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_MASK                                   0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_GET(x)                                 (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_SET(x)                                 (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_12_RESET                                  0x0
#define PHY_BB_CL_TAB_B1_12_ADDRESS                                            (0x130 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_12_RSTMASK                                            0x7fffffff
#define PHY_BB_CL_TAB_B1_12_RESET                                              0x0

// 0x134 (PHY_BB_CL_TAB_B1_13)
#define PHY_BB_CL_TAB_B1_BB_GAIN_13_LSB                                        27
#define PHY_BB_CL_TAB_B1_BB_GAIN_13_MSB                                        30
#define PHY_BB_CL_TAB_B1_BB_GAIN_13_MASK                                       0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_13_GET(x)                                     (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_13_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_13_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_13_SET(x)                                     (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_13_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_13_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_13_RESET                                      0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_LSB                               16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_MSB                               26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_MASK                              0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_13_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_LSB                               5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_MSB                               15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_MASK                              0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_13_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_LSB                                    0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_MSB                                    4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_MASK                                   0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_GET(x)                                 (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_SET(x)                                 (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_13_RESET                                  0x0
#define PHY_BB_CL_TAB_B1_13_ADDRESS                                            (0x134 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_13_RSTMASK                                            0x7fffffff
#define PHY_BB_CL_TAB_B1_13_RESET                                              0x0

// 0x138 (PHY_BB_CL_TAB_B1_14)
#define PHY_BB_CL_TAB_B1_BB_GAIN_14_LSB                                        27
#define PHY_BB_CL_TAB_B1_BB_GAIN_14_MSB                                        30
#define PHY_BB_CL_TAB_B1_BB_GAIN_14_MASK                                       0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_14_GET(x)                                     (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_14_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_14_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_14_SET(x)                                     (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_14_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_14_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_14_RESET                                      0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_LSB                               16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_MSB                               26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_MASK                              0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_14_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_LSB                               5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_MSB                               15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_MASK                              0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_14_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_LSB                                    0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_MSB                                    4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_MASK                                   0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_GET(x)                                 (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_SET(x)                                 (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_14_RESET                                  0x0
#define PHY_BB_CL_TAB_B1_14_ADDRESS                                            (0x138 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_14_RSTMASK                                            0x7fffffff
#define PHY_BB_CL_TAB_B1_14_RESET                                              0x0

// 0x13c (PHY_BB_CL_TAB_B1_15)
#define PHY_BB_CL_TAB_B1_BB_GAIN_15_LSB                                        27
#define PHY_BB_CL_TAB_B1_BB_GAIN_15_MSB                                        30
#define PHY_BB_CL_TAB_B1_BB_GAIN_15_MASK                                       0x78000000
#define PHY_BB_CL_TAB_B1_BB_GAIN_15_GET(x)                                     (((x) & PHY_BB_CL_TAB_B1_BB_GAIN_15_MASK) >> PHY_BB_CL_TAB_B1_BB_GAIN_15_LSB)
#define PHY_BB_CL_TAB_B1_BB_GAIN_15_SET(x)                                     (((0 | (x)) << PHY_BB_CL_TAB_B1_BB_GAIN_15_LSB) & PHY_BB_CL_TAB_B1_BB_GAIN_15_MASK)
#define PHY_BB_CL_TAB_B1_BB_GAIN_15_RESET                                      0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_LSB                               16
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_MSB                               26
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_MASK                              0x7ff0000
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_I_15_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_LSB                               5
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_MSB                               15
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_MASK                              0xffe0
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_GET(x)                            (((x) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_MASK) >> PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_LSB)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_SET(x)                            (((0 | (x)) << PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_LSB) & PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_MASK)
#define PHY_BB_CL_TAB_B1_CARR_LK_DC_ADD_Q_15_RESET                             0x0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_LSB                                    0
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_MSB                                    4
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_MASK                                   0x1f
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_GET(x)                                 (((x) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_MASK) >> PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_LSB)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_SET(x)                                 (((0 | (x)) << PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_LSB) & PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_MASK)
#define PHY_BB_CL_TAB_B1_CL_GAIN_MOD_15_RESET                                  0x0
#define PHY_BB_CL_TAB_B1_15_ADDRESS                                            (0x13c + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CL_TAB_B1_15_RSTMASK                                            0x7fffffff
#define PHY_BB_CL_TAB_B1_15_RESET                                              0x0

// 0x174 (PHY_BB_CHAN_INFO_NOISE_PWR_B1)
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_LSB                20
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_MSB                27
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_MASK               0xff00000
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_GET(x)             (((x) & PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_MASK) >> PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_LSB)
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_SET(x)             (((0 | (x)) << PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_LSB) & PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_MASK)
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_Q_1_RESET              0x0
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_LSB                12
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_MSB                19
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_MASK               0xff000
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_GET(x)             (((x) & PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_MASK) >> PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_LSB)
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_SET(x)             (((0 | (x)) << PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_LSB) & PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_MASK)
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_CHAN_INFO_FINE_DC_I_1_RESET              0x0
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_ADDRESS                                  (0x174 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_RSTMASK                                  0xffff000
#define PHY_BB_CHAN_INFO_NOISE_PWR_B1_RESET                                    0x0

// 0x180 (PHY_BB_CHAN_INFO_GAIN_B1)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_LSB                    24
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_MSB                    24
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_MASK                   0x1000000
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_GET(x)                 (((x) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_MASK) >> PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_LSB)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_SET(x)                 (((0 | (x)) << PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_LSB) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_MASK)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN2_SW_1_RESET                  0x0
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_LSB                    23
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_MSB                    23
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_MASK                   0x800000
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_GET(x)                 (((x) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_MASK) >> PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_LSB)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_SET(x)                 (((0 | (x)) << PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_LSB) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_MASK)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_XATTEN1_SW_1_RESET                  0x0
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_LSB                       16
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_MSB                       22
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_MASK                      0x7f0000
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_GET(x)                    (((x) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_MASK) >> PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_LSB)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_SET(x)                    (((0 | (x)) << PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_LSB) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_MASK)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_MB_GAIN_1_RESET                     0x0
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_LSB                       8
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_MSB                       15
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_MASK                      0xff00
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_GET(x)                    (((x) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_MASK) >> PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_LSB)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_SET(x)                    (((0 | (x)) << PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_LSB) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_MASK)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RF_GAIN_1_RESET                     0x0
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_LSB                          0
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_MSB                          7
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_MASK                         0xff
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_GET(x)                       (((x) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_MASK) >> PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_LSB)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_SET(x)                       (((0 | (x)) << PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_LSB) & PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_MASK)
#define PHY_BB_CHAN_INFO_GAIN_B1_CHAN_INFO_RSSI_1_RESET                        0x0
#define PHY_BB_CHAN_INFO_GAIN_B1_ADDRESS                                       (0x180 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_CHAN_INFO_GAIN_B1_RSTMASK                                       0x1ffffff
#define PHY_BB_CHAN_INFO_GAIN_B1_RESET                                         0x0

// 0x188 (PHY_BB_NF_DCOFF_B1)
#define PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_LSB                                      8
#define PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_MSB                                      15
#define PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_MASK                                     0xff00
#define PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_GET(x)                                   (((x) & PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_MASK) >> PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_LSB)
#define PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_SET(x)                                   (((0 | (x)) << PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_LSB) & PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_MASK)
#define PHY_BB_NF_DCOFF_B1_DC_OFF_Q_1_RESET                                    0x0
#define PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_LSB                                      0
#define PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_MSB                                      7
#define PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_MASK                                     0xff
#define PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_GET(x)                                   (((x) & PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_MASK) >> PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_LSB)
#define PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_SET(x)                                   (((0 | (x)) << PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_LSB) & PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_MASK)
#define PHY_BB_NF_DCOFF_B1_DC_OFF_I_1_RESET                                    0x0
#define PHY_BB_NF_DCOFF_B1_ADDRESS                                             (0x188 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_NF_DCOFF_B1_RSTMASK                                             0xffff
#define PHY_BB_NF_DCOFF_B1_RESET                                               0x0

// 0x204 (PHY_BB_TPC_4_B1)
#define PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_LSB                                 8
#define PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_MSB                                 15
#define PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_MASK                                0xff00
#define PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_GET(x)                              (((x) & PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_MASK) >> PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_LSB)
#define PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_SET(x)                              (((0 | (x)) << PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_LSB) & PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_MASK)
#define PHY_BB_TPC_4_B1_PDADC_CLIP_2_CNT_1_RESET                               0x0
#define PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_LSB                                 0
#define PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_MSB                                 7
#define PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_MASK                                0xff
#define PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_GET(x)                              (((x) & PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_MASK) >> PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_LSB)
#define PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_SET(x)                              (((0 | (x)) << PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_LSB) & PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_MASK)
#define PHY_BB_TPC_4_B1_PDADC_CLIP_1_CNT_1_RESET                               0x0
#define PHY_BB_TPC_4_B1_ADDRESS                                                (0x204 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TPC_4_B1_RSTMASK                                                0xffff
#define PHY_BB_TPC_4_B1_RESET                                                  0x0

// 0x220 (PHY_BB_TPC_11_B1)
#define PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_LSB                                   24
#define PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_MSB                                   26
#define PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_MASK                                  0x7000000
#define PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_GET(x)                                (((x) & PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_MASK) >> PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_LSB)
#define PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_SET(x)                                (((0 | (x)) << PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_LSB) & PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_MASK)
#define PHY_BB_TPC_11_B1_FORCED_PA_CFG_1_RESET                                 0x0
#define PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_LSB                                 16
#define PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_MSB                                 23
#define PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_MASK                                0xff0000
#define PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_GET(x)                              (((x) & PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_MASK) >> PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_LSB)
#define PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_SET(x)                              (((0 | (x)) << PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_LSB) & PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_MASK)
#define PHY_BB_TPC_11_B1_FORCED_DAC_GAIN_1_RESET                               0x0
#define PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_LSB                               10
#define PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_MSB                               14
#define PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_MASK                              0x7c00
#define PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_GET(x)                            (((x) & PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_MASK) >> PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_LSB)
#define PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_SET(x)                            (((0 | (x)) << PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_LSB) & PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_MASK)
#define PHY_BB_TPC_11_B1_FORCED_TXGAIN_IDX_1_RESET                             0x0
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_LSB                         8
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_MSB                         9
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_MASK                        0x300
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_GET(x)                      (((x) & PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_MASK) >> PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_LSB)
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_SET(x)                      (((0 | (x)) << PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_LSB) & PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_MASK)
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB_EXT_RESET                       0x0
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB                                 0
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_MSB                                 7
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_MASK                                0xff
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_GET(x)                              (((x) & PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_MASK) >> PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB)
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_SET(x)                              (((0 | (x)) << PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_LSB) & PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_MASK)
#define PHY_BB_TPC_11_B1_OLPC_GAIN_DELTA_1_RESET                               0x0
#define PHY_BB_TPC_11_B1_ADDRESS                                               (0x220 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TPC_11_B1_RSTMASK                                               0x7ff7fff
#define PHY_BB_TPC_11_B1_RESET                                                 0x0

// 0x224 (PHY_BB_TPC_12_B1)
#define PHY_BB_TPC_12_B1_PDADC_BIAS_1_LSB                                      0
#define PHY_BB_TPC_12_B1_PDADC_BIAS_1_MSB                                      7
#define PHY_BB_TPC_12_B1_PDADC_BIAS_1_MASK                                     0xff
#define PHY_BB_TPC_12_B1_PDADC_BIAS_1_GET(x)                                   (((x) & PHY_BB_TPC_12_B1_PDADC_BIAS_1_MASK) >> PHY_BB_TPC_12_B1_PDADC_BIAS_1_LSB)
#define PHY_BB_TPC_12_B1_PDADC_BIAS_1_SET(x)                                   (((0 | (x)) << PHY_BB_TPC_12_B1_PDADC_BIAS_1_LSB) & PHY_BB_TPC_12_B1_PDADC_BIAS_1_MASK)
#define PHY_BB_TPC_12_B1_PDADC_BIAS_1_RESET                                    0x0
#define PHY_BB_TPC_12_B1_ADDRESS                                               (0x224 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TPC_12_B1_RSTMASK                                               0xff
#define PHY_BB_TPC_12_B1_RESET                                                 0x0

// 0x240 (PHY_BB_TPC_19_B1)
#define PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_LSB                                31
#define PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_MSB                                31
#define PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_MASK                               0x80000000
#define PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_GET(x)                             (((x) & PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_MASK) >> PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_LSB)
#define PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_SET(x)                             (((0 | (x)) << PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_LSB) & PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_MASK)
#define PHY_BB_TPC_19_B1_BT_CLPC_ERR_UPDT_1_RESET                              0x0
#define PHY_BB_TPC_19_B1_ALPHA_VOLT_1_LSB                                      24
#define PHY_BB_TPC_19_B1_ALPHA_VOLT_1_MSB                                      30
#define PHY_BB_TPC_19_B1_ALPHA_VOLT_1_MASK                                     0x7f000000
#define PHY_BB_TPC_19_B1_ALPHA_VOLT_1_GET(x)                                   (((x) & PHY_BB_TPC_19_B1_ALPHA_VOLT_1_MASK) >> PHY_BB_TPC_19_B1_ALPHA_VOLT_1_LSB)
#define PHY_BB_TPC_19_B1_ALPHA_VOLT_1_SET(x)                                   (((0 | (x)) << PHY_BB_TPC_19_B1_ALPHA_VOLT_1_LSB) & PHY_BB_TPC_19_B1_ALPHA_VOLT_1_MASK)
#define PHY_BB_TPC_19_B1_ALPHA_VOLT_1_RESET                                    0x0
#define PHY_BB_TPC_19_B1_ALPHA_THERM_1_LSB                                     16
#define PHY_BB_TPC_19_B1_ALPHA_THERM_1_MSB                                     23
#define PHY_BB_TPC_19_B1_ALPHA_THERM_1_MASK                                    0xff0000
#define PHY_BB_TPC_19_B1_ALPHA_THERM_1_GET(x)                                  (((x) & PHY_BB_TPC_19_B1_ALPHA_THERM_1_MASK) >> PHY_BB_TPC_19_B1_ALPHA_THERM_1_LSB)
#define PHY_BB_TPC_19_B1_ALPHA_THERM_1_SET(x)                                  (((0 | (x)) << PHY_BB_TPC_19_B1_ALPHA_THERM_1_LSB) & PHY_BB_TPC_19_B1_ALPHA_THERM_1_MASK)
#define PHY_BB_TPC_19_B1_ALPHA_THERM_1_RESET                                   0x0
#define PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_LSB                                  8
#define PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_MSB                                  15
#define PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_MASK                                 0xff00
#define PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_GET(x)                               (((x) & PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_MASK) >> PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_LSB)
#define PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_SET(x)                               (((0 | (x)) << PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_LSB) & PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_MASK)
#define PHY_BB_TPC_19_B1_VOLT_CAL_VALUE_1_RESET                                0x0
#define PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_LSB                                 0
#define PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_MSB                                 7
#define PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_MASK                                0xff
#define PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_GET(x)                              (((x) & PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_MASK) >> PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_LSB)
#define PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_SET(x)                              (((0 | (x)) << PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_LSB) & PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_MASK)
#define PHY_BB_TPC_19_B1_THERM_CAL_VALUE_1_RESET                               0x0
#define PHY_BB_TPC_19_B1_ADDRESS                                               (0x240 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TPC_19_B1_RSTMASK                                               0xffffffff
#define PHY_BB_TPC_19_B1_RESET                                                 0x0

// 0x248 (PHY_BB_THERM_ADC_1_B1)
#define PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_LSB                           16
#define PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_MSB                           23
#define PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_MASK                          0xff0000
#define PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_GET(x)                        (((x) & PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_MASK) >> PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_LSB)
#define PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_SET(x)                        (((0 | (x)) << PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_LSB) & PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_MASK)
#define PHY_BB_THERM_ADC_1_B1_INIT_ATB_SETTING_1_RESET                         0x0
#define PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_LSB                          8
#define PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_MSB                          15
#define PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_MASK                         0xff00
#define PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_GET(x)                       (((x) & PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_MASK) >> PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_LSB)
#define PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_SET(x)                       (((0 | (x)) << PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_LSB) & PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_MASK)
#define PHY_BB_THERM_ADC_1_B1_INIT_VOLT_SETTING_1_RESET                        0x0
#define PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_LSB                         0
#define PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_MSB                         7
#define PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_MASK                        0xff
#define PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_GET(x)                      (((x) & PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_MASK) >> PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_LSB)
#define PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_SET(x)                      (((0 | (x)) << PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_LSB) & PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_MASK)
#define PHY_BB_THERM_ADC_1_B1_INIT_THERM_SETTING_1_RESET                       0x0
#define PHY_BB_THERM_ADC_1_B1_ADDRESS                                          (0x248 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_THERM_ADC_1_B1_RSTMASK                                          0xffffff
#define PHY_BB_THERM_ADC_1_B1_RESET                                            0x0

// 0x250 (PHY_BB_THERM_ADC_3_B1)
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_LSB                      8
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_MSB                      16
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_MASK                     0x1ff00
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_GET(x)                   (((x) & PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_MASK) >> PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_LSB)
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_SET(x)                   (((0 | (x)) << PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_LSB) & PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_MASK)
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_SCALED_GAIN_1_RESET                    0x100
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_LSB                           0
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_MSB                           7
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_MASK                          0xff
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_GET(x)                        (((x) & PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_MASK) >> PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_LSB)
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_SET(x)                        (((0 | (x)) << PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_LSB) & PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_MASK)
#define PHY_BB_THERM_ADC_3_B1_THERM_ADC_OFFSET_1_RESET                         0x0
#define PHY_BB_THERM_ADC_3_B1_ADDRESS                                          (0x250 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_THERM_ADC_3_B1_RSTMASK                                          0x1ffff
#define PHY_BB_THERM_ADC_3_B1_RESET                                            0x10000

// 0x254 (PHY_BB_THERM_ADC_4_B1)
#define PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_LSB                           16
#define PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_MSB                           23
#define PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_MASK                          0xff0000
#define PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_GET(x)                        (((x) & PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_MASK) >> PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_LSB)
#define PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_SET(x)                        (((0 | (x)) << PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_LSB) & PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_MASK)
#define PHY_BB_THERM_ADC_4_B1_LATEST_ATB_VALUE_1_RESET                         0x0
#define PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_LSB                          8
#define PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_MSB                          15
#define PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_MASK                         0xff00
#define PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_GET(x)                       (((x) & PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_MASK) >> PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_LSB)
#define PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_SET(x)                       (((0 | (x)) << PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_LSB) & PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_MASK)
#define PHY_BB_THERM_ADC_4_B1_LATEST_VOLT_VALUE_1_RESET                        0x0
#define PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_LSB                         0
#define PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_MSB                         7
#define PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_MASK                        0xff
#define PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_GET(x)                      (((x) & PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_MASK) >> PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_LSB)
#define PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_SET(x)                      (((0 | (x)) << PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_LSB) & PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_MASK)
#define PHY_BB_THERM_ADC_4_B1_LATEST_THERM_VALUE_1_RESET                       0x0
#define PHY_BB_THERM_ADC_4_B1_ADDRESS                                          (0x254 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_THERM_ADC_4_B1_RSTMASK                                          0xffffff
#define PHY_BB_THERM_ADC_4_B1_RESET                                            0x0

// 0x25c (PHY_BB_TPC_STAT_0_B1)
#define PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_LSB                             17
#define PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_MSB                             25
#define PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_MASK                            0x3fe0000
#define PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_GET(x)                          (((x) & PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_MASK) >> PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_LSB)
#define PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_SET(x)                          (((0 | (x)) << PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_LSB) & PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_MASK)
#define PHY_BB_TPC_STAT_0_B1_LATEST_DC_VALUE_1_RESET                           0x0
#define PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_LSB                               9
#define PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_MSB                               16
#define PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_MASK                              0x1fe00
#define PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_GET(x)                            (((x) & PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_MASK) >> PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_LSB)
#define PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_SET(x)                            (((0 | (x)) << PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_LSB) & PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_MASK)
#define PHY_BB_TPC_STAT_0_B1_PDACC_AVG_OUT_1_RESET                             0x0
#define PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_LSB                                0
#define PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_MSB                                8
#define PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_MASK                               0x1ff
#define PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_GET(x)                             (((x) & PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_MASK) >> PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_LSB)
#define PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_SET(x)                             (((0 | (x)) << PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_LSB) & PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_MASK)
#define PHY_BB_TPC_STAT_0_B1_MEAS_PWR_OUT_1_RESET                              0x0
#define PHY_BB_TPC_STAT_0_B1_ADDRESS                                           (0x25c + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TPC_STAT_0_B1_RSTMASK                                           0x3ffffff
#define PHY_BB_TPC_STAT_0_B1_RESET                                             0x0

// 0x260 (PHY_BB_TPC_STAT_1_B1)
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_LSB                               16
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_MSB                               23
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_MASK                              0xff0000
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_GET(x)                            (((x) & PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_MASK) >> PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_LSB)
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_SET(x)                            (((0 | (x)) << PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_LSB) & PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_MASK)
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_MID_1_RESET                             0x0
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_LSB                              8
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_MSB                              15
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_MASK                             0xff00
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_GET(x)                           (((x) & PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_MASK) >> PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_LSB)
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_SET(x)                           (((0 | (x)) << PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_LSB) & PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_MASK)
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_HIGH_1_RESET                            0x0
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_LSB                               0
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_MSB                               7
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_MASK                              0xff
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_GET(x)                            (((x) & PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_MASK) >> PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_LSB)
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_SET(x)                            (((0 | (x)) << PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_LSB) & PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_MASK)
#define PHY_BB_TPC_STAT_1_B1_GAIN_MISS_LOW_1_RESET                             0x0
#define PHY_BB_TPC_STAT_1_B1_ADDRESS                                           (0x260 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TPC_STAT_1_B1_RSTMASK                                           0xffffff
#define PHY_BB_TPC_STAT_1_B1_RESET                                             0x0

// 0x264 (PHY_BB_TPC_STAT_2_B1)
#define PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_LSB                                 18
#define PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_MSB                                 20
#define PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_MASK                                0x1c0000
#define PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_GET(x)                              (((x) & PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_MASK) >> PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_LSB)
#define PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_SET(x)                              (((0 | (x)) << PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_LSB) & PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_MASK)
#define PHY_BB_TPC_STAT_2_B1_ANA_SET_NDP_1_RESET                               0x0
#define PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_LSB                                 8
#define PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_MSB                                 17
#define PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_MASK                                0x3ff00
#define PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_GET(x)                              (((x) & PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_MASK) >> PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_LSB)
#define PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_SET(x)                              (((0 | (x)) << PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_LSB) & PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_MASK)
#define PHY_BB_TPC_STAT_2_B1_CLPC_ERR_MU_1_RESET                               0x0
#define PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_LSB                                0
#define PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_MSB                                7
#define PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_MASK                               0xff
#define PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_GET(x)                             (((x) & PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_MASK) >> PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_LSB)
#define PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_SET(x)                             (((0 | (x)) << PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_LSB) & PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_MASK)
#define PHY_BB_TPC_STAT_2_B1_DAC_GAIN_NDP_1_RESET                              0x0
#define PHY_BB_TPC_STAT_2_B1_ADDRESS                                           (0x264 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TPC_STAT_2_B1_RSTMASK                                           0x1fffff
#define PHY_BB_TPC_STAT_2_B1_RESET                                             0x0

// 0x274 (PHY_BB_TPC_STAT_3_B1)
#define PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_LSB                             18
#define PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_MSB                             20
#define PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_MASK                            0x1c0000
#define PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_GET(x)                          (((x) & PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_MASK) >> PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_LSB)
#define PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_SET(x)                          (((0 | (x)) << PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_LSB) & PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_MASK)
#define PHY_BB_TPC_STAT_3_B1_LATEST_GLUT_SET_1_RESET                           0x0
#define PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_LSB                             8
#define PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_MSB                             17
#define PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_MASK                            0x3ff00
#define PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_GET(x)                          (((x) & PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_MASK) >> PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_LSB)
#define PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_SET(x)                          (((0 | (x)) << PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_LSB) & PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_MASK)
#define PHY_BB_TPC_STAT_3_B1_LATEST_CLPC_ERR_1_RESET                           0x0
#define PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_LSB                             0
#define PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_MSB                             7
#define PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_MASK                            0xff
#define PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_GET(x)                          (((x) & PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_MASK) >> PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_LSB)
#define PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_SET(x)                          (((0 | (x)) << PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_LSB) & PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_MASK)
#define PHY_BB_TPC_STAT_3_B1_LATEST_DAC_GAIN_1_RESET                           0x0
#define PHY_BB_TPC_STAT_3_B1_ADDRESS                                           (0x274 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TPC_STAT_3_B1_RSTMASK                                           0x1fffff
#define PHY_BB_TPC_STAT_3_B1_RESET                                             0x0

// 0x384 (PHY_BB_RRT_TABLE_SW_INTF_B1)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_LSB             5
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_MSB             5
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_MASK            0x20
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_GET(x)          (((x) & PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_MASK) >> PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_LSB)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_SET(x)          (((0 | (x)) << PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_LSB) & PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_MASK)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_OFFSET_1_RESET           0x0
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_LSB                    2
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_MSB                    4
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_MASK                   0x1c
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_GET(x)                 (((x) & PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_MASK) >> PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_LSB)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_SET(x)                 (((0 | (x)) << PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_LSB) & PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_MASK)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ADDR_1_RESET                  0x0
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_LSB                   1
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_MSB                   1
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_MASK                  0x2
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_GET(x)                (((x) & PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_MASK) >> PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_LSB)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_SET(x)                (((0 | (x)) << PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_LSB) & PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_MASK)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_WRITE_1_RESET                 0x0
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_LSB                  0
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_MSB                  0
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_MASK                 0x1
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_GET(x)               (((x) & PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_MASK) >> PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_LSB)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_SET(x)               (((0 | (x)) << PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_LSB) & PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_MASK)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_SW_RRT_TABLE_ACCESS_1_RESET                0x0
#define PHY_BB_RRT_TABLE_SW_INTF_B1_ADDRESS                                    (0x384 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_RRT_TABLE_SW_INTF_B1_RSTMASK                                    0x3f
#define PHY_BB_RRT_TABLE_SW_INTF_B1_RESET                                      0x0

// 0x388 (PHY_BB_RRT_TABLE_SW_INTF_1_B1)
#define PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_LSB                  0
#define PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_MSB                  31
#define PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_MASK                 0xffffffff
#define PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_GET(x)               (((x) & PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_MASK) >> PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_LSB)
#define PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_SET(x)               (((0 | (x)) << PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_LSB) & PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_MASK)
#define PHY_BB_RRT_TABLE_SW_INTF_1_B1_SW_RRT_TABLE_DATA_1_RESET                0x0
#define PHY_BB_RRT_TABLE_SW_INTF_1_B1_ADDRESS                                  (0x388 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_RRT_TABLE_SW_INTF_1_B1_RSTMASK                                  0xffffffff
#define PHY_BB_RRT_TABLE_SW_INTF_1_B1_RESET                                    0x0

// 0x48c (PHY_BB_TXIQCAL_STATUS_B1)
#define PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_LSB                          18
#define PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_MSB                          23
#define PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_MASK                         0xfc0000
#define PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_GET(x)                       (((x) & PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_MASK) >> PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_LSB)
#define PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_SET(x)                       (((0 | (x)) << PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_LSB) & PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_MASK)
#define PHY_BB_TXIQCAL_STATUS_B1_LAST_MEAS_ADDR_1_RESET                        0x0
#define PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_LSB                            12
#define PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_MSB                            17
#define PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_MASK                           0x3f000
#define PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_GET(x)                         (((x) & PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_MASK) >> PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_LSB)
#define PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_SET(x)                         (((0 | (x)) << PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_LSB) & PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_MASK)
#define PHY_BB_TXIQCAL_STATUS_B1_RX_GAIN_USED_1_RESET                          0x0
#define PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_LSB                          6
#define PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_MSB                          11
#define PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_MASK                         0xfc0
#define PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_GET(x)                       (((x) & PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_MASK) >> PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_LSB)
#define PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_SET(x)                       (((0 | (x)) << PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_LSB) & PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_MASK)
#define PHY_BB_TXIQCAL_STATUS_B1_TONE_GAIN_USED_1_RESET                        0x0
#define PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_LSB                        1
#define PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_MSB                        5
#define PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_MASK                       0x3e
#define PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_GET(x)                     (((x) & PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_MASK) >> PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_LSB)
#define PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_SET(x)                     (((0 | (x)) << PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_LSB) & PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_MASK)
#define PHY_BB_TXIQCAL_STATUS_B1_CALIBRATED_GAINS_1_RESET                      0x0
#define PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_LSB                          0
#define PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_MSB                          0
#define PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_MASK                         0x1
#define PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_GET(x)                       (((x) & PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_MASK) >> PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_LSB)
#define PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_SET(x)                       (((0 | (x)) << PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_LSB) & PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_MASK)
#define PHY_BB_TXIQCAL_STATUS_B1_TXIQCAL_FAILED_1_RESET                        0x0
#define PHY_BB_TXIQCAL_STATUS_B1_ADDRESS                                       (0x48c + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TXIQCAL_STATUS_B1_RSTMASK                                       0xffffff
#define PHY_BB_TXIQCAL_STATUS_B1_RESET                                         0x0

// 0x4ac (PHY_BB_RXIQCAL_STATUS_B1)
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_LSB                  11
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_MSB                  16
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_MASK                 0x1f800
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_GET(x)               (((x) & PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_MASK) >> PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_LSB)
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_SET(x)               (((0 | (x)) << PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_LSB) & PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_MASK)
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_LAST_MEAS_ADDR_1_RESET                0x0
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_LSB                 6
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_MSB                 10
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_MASK                0x7c0
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_GET(x)              (((x) & PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_MASK) >> PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_LSB)
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_SET(x)              (((0 | (x)) << PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_LSB) & PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_MASK)
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_TXGAIN_IDX_USED_1_RESET               0x0
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_LSB                1
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_MSB                5
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_MASK               0x3e
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_GET(x)             (((x) & PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_MASK) >> PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_LSB)
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_SET(x)             (((0 | (x)) << PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_LSB) & PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_MASK)
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_CALIBRATED_GAINS_1_RESET              0x0
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_LSB                          0
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_MSB                          0
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_MASK                         0x1
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_GET(x)                       (((x) & PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_MASK) >> PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_LSB)
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_SET(x)                       (((0 | (x)) << PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_LSB) & PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_MASK)
#define PHY_BB_RXIQCAL_STATUS_B1_RXIQCAL_FAILED_1_RESET                        0x0
#define PHY_BB_RXIQCAL_STATUS_B1_ADDRESS                                       (0x4ac + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_RXIQCAL_STATUS_B1_RSTMASK                                       0x1ffff
#define PHY_BB_RXIQCAL_STATUS_B1_RESET                                         0x0

// 0x5f0 (PHY_BB_TABLES_INTF_ADDR_B1)
#define PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_LSB                        31
#define PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_MSB                        31
#define PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_MASK                       0x80000000
#define PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_GET(x)                     (((x) & PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_MASK) >> PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_LSB)
#define PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_SET(x)                     (((0 | (x)) << PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_LSB) & PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_MASK)
#define PHY_BB_TABLES_INTF_ADDR_B1_ADDR_AUTO_INCR_1_RESET                      0x0
#define PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_LSB                           2
#define PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_MSB                           17
#define PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_MASK                          0x3fffc
#define PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_GET(x)                        (((x) & PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_MASK) >> PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_LSB)
#define PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_SET(x)                        (((0 | (x)) << PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_LSB) & PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_MASK)
#define PHY_BB_TABLES_INTF_ADDR_B1_TABLES_ADDR_1_RESET                         0x0
#define PHY_BB_TABLES_INTF_ADDR_B1_ADDRESS                                     (0x5f0 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TABLES_INTF_ADDR_B1_RSTMASK                                     0x8003fffc
#define PHY_BB_TABLES_INTF_ADDR_B1_RESET                                       0x0

// 0x5f4 (PHY_BB_TABLES_INTF_DATA_B1)
#define PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_LSB                           0
#define PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_MSB                           31
#define PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_MASK                          0xffffffff
#define PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_GET(x)                        (((x) & PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_MASK) >> PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_LSB)
#define PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_SET(x)                        (((0 | (x)) << PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_LSB) & PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_MASK)
#define PHY_BB_TABLES_INTF_DATA_B1_TABLES_DATA_1_RESET                         0x0
#define PHY_BB_TABLES_INTF_DATA_B1_ADDRESS                                     (0x5f4 + __PHY_SM1_REG_MAP_BASE_ADDRESS)
#define PHY_BB_TABLES_INTF_DATA_B1_RSTMASK                                     0xffffffff
#define PHY_BB_TABLES_INTF_DATA_B1_RESET                                       0x0



#endif /* _PHY_SM1_REG_MAP_H_ */
