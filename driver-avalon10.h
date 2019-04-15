/*
 * Copyright 2017-2019 Johnson-Fan <1314zhengyi@gmail.com>
 * Copyright 2016-2017 Mikeqin <Fengling.Qin@gmail.com>
 * Copyright 2016 Con Kolivas <kernel@kolivas.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef _AVALON10_H_
#define _AVALON10_H_

#include "util.h"
#include "i2c-context.h"

#define UNPACK32(x, str)			\
{						\
	*((str) + 3) = (uint8_t) ((x)      );	\
	*((str) + 2) = (uint8_t) ((x) >>  8);	\
	*((str) + 1) = (uint8_t) ((x) >> 16);	\
	*((str) + 0) = (uint8_t) ((x) >> 24);	\
}

#define get_fan_pwm(v)				(AVA10_PWM_MAX - (v))

#ifdef USE_AVALON10

#define AVA10_DEFAULT_FAN_MIN			50 /* % */
#define AVA10_DEFAULT_FAN_MAX			1023

#define AVA10_DEFAULT_TEMP_MIN			0
#define AVA10_DEFAULT_TEMP_MAX			100
#define AVA10_DEFAULT_TEMP_TARGET		65
#define AVA10_DEFAULT_TEMP_OVERHEAT		105

#define AVA10_DEFAULT_VOLTAGE_LEVEL		49
#define AVA10_DEFAULT_VOLTAGE_LEVEL_MIN		0
#define AVA10_DEFAULT_VOLTAGE_LEVEL_MAX		75
#define AVA10_INVALID_VOLTAGE_LEVEL		-1

#define AVA10_DEFAULT_HASH_OD_MIN		0
#define AVA10_DEFAULT_HASH_OD			0
#define AVA10_DEFAULT_HASH_OD_MAX		1

#define AVA10_DEFAULT_VOLTAGE_LEVEL_OFFSET_MIN	-2
#define AVA10_DEFAULT_VOLTAGE_LEVEL_OFFSET	0
#define AVA10_DEFAULT_VOLTAGE_LEVEL_OFFSET_MAX	1

#define AVA10_DEFAULT_FACTORY_INFO_CNT		32

#define AVA10_DEFAULT_FREQUENCY_0M		0
#define AVA10_DEFAULT_FREQUENCY_525M		525
#define AVA10_DEFAULT_FREQUENCY_575M		575
#define AVA10_DEFAULT_FREQUENCY_MAX		800
#define AVA10_DEFAULT_FREQUENCY			(AVA10_DEFAULT_FREQUENCY_MAX)
#define AVA10_DEFAULT_FREQUENCY_SEL		4

#define AVA10_DEFAULT_MODULARS			7 /* Only support 6 modules maximum with one AUC */
#define AVA10_DEFAULT_MINER_CNT			2
#define AVA10_DEFAULT_ASIC_MAX			120
#define AVA10_DEFAULT_PLL_CNT			4
#define AVA10_DEFAULT_CORE_VOLT_CNT		8
#define AVA10_DEFAULT_CORE_CLK_SEL		1

#define AVA10_DEFAULT_POLLING_DELAY		10 /* ms */

#define AVA10_DEFAULT_SMART_SPEED		1
#define AVA10_DEFAULT_SSDN_PRO			0

#define AVA10_DEFAULT_TH_PASS			7
#define AVA10_DEFAULT_TH_FAIL			1000
#define AVA10_DEFAULT_TH_INIT			32767
#define AVA10_DEFAULT_TH_MSSEL			0
#define AVA10_DEFAULT_TH_TIMEOUT		1300000
#define AVA10_DEFAULT_LV1_TH_MSADD		1
#define AVA10_DEFAULT_LV1_TH_MS			4
#define AVA10_DEFAULT_LV2_TH_MSADD		0
#define AVA10_DEFAULT_LV2_TH_MS			0
#define AVA10_DEFAULT_LV3_TH_MSADD		0
#define AVA10_DEFAULT_LV3_TH_MS			0
#define AVA10_DEFAULT_LV4_TH_MSADD		0
#define AVA10_DEFAULT_LV4_TH_MS			0
#define AVA10_DEFAULT_NONCE_MASK		25
#define AVA10_DEFAULT_NONCE_CHECK		1
#define AVA10_DEFAULT_MUX_L2H			0
#define AVA10_DEFAULT_MUX_H2L			1
#define AVA10_DEFAULT_H2LTIME0_SPD		3
#define AVA10_DEFAULT_ROLL_ENABLE		1
#define AVA10_DEFAULT_SPDLOW			3
#define AVA10_DEFAULT_SPDHIGH			4

/* PID CONTROLLER*/
#define AVA10_DEFAULT_PID_P		 	2
#define AVA10_DEFAULT_PID_I			5
#define AVA10_DEFAULT_PID_D			0
#define AVA10_DEFAULT_PID_TEMP_MIN		50
#define AVA10_DEFAULT_PID_TEMP_MAX		100

#define AVA10_DEFAULT_ADJUST_VOLTAGE		1

#define AVA10_DEFAULT_ASIC_AVERAGE_TEMP_START	12
#define AVA10_DEFAULT_ASIC_AVERAGE_TEMP_END	21

#define AVA10_PWM_MAX				0x3FF
#define AVA10_DRV_DIFFMAX			1024
#define AVA10_ASIC_TIMEOUT_CONST		419430400 /* (2^32 * 1000) / (256 * 40) */

#define AVA10_MODULE_DETECT_INTERVAL		30 /* 30 s */

#define AVA10_AUC_VER_LEN			12	/* Version length: 12 (AUC-YYYYMMDD) */
#define AVA10_AUC_SPEED				400000
#define AVA10_AUC_XDELAY			19200	/* 4800 = 1ms in AUC (11U14)  */
#define AVA10_AUC_P_SIZE			64

#define AVA10_CONNECTER_AUC			1

/* avalon10 protocol package type from MM protocol.h */
#define AVA10_MM_VER_LEN			15
#define AVA10_MM_DNA_LEN			8
#define AVA10_H1				'C'
#define AVA10_H2				'N'

#define AVA10_P_COINBASE_SIZE			(6 * 1024 + 64)
#define AVA10_P_MERKLES_COUNT			30

#define AVA10_P_COUNT				40
#define AVA10_P_DATA_LEN			32

/* Broadcase with block iic_write*/
#define AVA10_P_DETECT				0x10

/* Broadcase With non-block iic_write*/
#define AVA10_P_STATIC				0x11
#define AVA10_P_JOB_ID				0x12
#define AVA10_P_COINBASE			0x13
#define AVA10_P_MERKLES				0x14
#define AVA10_P_HEADER				0x15
#define AVA10_P_TARGET				0x16
#define AVA10_P_JOB_FIN				0x17
#define AVA10_P_VMASK				0x19

/* Broadcase or with I2C address */
#define AVA10_P_SET				0x20
#define AVA10_P_SET_FIN				0x21
#define AVA10_P_SET_VOLT			0x22
#define AVA10_P_SET_PMU				0x24
#define AVA10_P_SET_PLL				0x25
#define AVA10_P_SET_SS				0x26
/* 0x27 reserved */
#define AVA10_P_SET_FAC				0x28

/* Have to send with I2C address */
#define AVA10_P_POLLING				0x30
#define AVA10_P_SYNC				0x31
#define AVA10_P_TEST				0x32
#define AVA10_P_RSTMMTX				0x33
#define AVA10_P_GET_VOLT			0x34

/* Back to host */
#define AVA10_P_ACKDETECT			0x40
#define AVA10_P_STATUS				0x41
#define AVA10_P_NONCE				0x42
#define AVA10_P_TEST_RET			0x43
#define AVA10_P_STATUS_VOLT			0x46
#define AVA10_P_STATUS_POWER			0x48
#define AVA10_P_STATUS_PLL			0x49
#define AVA10_P_STATUS_ASIC			0x4b
#define AVA10_P_STATUS_PVT			0x4c
#define AVA10_P_STATUS_FAC			0x4d
#define AVA10_P_SET_ADJUST_VOLT			0x51

/* Factory used */
#define AVA10_P_SET_FAC_PLL			0x50
#define AVA10_P_SET_FAC_VOLT			0x51
#define AVA10_P_SET_SS_SWITCH			0x52
#define AVA10_P_SET_SSDN_PRO			0x53
#define AVA10_P_SET_HASH_OD			0x54

#define AVA10_MODULE_BROADCAST			0
#define AVA10_ASIC_ID_BROADCAST			0xff
/* End of avalon10 protocol package type */

#define AVA10_IIC_RESET				0xa0
#define AVA10_IIC_INIT				0xa1
#define AVA10_IIC_DEINIT			0xa2
#define AVA10_IIC_XFER				0xa5
#define AVA10_IIC_INFO				0xa6

#define AVA10_FREQ_INIT_MODE			0x0
#define AVA10_FREQ_PLLADJ_MODE			0x1

#define AVA10_DEFAULT_POWER_INFO_CNT		6

#define SERIESRESISTOR				10000
#define THERMISTORNOMINAL			10000
#define BCOEFFICIENT				3500
#define TEMPERATURENOMINAL			25

#define STATBUFLEN_WITHOUT_DBG			(6 * 1024)
#define STATBUFLEN_WITH_DBG			(6 * 7 * 1024)

struct avalon10_pkg {
	uint8_t head[2];
	uint8_t type;
	uint8_t opt;
	uint8_t idx;
	uint8_t cnt;
	uint8_t data[32];
	uint8_t crc[2];
};
#define avalon10_ret avalon10_pkg

struct avalon10_info {
	/* Public data */
	int64_t last_diff1;
	int64_t pending_diff1;
	double last_rej;

	int mm_count;
	int xfer_err_cnt;
	int pool_no;

	struct timeval firsthash;
	struct timeval last_fan_adj;
	struct timeval last_stratum;
	struct timeval last_detect;

	cglock_t update_lock;

	struct pool pool0;
	struct pool pool1;
	struct pool pool2;

	bool work_restart;

	uint32_t last_jobid;

	/* For connecter */
	char auc_version[AVA10_AUC_VER_LEN + 1];

	int auc_speed;
	int auc_xdelay;
	int auc_sensor;

	struct i2c_ctx *i2c_slaves[AVA10_DEFAULT_MODULARS];

	uint8_t connecter; /* AUC or Other */

	/* For modulars */
	bool enable[AVA10_DEFAULT_MODULARS];
	bool reboot[AVA10_DEFAULT_MODULARS];

	struct timeval elapsed[AVA10_DEFAULT_MODULARS];

	uint8_t mm_dna[AVA10_DEFAULT_MODULARS][AVA10_MM_DNA_LEN];
	char mm_version[AVA10_DEFAULT_MODULARS][AVA10_MM_VER_LEN + 1]; /* It's a string */
	uint32_t total_asics[AVA10_DEFAULT_MODULARS];
	uint32_t max_ntime; /* Maximum: 7200 */

	uint8_t mod_type[AVA10_DEFAULT_MODULARS][8];
	uint8_t miner_count[AVA10_DEFAULT_MODULARS];
	uint8_t asic_count[AVA10_DEFAULT_MODULARS];

	uint32_t freq_mode[AVA10_DEFAULT_MODULARS];
	int led_indicator[AVA10_DEFAULT_MODULARS];
	int fan_pct[AVA10_DEFAULT_MODULARS];
	int fan_cpm[AVA10_DEFAULT_MODULARS][2];

	int temp[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT][AVA10_DEFAULT_ASIC_MAX];
	int temp_mm[AVA10_DEFAULT_MODULARS];

	uint32_t core_volt[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT] \
			  [AVA10_DEFAULT_ASIC_MAX][AVA10_DEFAULT_CORE_VOLT_CNT];

	int ro[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT][AVA10_DEFAULT_ASIC_MAX];

	int temp_target[AVA10_DEFAULT_MODULARS];
	int temp_overheat[AVA10_DEFAULT_MODULARS];

	/* pid controler*/
	int pid_p[AVA10_DEFAULT_MODULARS];
	int pid_i[AVA10_DEFAULT_MODULARS];
	int pid_d[AVA10_DEFAULT_MODULARS];
	double pid_u[AVA10_DEFAULT_MODULARS];
	int pid_e[AVA10_DEFAULT_MODULARS][3];
	int pid_0[AVA10_DEFAULT_MODULARS];

	int set_hash_od[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT];
	int set_voltage_level[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT];
	uint32_t set_frequency[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT][AVA10_DEFAULT_PLL_CNT];
	uint32_t get_frequency[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT][AVA10_DEFAULT_ASIC_MAX][AVA10_DEFAULT_PLL_CNT];

	uint16_t get_voltage[AVA10_DEFAULT_MODULARS][1]; /* Output is the same */
	uint32_t get_pll[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT][AVA10_DEFAULT_PLL_CNT];

	uint32_t get_asic[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT][AVA10_DEFAULT_ASIC_MAX][6];

	int8_t factory_info[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_FACTORY_INFO_CNT + 1];

	uint64_t local_works[AVA10_DEFAULT_MODULARS];
	uint64_t local_works_i[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT];
	uint64_t hw_works[AVA10_DEFAULT_MODULARS];
	uint64_t hw_works_i[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT];
	uint64_t chip_matching_work[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT][AVA10_DEFAULT_ASIC_MAX];

	uint32_t error_code[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT + 1];
	uint32_t error_crc[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT];
	uint8_t error_polling_cnt[AVA10_DEFAULT_MODULARS];

	uint64_t diff1[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT];

	uint16_t power_info[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_POWER_INFO_CNT];

	bool conn_overloaded;
};

struct avalon10_iic_info {
	uint8_t iic_op;
	union {
		uint32_t aucParam[2];
		uint8_t slave_addr;
	} iic_param;
};

struct avalon10_dev_description {
	uint8_t dev_id_str[8];
	uint8_t miner_count;	/* it should not greater than AVA10_DEFAULT_MINER_CNT */
	uint8_t asic_count;	/* asic count each miner, it should not great than AVA10_DEFAULT_ASIC_MAX */
	int set_voltage_level;
	uint16_t set_freq[AVA10_DEFAULT_PLL_CNT];
};

#define AVA10_WRITE_SIZE (sizeof(struct avalon10_pkg))
#define AVA10_READ_SIZE AVA10_WRITE_SIZE

#define AVA10_SEND_OK	0
#define AVA10_SEND_ERROR -1

extern char *set_avalon10_fan(char *arg);
extern char *set_avalon10_freq(char *arg);
extern char *set_avalon10_voltage_level(char *arg);
extern char *set_avalon10_voltage_level_offset(char *arg);
extern int opt_avalon10_temp_target;
extern int opt_avalon10_polling_delay;
extern int opt_avalon10_aucspeed;
extern int opt_avalon10_aucxdelay;
extern int opt_avalon10_smart_speed;
extern int opt_avalon10_ssdn_pro;
extern bool opt_avalon10_iic_detect;
extern int opt_avalon10_freq_sel;
extern int opt_avalon10_hash_od;
extern uint32_t opt_avalon10_th_pass;
extern uint32_t opt_avalon10_th_fail;
extern uint32_t opt_avalon10_th_init;
extern uint32_t opt_avalon10_th_mssel;
extern uint32_t opt_avalon10_lv1_th_msadd;
extern uint32_t opt_avalon10_lv1_th_ms;
extern uint32_t opt_avalon10_lv2_th_msadd;
extern uint32_t opt_avalon10_lv2_th_ms;
extern uint32_t opt_avalon10_lv3_th_msadd;
extern uint32_t opt_avalon10_lv3_th_ms;
extern uint32_t opt_avalon10_lv4_th_msadd;
extern uint32_t opt_avalon10_lv4_th_ms;
extern uint32_t opt_avalon10_th_timeout;
extern uint32_t opt_avalon10_nonce_mask;
extern uint32_t opt_avalon10_nonce_check;
extern uint32_t opt_avalon10_mux_l2h;
extern uint32_t opt_avalon10_mux_h2l;
extern uint32_t opt_avalon10_h2ltime0_spd;
extern uint32_t opt_avalon10_roll_enable;
extern uint32_t opt_avalon10_spdlow;
extern uint32_t opt_avalon10_spdhigh;
extern uint32_t opt_avalon10_pid_p;
extern uint32_t opt_avalon10_pid_i;
extern uint32_t opt_avalon10_pid_d;
extern uint32_t opt_avalon10_adjust_voltage;
extern uint32_t opt_avalon10_core_clk_sel;
extern uint32_t opt_avalon10_target_diff;

#endif /* USE_AVALON10 */
#endif /* _AVALON10_H_ */
