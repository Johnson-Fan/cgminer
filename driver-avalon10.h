/*
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

#ifdef USE_AVALON10

#define AVA10_DEFAULT_FAN_MIN		5 /* % */
#define AVA10_DEFAULT_FAN_MAX		100

#define AVA10_DEFAULT_TEMP_MIN		0
#define AVA10_DEFAULT_TEMP_MAX		100
#define AVA10_DEFAULT_TEMP_TARGET	80
#define AVA10_DEFAULT_TEMP_OVERHEAT	105

#define AVA10_DEFAULT_VOLTAGE_LEVEL_MIN	0
#define AVA10_DEFAULT_VOLTAGE_LEVEL_MAX	35
#define AVA10_INVALID_VOLTAGE_LEVEL	-1

#define AVA10_DEFAULT_VOLTAGE_LEVEL_OFFSET_MIN	-2
#define AVA10_DEFAULT_VOLTAGE_LEVEL_OFFSET	0
#define AVA10_DEFAULT_VOLTAGE_LEVEL_OFFSET_MAX	1

#define AVA10_DEFAULT_FACTORY_INFO_0_MIN		0
#define AVA10_DEFAULT_FACTORY_INFO_0		0
#define AVA10_DEFAULT_FACTORY_INFO_0_MAX		35
#define AVA10_DEFAULT_FACTORY_INFO_0_CNT		1
#define AVA10_DEFAULT_FACTORY_INFO_0_IGNORE	36

#define AVA10_DEFAULT_FACTORY_INFO_1_CNT		3

#define AVA10_DEFAULT_FREQUENCY_0M	0
#define AVA10_DEFAULT_FREQUENCY_462M	462
#define AVA10_DEFAULT_FREQUENCY_512M	512
#define AVA10_DEFAULT_FREQUENCY_562M	562
#define AVA10_DEFAULT_FREQUENCY_MAX	1200
#define AVA10_DEFAULT_FREQUENCY		(AVA10_DEFAULT_FREQUENCY_MAX)
#define AVA10_DEFAULT_FREQUENCY_SEL	3

#define AVA10_DEFAULT_MODULARS		7	/* Only support 6 modules maximum with one AUC */
#define AVA10_DEFAULT_MINER_CNT		2
#define AVA10_DEFAULT_ASIC_MAX		68
#define AVA10_DEFAULT_PLL_CNT		4
#define AVA10_DEFAULT_CORE_VOLT_CNT	8

#define AVA10_DEFAULT_POLLING_DELAY	20 /* ms */

#define AVA10_DEFAULT_SMARTSPEED_OFF	0
#define AVA10_DEFAULT_SMARTSPEED_MODE1	1
#define AVA10_DEFAULT_SMART_SPEED	(AVA10_DEFAULT_SMARTSPEED_MODE1)

#define AVA10_DEFAULT_TH_PASS		150
#define AVA10_DEFAULT_TH_FAIL		17000
#define AVA10_DEFAULT_TH_INIT		32767
#define AVA10_DEFAULT_TH_ADD		0
#define AVA10_DEFAULT_TH_MS		12
#define AVA10_DEFAULT_TH_TIMEOUT		385000
#define AVA10_DEFAULT_NONCE_MASK 	24
#define AVA10_DEFAULT_NONCE_CHECK	1
#define AVA10_DEFAULT_MUX_L2H		0
#define AVA10_DEFAULT_MUX_H2L		1
#define AVA10_DEFAULT_H2LTIME0_SPD	3
#define AVA10_DEFAULT_ROLL_ENABLE	1
#define AVA10_DEFAULT_SPDLOW		1
#define AVA10_DEFAULT_SPDHIGH		3
#define AVA10_DEFAULT_TBASE		0

/* PID CONTROLLER*/
#define AVA10_DEFAULT_PID_P		2
#define AVA10_DEFAULT_PID_I		5
#define AVA10_DEFAULT_PID_D		0
#define AVA10_DEFAULT_PID_TEMP_MIN	50
#define AVA10_DEFAULT_PID_TEMP_MAX	100

#define AVA10_DEFAULT_ADJUST_VOLTAGE	1

#define AVA10_DEFAULT_ASIC_AVERAGE_TEMP_START	12
#define AVA10_DEFAULT_ASIC_AVERAGE_TEMP_END	21

#define AVA10_DEFAULT_IIC_DETECT		false

#define AVA10_PWM_MAX                    0x3FF
#define AVA10_DRV_DIFFMAX		2700
#define AVA10_ASIC_TIMEOUT_CONST		419430400 /* (2^32 * 1000) / (256 * 40) */

#define AVA10_MODULE_DETECT_INTERVAL	30 /* 30 s */

#define AVA10_AUC_VER_LEN	12	/* Version length: 12 (AUC-YYYYMMDD) */
#define AVA10_AUC_SPEED		400000
#define AVA10_AUC_XDELAY  	19200	/* 4800 = 1ms in AUC (11U14)  */
#define AVA10_AUC_P_SIZE		64

#define AVA10_CONNECTER_AUC	1
#define AVA10_CONNECTER_IIC	2

/* avalon10 protocol package type from MM protocol.h */
#define AVA10_MM_VER_LEN		15
#define AVA10_MM_DNA_LEN		8
#define AVA10_H1			'C'
#define AVA10_H2			'N'

#define AVA10_P_COINBASE_SIZE	(6 * 1024 + 64)
#define AVA10_P_MERKLES_COUNT	30

#define AVA10_P_COUNT		40
#define AVA10_P_DATA_LEN		32

/* Broadcase with block iic_write*/
#define AVA10_P_DETECT		0x10

/* Broadcase With non-block iic_write*/
#define AVA10_P_STATIC		0x11
#define AVA10_P_JOB_ID		0x12
#define AVA10_P_COINBASE		0x13
#define AVA10_P_MERKLES		0x14
#define AVA10_P_HEADER		0x15
#define AVA10_P_TARGET		0x16
#define AVA10_P_JOB_FIN		0x17
#define AVA10_P_VMASK		0x19

/* Broadcase or with I2C address */
#define AVA10_P_SET		0x20
#define AVA10_P_SET_FIN		0x21
#define AVA10_P_SET_VOLT		0x22
#define AVA10_P_SET_PMU		0x24
#define AVA10_P_SET_PLL		0x25
#define AVA10_P_SET_SS		0x26
/* 0x27 reserved */
#define AVA10_P_SET_FAC		0x28

/* Have to send with I2C address */
#define AVA10_P_POLLING		0x30
#define AVA10_P_SYNC		0x31
#define AVA10_P_TEST		0x32
#define AVA10_P_RSTMMTX		0x33
#define AVA10_P_GET_VOLT		0x34

/* Back to host */
#define AVA10_P_ACKDETECT	0x40
#define AVA10_P_STATUS		0x41
#define AVA10_P_NONCE		0x42
#define AVA10_P_TEST_RET		0x43
#define AVA10_P_STATUS_VOLT	0x46
#define AVA10_P_STATUS_POWER	0x48
#define AVA10_P_STATUS_PLL	0x49
#define AVA10_P_STATUS_ASIC	0x4b
#define AVA10_P_STATUS_PVT	0x4c
#define AVA10_P_STATUS_FAC	0x4d
#define AVA10_P_SET_ADJUST_VOLT	0x51

#define AVA10_MODULE_BROADCAST	0
/* End of avalon10 protocol package type */

#define AVA10_IIC_RESET		0xa0
#define AVA10_IIC_INIT		0xa1
#define AVA10_IIC_DEINIT		0xa2
#define AVA10_IIC_XFER		0xa5
#define AVA10_IIC_INFO		0xa6

#define AVA10_FREQ_INIT_MODE	0x0
#define AVA10_FREQ_PLLADJ_MODE	0x1

#define AVA10_DEFAULT_FACTORY_INFO_CNT	(AVA10_DEFAULT_FACTORY_INFO_0_CNT + AVA10_DEFAULT_FACTORY_INFO_1_CNT)

#define AVA10_DEFAULT_POWER_INFO_CNT	6

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

	uint8_t connecter; /* AUC or IIC */

	/* For modulars */
	bool enable[AVA10_DEFAULT_MODULARS];
	bool reboot[AVA10_DEFAULT_MODULARS];

	struct timeval elapsed[AVA10_DEFAULT_MODULARS];

	uint8_t mm_dna[AVA10_DEFAULT_MODULARS][AVA10_MM_DNA_LEN];
	char mm_version[AVA10_DEFAULT_MODULARS][AVA10_MM_VER_LEN + 1]; /* It's a string */
	uint32_t total_asics[AVA10_DEFAULT_MODULARS];
	uint32_t max_ntime; /* Maximum: 7200 */

	int mod_type[AVA10_DEFAULT_MODULARS];
	uint8_t miner_count[AVA10_DEFAULT_MODULARS];
	uint8_t asic_count[AVA10_DEFAULT_MODULARS];

	uint32_t freq_mode[AVA10_DEFAULT_MODULARS];
	int led_indicator[AVA10_DEFAULT_MODULARS];
	int fan_pct[AVA10_DEFAULT_MODULARS];
	int fan_cpm[AVA10_DEFAULT_MODULARS];

	int temp[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT][AVA10_DEFAULT_ASIC_MAX];
	int temp_mm[AVA10_DEFAULT_MODULARS];

	uint32_t core_volt[AVA10_DEFAULT_MODULARS][AVA10_DEFAULT_MINER_CNT] \
			  [AVA10_DEFAULT_ASIC_MAX][AVA10_DEFAULT_CORE_VOLT_CNT];

	uint8_t cutoff[AVA10_DEFAULT_MODULARS];
	int temp_target[AVA10_DEFAULT_MODULARS];
	int temp_overheat[AVA10_DEFAULT_MODULARS];

	/* pid controler*/
	int pid_p[AVA10_DEFAULT_MODULARS];
	int pid_i[AVA10_DEFAULT_MODULARS];
	int pid_d[AVA10_DEFAULT_MODULARS];
	double pid_u[AVA10_DEFAULT_MODULARS];
	int pid_e[AVA10_DEFAULT_MODULARS][3];
	int pid_0[AVA10_DEFAULT_MODULARS];

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

	uint64_t diff1[AVA10_DEFAULT_MODULARS];

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
	int mod_type;
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
extern bool opt_avalon10_iic_detect;
extern int opt_avalon10_freq_sel;
extern uint32_t opt_avalon10_th_pass;
extern uint32_t opt_avalon10_th_fail;
extern uint32_t opt_avalon10_th_init;
extern uint32_t opt_avalon10_th_ms;
extern uint32_t opt_avalon10_th_timeout;
extern uint32_t opt_avalon10_th_add;
extern uint32_t opt_avalon10_nonce_mask;
extern uint32_t opt_avalon10_nonce_check;
extern uint32_t opt_avalon10_mux_l2h;
extern uint32_t opt_avalon10_mux_h2l;
extern uint32_t opt_avalon10_h2ltime0_spd;
extern uint32_t opt_avalon10_roll_enable;
extern uint32_t opt_avalon10_spdlow;
extern uint32_t opt_avalon10_spdhigh;
extern uint32_t opt_avalon10_tbase;
extern uint32_t opt_avalon10_pid_p;
extern uint32_t opt_avalon10_pid_i;
extern uint32_t opt_avalon10_pid_d;
extern uint32_t opt_avalon10_adjust_voltage;

#endif /* USE_AVALON10 */
#endif /* _AVALON10_H_ */
