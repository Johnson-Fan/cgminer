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
#include <math.h>
#include "config.h"

#include "miner.h"
#include "driver-avalon10.h"
#include "crc.h"
#include "sha2.h"
#include "hexdump.c"

int opt_avalon10_temp_target = AVA10_DEFAULT_TEMP_TARGET;

int opt_avalon10_fan_min = AVA10_DEFAULT_FAN_MIN;
int opt_avalon10_fan_max = AVA10_DEFAULT_FAN_MAX;

int opt_avalon10_voltage_level = AVA10_INVALID_VOLTAGE_LEVEL;
int opt_avalon10_voltage_level_offset = AVA10_DEFAULT_VOLTAGE_LEVEL_OFFSET;

int opt_avalon10_freq[AVA10_DEFAULT_PLL_CNT] =
{
	AVA10_DEFAULT_FREQUENCY,
	AVA10_DEFAULT_FREQUENCY,
	AVA10_DEFAULT_FREQUENCY,
	AVA10_DEFAULT_FREQUENCY
};

int opt_avalon10_freq_sel = AVA10_DEFAULT_FREQUENCY_SEL;

int opt_avalon10_polling_delay = AVA10_DEFAULT_POLLING_DELAY;

int opt_avalon10_aucspeed = AVA10_AUC_SPEED;
int opt_avalon10_aucxdelay = AVA10_AUC_XDELAY;

int opt_avalon10_smart_speed = AVA10_DEFAULT_SMART_SPEED;

uint32_t opt_avalon10_th_pass = AVA10_DEFAULT_TH_PASS;
uint32_t opt_avalon10_th_fail = AVA10_DEFAULT_TH_FAIL;
uint32_t opt_avalon10_th_init = AVA10_DEFAULT_TH_INIT;
uint32_t opt_avalon10_th_mssel = AVA10_DEFAULT_TH_MSSEL;
uint32_t opt_avalon10_th_timeout = AVA10_DEFAULT_TH_TIMEOUT;
uint32_t opt_avalon10_lv1_th_msadd = AVA10_DEFAULT_LV1_TH_MSADD;
uint32_t opt_avalon10_lv1_th_ms = AVA10_DEFAULT_LV1_TH_MS;
uint32_t opt_avalon10_lv2_th_msadd = AVA10_DEFAULT_LV2_TH_MSADD;
uint32_t opt_avalon10_lv2_th_ms = AVA10_DEFAULT_LV2_TH_MS;
uint32_t opt_avalon10_lv3_th_msadd = AVA10_DEFAULT_LV3_TH_MSADD;
uint32_t opt_avalon10_lv3_th_ms = AVA10_DEFAULT_LV3_TH_MS;
uint32_t opt_avalon10_lv4_th_msadd = AVA10_DEFAULT_LV4_TH_MSADD;
uint32_t opt_avalon10_lv4_th_ms = AVA10_DEFAULT_LV4_TH_MS;
uint32_t opt_avalon10_nonce_mask = AVA10_DEFAULT_NONCE_MASK;
uint32_t opt_avalon10_nonce_check = AVA10_DEFAULT_NONCE_CHECK;
uint32_t opt_avalon10_mux_l2h = AVA10_DEFAULT_MUX_L2H;
uint32_t opt_avalon10_mux_h2l = AVA10_DEFAULT_MUX_H2L;
uint32_t opt_avalon10_h2ltime0_spd = AVA10_DEFAULT_H2LTIME0_SPD;
uint32_t opt_avalon10_roll_enable = AVA10_DEFAULT_ROLL_ENABLE;
uint32_t opt_avalon10_spdlow = AVA10_DEFAULT_SPDLOW;
uint32_t opt_avalon10_spdhigh = AVA10_DEFAULT_SPDHIGH;
uint32_t opt_avalon10_tbase = AVA10_DEFAULT_TBASE;

uint32_t opt_avalon10_pid_p = AVA10_DEFAULT_PID_P;
uint32_t opt_avalon10_pid_i = AVA10_DEFAULT_PID_I;
uint32_t opt_avalon10_pid_d = AVA10_DEFAULT_PID_D;

uint32_t opt_avalon10_adjust_voltage = AVA10_DEFAULT_ADJUST_VOLTAGE;

uint32_t opt_avalon10_core_clk_sel = AVA10_DEFAULT_CORE_CLK_SEL;

uint32_t opt_avalon10_target_diff = AVA10_DRV_DIFFMAX;

uint32_t cpm_table[] =
{
	0x04400000,
	0x04000000,
	0x008ffbe1,
	0x0097fde1,
	0x009fffe1,
	0x009ddf61,
	0x009dcf61,
	0x009f47c1,
	0x009fbfe1,
	0x009f37c1,
	0x009daf61,
	0x009b26c1,
	0x009da761,
	0x00999e61,
	0x009b9ee1,
	0x009d9f61,
	0x009f9fe1,
	0x00991641,
	0x009a96a1,
	0x009c1701,
	0x009d9761,
	0x009f17c1,
	0x00958d61,
	0x00968da1,
	0x00978de1,
	0x00988e21,
	0x00998e61,
	0x009a8ea1,
	0x009b8ee1,
	0x009c8f21,
	0x009d8f61,
	0x009e8fa1,
	0x009f8fe1,
	0x00900401,
	0x00908421,
	0x00910441,
	0x00918461,
	0x00920481,
	0x009284a1,
	0x009304c1,
	0x009384e1,
	0x00940501,
	0x00948521,
	0x00950541,
	0x00958561,
	0x00960581,
	0x009685a1,
	0x009705c1,
	0x009785e1
};

uint32_t cpm_table_point[] =
{
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01,
	0x00900c01, /* 412.5MHz */
	0x00910c41,
	0x00920c81,
	0x00930cc1,
	0x00940d01,
	0x00950d41,
	0x00960d81,
	0x00970dc1,
	0x00980e01,
	0x00990e41,
	0x009a0e81,
	0x009b0ec1,
	0x009c0f01,
	0x009d0f41,
	0x009e0f81,
	0x009f0fc1, /* 787.5MHz */
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1,
	0x009f0fc1
};

struct avalon10_dev_description avalon10_dev_table[] = {
	{
		"A10",
		AVA10_DEFAULT_MINER_CNT,
		AVA10_DEFAULT_ASIC_MAX,
		AVA10_DEFAULT_VOLTAGE_LEVEL,
		{
			AVA10_DEFAULT_FREQUENCY_0M,
			AVA10_DEFAULT_FREQUENCY_462M,
			AVA10_DEFAULT_FREQUENCY_512M,
			AVA10_DEFAULT_FREQUENCY_562M
		}
	}
};

static uint32_t api_get_cpm(uint32_t freq)
{
	if (freq % 25 == 0)
		return cpm_table[freq / 25];
	else
		return cpm_table_point[(freq - 12) / 25];
}

static uint32_t encode_voltage(int volt_level)
{
	if (volt_level > AVA10_DEFAULT_VOLTAGE_LEVEL_MAX)
		volt_level = AVA10_DEFAULT_VOLTAGE_LEVEL_MAX;
	else if (volt_level < AVA10_DEFAULT_VOLTAGE_LEVEL_MIN)
		volt_level = AVA10_DEFAULT_VOLTAGE_LEVEL_MIN;

	return volt_level;
}

static double decode_pvt_temp(uint16_t pvt_code)
{
	double g = 60.0;
	double h = 200.0;
	double cal5 = 4094.0;
	double j = -0.1;
	double fclkm = 6.25;

	/* Mode2 temperature equation */
	return g + h * (pvt_code / cal5 - 0.5) + j * fclkm;
}

static uint32_t decode_pvt_volt(uint16_t volt)
{
	double vref = 1.20;
	double r = 16384.0; /* 2 ** 14 */
	double c;

	c = vref / 5.0 * (6 * (volt - 0.5) / r - 1.0);

	if (c < 0)
		c = 0;

	return c * 1000;
}

float decode_auc_temp(int value)
{
	float ret, resistance;

	if (!((value > 0) && (value < 33000)))
		return -273;

	resistance = (3.3 * 10000 / value) - 1;
	resistance = SERIESRESISTOR / resistance;
	ret = resistance / THERMISTORNOMINAL;
	ret = logf(ret);
	ret /= BCOEFFICIENT;
	ret += 1.0 / (TEMPERATURENOMINAL + 273.15);
	ret = 1.0 / ret;
	ret -= 273.15;

	return ret;
}

static inline void sha256_prehash(const unsigned char *message, unsigned int len, unsigned char *digest)
{
	int i;
	sha256_ctx ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, message, len);

	for (i = 0; i < 8; i++)
		UNPACK32(ctx.h[i], &digest[i << 2]);
}

char *set_avalon10_fan(char *arg)
{
	int val1, val2, ret;

	ret = sscanf(arg, "%d-%d", &val1, &val2);
	if (ret < 1)
		return "No value passed to avalon10-fan";
	if (ret == 1)
		val2 = val1;

	if (val1 < 0 || val1 > 100 || val2 < 0 || val2 > 100 || val2 < val1)
		return "Invalid value passed to avalon10-fan";

	opt_avalon10_fan_min = val1;
	opt_avalon10_fan_max = val2;

	return NULL;
}

char *set_avalon10_freq(char *arg)
{
	int val[AVA10_DEFAULT_PLL_CNT];
	char *colon, *data;
	int i;

	if (!(*arg))
		return NULL;

	data = arg;
	memset(val, 0, sizeof(val));

	for (i = 0; i < AVA10_DEFAULT_PLL_CNT; i++) {
		colon = strchr(data, ':');
		if (colon)
			*(colon++) = '\0';
		else {
			/* last value */
			if (*data) {
				val[i] = atoi(data);
				if (val[i] > AVA10_DEFAULT_FREQUENCY_MAX)
					return "Invalid value passed to avalon10-freq";
			}
			break;
		}

		if (*data) {
			val[i] = atoi(data);
			if (val[i] > AVA10_DEFAULT_FREQUENCY_MAX)
				return "Invalid value passed to avalon10-freq";
		}
		data = colon;
	}

	for (i = 0; i < AVA10_DEFAULT_PLL_CNT; i++)
		opt_avalon10_freq[i] = val[i];

	return NULL;
}

char *set_avalon10_voltage_level(char *arg)
{
       int val, ret;

       ret = sscanf(arg, "%d", &val);
       if (ret < 1)
               return "No value passed to avalon10-voltage-level";

       if (val < AVA10_DEFAULT_VOLTAGE_LEVEL_MIN || val > AVA10_DEFAULT_VOLTAGE_LEVEL_MAX)
               return "Invalid value passed to avalon10-voltage-level";

       opt_avalon10_voltage_level = val;

       return NULL;
}

char *set_avalon10_voltage_level_offset(char *arg)
{
       int val, ret;

       ret = sscanf(arg, "%d", &val);
       if (ret < 1)
               return "No value passed to avalon10-voltage-level-offset";

       if (val < AVA10_DEFAULT_VOLTAGE_LEVEL_OFFSET_MIN || val > AVA10_DEFAULT_VOLTAGE_LEVEL_OFFSET_MAX)
               return "Invalid value passed to avalon10-voltage-level-offset";

       opt_avalon10_voltage_level_offset = val;

       return NULL;
}

static int job_idcmp(uint8_t *job_id, char *pool_job_id)
{
	int job_id_len;
	unsigned short crc, crc_expect;

	if (!pool_job_id)
		return 1;

	job_id_len = strlen(pool_job_id);
	crc_expect = crc16((unsigned char *)pool_job_id, job_id_len);

	crc = job_id[0] << 8 | job_id[1];

	if (crc_expect == crc)
		return 0;

	applog(LOG_DEBUG, "avalon10: job_id doesn't match! [%04x:%04x (%s)]",
	       crc, crc_expect, pool_job_id);

	return 1;
}

static inline int get_temp_max(struct avalon10_info *info, int addr)
{
	int i, j;
	int max = -273;

	for (i = 0; i < info->miner_count[addr]; i++) {
		for (j = 0; j < info->asic_count[addr]; j++) {
			if (info->temp[addr][i][j] > max)
				max = info->temp[addr][i][j];
		}
	}

	if (max < info->temp_mm[addr])
		max = info->temp_mm[addr];

	return max;
}

static inline int get_temp_average(struct avalon10_info *info, int addr)
{
	int i, j;
	int average = -273;
	int sum = 0;
	int count = 0;
	int tmp;

	for (i = 0; i < info->miner_count[addr]; i++) {
		for (j = 0; j < AVA10_DEFAULT_ASIC_MAX; j++) {
			if (info->temp[addr][i][j] > 0) {
				sum += info->temp[addr][i][j];
				count++;
			}
		}

		if (count) {
			tmp = sum / count;
			if (average < tmp)
				average = tmp;
		}

		sum = 0;
		count = 0;
	}

	if (average < info->temp_mm[addr])
		average = info->temp_mm[addr];

	return average;
}

static inline int get_miner_temp_max(struct avalon10_info *info, int addr, int miner)
{
	int i;
	int max = -273;

	for (i = 0; i < info->asic_count[addr]; i++) {
		if (info->temp[addr][miner][i] > max)
			max = info->temp[addr][miner][i];
	}

	return max;
}

static inline int get_miner_temp_avg(struct avalon10_info *info, int addr, int miner)
{
	int i;
	int sum = 0;
	int count = 0;

	for (i = 0; i <= info->asic_count[addr]; i++) {
		if (info->temp[addr][miner][i] > 0) {
			sum += info->temp[addr][miner][i];
			count++;
		}
	}

	return count ? sum / count : 0;
}

/*
 * Incremental PID controller
 *
 * controller input: u, output: t
 *
 * delta_u = P * [e(k) - e(k-1)] + I * e(k) + D * [e(k) - 2*e(k-1) + e(k-2)];
 * e(k) = t(k) - t[target];
 * u(k) = u(k-1) + delta_u;
 *
 */
static inline uint32_t adjust_fan(struct avalon10_info *info, int id)
{
	int t, ta, temp;
	double delta_u;
	double delta_p, delta_i, delta_d;
	uint32_t pwm;
	static uint8_t count = 0;
	static uint8_t flag = 0;
	static uint16_t time_count = 0;

	t = get_temp_max(info, id);
	ta = get_temp_average(info, id);

	/* Before 10Mins, used max temp */
	if (time_count > 300) {
		if ((t > AVA10_DEFAULT_PID_TEMP_MAX) || flag) {
			temp = t;

			if (!flag)
				flag = 1;

			if (count++ > 5) {
				flag = 0;
				count = 0;
			}
		} else {
			temp = ta;
		}
	} else {
		temp = t;
		time_count++;
	}

	/* update target error */
	info->pid_e[id][2] = info->pid_e[id][1];
	info->pid_e[id][1] = info->pid_e[id][0];
	info->pid_e[id][0] = temp - info->temp_target[id];

	if (temp > AVA10_DEFAULT_PID_TEMP_MAX) {
		info->pid_u[id] = opt_avalon10_fan_max;
	} else if (temp < AVA10_DEFAULT_PID_TEMP_MIN && info->pid_0[id] == 0) {
		info->pid_u[id] = opt_avalon10_fan_min;
	} else if (!info->pid_0[id]) {
			/* first, init u as t */
			info->pid_0[id] = 1;
			info->pid_u[id] = temp;
	} else {
		delta_p = info->pid_p[id] * (info->pid_e[id][0] - info->pid_e[id][1]);
		delta_i = info->pid_i[id] * info->pid_e[id][0];
		delta_d = info->pid_d[id] * (info->pid_e[id][0] - 2 * info->pid_e[id][1] + info->pid_e[id][2]);

		/*Parameter I is int type(1, 2, 3...), but should be used as a smaller value (such as 0.1, 0.01...)*/
		delta_u = delta_p + delta_i / 100 + delta_d;

		info->pid_u[id] += delta_u;
	}

	if(info->pid_u[id] > opt_avalon10_fan_max)
		info->pid_u[id] = opt_avalon10_fan_max;

	if (info->pid_u[id] < opt_avalon10_fan_min)
		info->pid_u[id] = opt_avalon10_fan_min;

	/* Round from float to int */
	info->fan_pct[id] = (int)(info->pid_u[id] + 0.5);
	pwm = get_fan_pwm(info->fan_pct[id]);

	return pwm;
}

static int decode_pkg(struct cgpu_info *avalon10, struct avalon10_ret *ar, int modular_id)
{
	struct avalon10_info *info = avalon10->device_data;
	struct pool *pool, *real_pool;
	struct pool *pool_stratum0 = &info->pool0;
	struct pool *pool_stratum1 = &info->pool1;
	struct pool *pool_stratum2 = &info->pool2;
	struct thr_info *thr = NULL;

	unsigned short expected_crc;
	unsigned short actual_crc;
	uint32_t nonce, nonce2, ntime, miner_id, asic_id, tmp;
	uint32_t micro_job_id, nonce_valid;
	uint8_t job_id[2];
	int pool_no;
	uint32_t i, j;
	int64_t last_diff1;
	uint16_t vin;
	uint16_t power_info;
	uint16_t get_vcore;

	if (likely(avalon10->thr))
		thr = avalon10->thr[0];
	if (ar->head[0] != AVA10_H1 && ar->head[1] != AVA10_H2) {
		applog(LOG_DEBUG, "%s-%d-%d: H1 %02x, H2 %02x",
				avalon10->drv->name, avalon10->device_id, modular_id,
				ar->head[0], ar->head[1]);
		hexdump(ar->data, 32);
		return 1;
	}

	expected_crc = crc16(ar->data, AVA10_P_DATA_LEN);
	actual_crc = ((ar->crc[0] & 0xff) << 8) | (ar->crc[1] & 0xff);
	if (expected_crc != actual_crc) {
		applog(LOG_DEBUG, "%s-%d-%d: %02x: expected crc(%04x), actual_crc(%04x)",
		       avalon10->drv->name, avalon10->device_id, modular_id,
		       ar->type, expected_crc, actual_crc);
		return 1;
	}

	switch(ar->type) {
	case AVA10_P_NONCE:
		applog(LOG_DEBUG, "%s-%d-%d: AVA10_P_NONCE", avalon10->drv->name, avalon10->device_id, modular_id);
		/* NOTE: only support 2 nonce2 */
		for (i = 0; i < 2; i++) {
			memcpy(&tmp, ar->data + i * 16, 4);
			tmp = be32toh(tmp);
			nonce_valid = (tmp >> 28) & 0xf;
			if (!nonce_valid)
				continue;

			micro_job_id = (tmp >> 24) & 0xf;
			ntime = (tmp >> 16) & 0xff;
			miner_id = (tmp >> 8) & 0xff;
			asic_id = tmp & 0xff;

			memcpy(&tmp, ar->data + i * 16 + 4, 4);
			nonce = be32toh(tmp);

			memcpy(&tmp, ar->data + i * 16 + 8, 4);
			nonce2 = be32toh(tmp);

			job_id[0] = ar->data[i * 16 + 12];
			job_id[1] = ar->data[i * 16 + 13];
			pool_no = (ar->data[i * 16 + 14] | (ar->data[i * 16 + 15] << 8));

			/* Can happen during init sequence before add_cgpu */
			if (unlikely(!thr))
				break;

			if ((miner_id >= AVA10_DEFAULT_MINER_CNT) || (asic_id >= AVA10_DEFAULT_ASIC_MAX)) {
				applog(LOG_NOTICE, "%s-%d-%d: Wrong miner_id:%d or asic_id:%d",
								avalon10->drv->name, avalon10->device_id, modular_id, miner_id, asic_id);
				continue;
			}

			if (pool_no >= total_pools || pool_no < 0) {
				applog(LOG_DEBUG, "%s-%d-%d: Wrong pool_no %d",
								avalon10->drv->name, avalon10->device_id, modular_id, pool_no);
				continue;
			}

			if (ntime > info->max_ntime)
				info->max_ntime = ntime;

			applog(LOG_NOTICE, "%s-%d-%d: Found! P:%d - N2:%08x N:%08x NR:%d/%d [M:%d, A:%d, C:%d, MID:%d]",
								avalon10->drv->name, avalon10->device_id, modular_id, pool_no, nonce2,
								nonce, ntime, info->max_ntime, miner_id, asic_id, nonce & 0xff, micro_job_id);

			real_pool = pool = pools[pool_no];
			if (job_idcmp(job_id, pool->swork.job_id)) {
				if (!job_idcmp(job_id, pool_stratum0->swork.job_id)) {
					applog(LOG_DEBUG, "%s-%d-%d: Match to previous stratum0! (%s)",
							avalon10->drv->name, avalon10->device_id, modular_id,
							pool_stratum0->swork.job_id);
					pool = pool_stratum0;
				} else if (!job_idcmp(job_id, pool_stratum1->swork.job_id)) {
					applog(LOG_DEBUG, "%s-%d-%d: Match to previous stratum1! (%s)",
							avalon10->drv->name, avalon10->device_id, modular_id,
							pool_stratum1->swork.job_id);
					pool = pool_stratum1;
				} else if (!job_idcmp(job_id, pool_stratum2->swork.job_id)) {
					applog(LOG_DEBUG, "%s-%d-%d: Match to previous stratum2! (%s)",
							avalon10->drv->name, avalon10->device_id, modular_id,
							pool_stratum2->swork.job_id);
					pool = pool_stratum2;
				} else {
					applog(LOG_ERR, "%s-%d-%d: Cannot match to any stratum! (%s)",
							avalon10->drv->name, avalon10->device_id, modular_id,
							pool->swork.job_id);
					if (likely(thr))
						inc_hw_errors(thr);
					info->hw_works_i[modular_id][miner_id]++;
					continue;
				}
			}

			last_diff1 = avalon10->diff1;
			if (!submit_nonce2_nonce(thr, pool, real_pool, nonce2, nonce, ntime, micro_job_id))
				info->hw_works_i[modular_id][miner_id]++;
			else {
				info->diff1[modular_id][miner_id] += (avalon10->diff1 - last_diff1);
				info->chip_matching_work[modular_id][miner_id][asic_id]++;
			}
		}
		break;
	case AVA10_P_STATUS:
		applog(LOG_DEBUG, "%s-%d-%d: AVA10_P_STATUS", avalon10->drv->name, avalon10->device_id, modular_id);
		hexdump(ar->data, 32);
		memcpy(&tmp, ar->data, 4);
		tmp = be32toh(tmp);
		info->temp_mm[modular_id] = tmp;
		avalon10->temp = decode_auc_temp(info->auc_sensor);

		memcpy(&tmp, ar->data + 4, 4);
		tmp = be32toh(tmp);
		info->fan_cpm[modular_id][0] = tmp;

		memcpy(&tmp, ar->data + 8, 4);
		tmp = be32toh(tmp);
		info->fan_cpm[modular_id][1] = tmp;

		memcpy(&tmp, ar->data + 12, 4);
		info->local_works_i[modular_id][ar->idx] += be32toh(tmp);

		memcpy(&tmp, ar->data + 16, 4);
		info->hw_works_i[modular_id][ar->idx] += be32toh(tmp);

		memcpy(&tmp, ar->data + 20, 4);
		info->error_code[modular_id][ar->idx] = be32toh(tmp);

		memcpy(&tmp, ar->data + 24, 4);
		info->error_code[modular_id][ar->cnt] = be32toh(tmp);

		memcpy(&tmp, ar->data + 28, 4);
		info->error_crc[modular_id][ar->idx] += be32toh(tmp);
		break;
	case AVA10_P_STATUS_VOLT:
		applog(LOG_DEBUG, "%s-%d-%d: AVA10_P_STATUS_VOLT", avalon10->drv->name, avalon10->device_id, modular_id);
		memcpy(&get_vcore, ar->data, 2);
		info->get_voltage[modular_id][0] = be16toh(get_vcore);
		break;
	case AVA10_P_STATUS_PLL:
		applog(LOG_DEBUG, "%s-%d-%d: AVA10_P_STATUS_PLL", avalon10->drv->name, avalon10->device_id, modular_id);
		for (i = 0; i < AVA10_DEFAULT_MINER_CNT; i++) {
			for (j = 0; j < AVA10_DEFAULT_PLL_CNT; j++) {
				memcpy(&tmp, ar->data + i * AVA10_DEFAULT_PLL_CNT * 4 + j * 4, 4);
				info->get_pll[modular_id][i][j] = be32toh(tmp);
			}
		}
		break;
	case AVA10_P_STATUS_PVT:
		applog(LOG_DEBUG, "%s-%d-%d: AVA10_P_STATUS_PVT", avalon10->drv->name, avalon10->device_id, modular_id);
		if (!info->asic_count[modular_id])
			break;

		if (ar->idx < info->asic_count[modular_id]) {
			for (i = 0; i < info->miner_count[modular_id]; i++) {
				memcpy(&tmp, ar->data + i * 4, 2);
				tmp = be16toh(tmp);
				info->temp[modular_id][i][ar->idx] = decode_pvt_temp(tmp);

				memcpy(&tmp, ar->data + i * 4 + 2, 2);
				tmp = be16toh(tmp);
				info->core_volt[modular_id][i][ar->idx][0] = decode_pvt_volt(tmp);
			}
		}
		break;
	case AVA10_P_STATUS_ASIC:
		{
			int miner_id;
			int asic_id;
			uint16_t freq;

			if (!info->asic_count[modular_id])
				break;

			miner_id = ar->idx / info->asic_count[modular_id];
			asic_id = ar->idx % info->asic_count[modular_id];

			applog(LOG_DEBUG, "%s-%d-%d: AVA10_P_STATUS_ASIC %d-%d",
						avalon10->drv->name, avalon10->device_id, modular_id,
						miner_id, asic_id);

			if (ar->data[31]) {
				memcpy(&tmp, ar->data + 0, 4);
				info->get_asic[modular_id][miner_id][asic_id][0] = be32toh(tmp);

				memcpy(&tmp, ar->data + 4, 4);
				info->get_asic[modular_id][miner_id][asic_id][1] = be32toh(tmp);
			}

			for (i = 0; i < AVA10_DEFAULT_PLL_CNT; i++)
				info->get_asic[modular_id][miner_id][asic_id][2 + i] = ar->data[8 + i];

			for (i = 0; i < AVA10_DEFAULT_PLL_CNT; i++) {
				memcpy(&freq, ar->data + 8 + AVA10_DEFAULT_PLL_CNT + i * 2, 2);
				info->get_frequency[modular_id][miner_id][asic_id][i] = be16toh(freq);
			}
		}
		break;
	case AVA10_P_STATUS_POWER:
		applog(LOG_DEBUG, "%s-%d-%d: AVA10_P_STATUS_POWER", avalon10->drv->name, avalon10->device_id, modular_id);

		if (ar->data[12]) {
			for (i = 0; i < AVA10_DEFAULT_POWER_INFO_CNT; i++) {
				memcpy(&power_info, ar->data + i * 2, 2);
				info->power_info[modular_id][i] = be16toh(power_info);
			}
		}
		break;
	case AVA10_P_STATUS_FAC:
		applog(LOG_DEBUG, "%s-%d-%d: AVA10_P_STATUS_FAC", avalon10->drv->name, avalon10->device_id, modular_id);
		info->factory_info[modular_id][0] = ar->data[0];
		info->factory_info[modular_id][AVA10_DEFAULT_FACTORY_INFO_CNT] = ar->data[1];
		break;
	default:
		applog(LOG_DEBUG, "%s-%d-%d: Unknown response %x", avalon10->drv->name, avalon10->device_id, modular_id, ar->type);
		break;
	}
	return 0;
}

/*
 #  IIC packet format: length[1]+transId[1]+sesId[1]+req[1]+data[60]
 #  length: 4+len(data)
 #  transId: 0
 #  sesId: 0
 #  req: checkout the header file
 #  data:
 #    INIT: clock_rate[4] + reserved[4] + payload[52]
 #    XFER: txSz[1]+rxSz[1]+options[1]+slaveAddr[1] + payload[56]
 */
static int avalon10_auc_init_pkg(uint8_t *iic_pkg, struct avalon10_iic_info *iic_info, uint8_t *buf, int wlen, int rlen)
{
	memset(iic_pkg, 0, AVA10_AUC_P_SIZE);

	switch (iic_info->iic_op) {
	case AVA10_IIC_INIT:
		iic_pkg[0] = 12;	/* 4 bytes IIC header + 4 bytes speed + 4 bytes xfer delay */
		iic_pkg[3] = AVA10_IIC_INIT;
		iic_pkg[4] = iic_info->iic_param.aucParam[0] & 0xff;
		iic_pkg[5] = (iic_info->iic_param.aucParam[0] >> 8) & 0xff;
		iic_pkg[6] = (iic_info->iic_param.aucParam[0] >> 16) & 0xff;
		iic_pkg[7] = iic_info->iic_param.aucParam[0] >> 24;
		iic_pkg[8] = iic_info->iic_param.aucParam[1] & 0xff;
		iic_pkg[9] = (iic_info->iic_param.aucParam[1] >> 8) & 0xff;
		iic_pkg[10] = (iic_info->iic_param.aucParam[1] >> 16) & 0xff;
		iic_pkg[11] = iic_info->iic_param.aucParam[1] >> 24;
		break;
	case AVA10_IIC_XFER:
		iic_pkg[0] = 8 + wlen;
		iic_pkg[3] = AVA10_IIC_XFER;
		iic_pkg[4] = wlen;
		iic_pkg[5] = rlen;
		iic_pkg[7] = iic_info->iic_param.slave_addr;
		if (buf && wlen)
			memcpy(iic_pkg + 8, buf, wlen);
		break;
	case AVA10_IIC_RESET:
	case AVA10_IIC_DEINIT:
	case AVA10_IIC_INFO:
		iic_pkg[0] = 4;
		iic_pkg[3] = iic_info->iic_op;
		break;

	default:
		break;
	}

	return 0;
}

static int avalon10_auc_xfer(struct cgpu_info *avalon10,
			    uint8_t *wbuf, int wlen, int *write,
			    uint8_t *rbuf, int rlen, int *read)
{
	int err = -1;

	if (unlikely(avalon10->usbinfo.nodev))
		goto out;

	usb_buffer_clear(avalon10);
	err = usb_write(avalon10, (char *)wbuf, wlen, write, C_AVA10_WRITE);
	if (err || *write != wlen) {
		applog(LOG_DEBUG, "%s-%d: AUC xfer %d, w(%d-%d)!", avalon10->drv->name, avalon10->device_id, err, wlen, *write);
		usb_nodev(avalon10);
		goto out;
	}

	cgsleep_ms(opt_avalon10_aucxdelay / 4800 + 1);

	rlen += 4;		/* Add 4 bytes IIC header */
	err = usb_read(avalon10, (char *)rbuf, rlen, read, C_AVA10_READ);
	if (err || *read != rlen || *read != rbuf[0]) {
		applog(LOG_DEBUG, "%s-%d: AUC xfer %d, r(%d-%d-%d)!", avalon10->drv->name, avalon10->device_id, err, rlen - 4, *read, rbuf[0]);
		hexdump(rbuf, rlen);
		return -1;
	}
	*read = rbuf[0] - 4;	/* Remove 4 bytes IIC header */
out:
	return err;
}

static int avalon10_auc_init(struct cgpu_info *avalon10, char *ver)
{
	struct avalon10_iic_info iic_info;
	int err, wlen, rlen;
	uint8_t wbuf[AVA10_AUC_P_SIZE];
	uint8_t rbuf[AVA10_AUC_P_SIZE];

	if (unlikely(avalon10->usbinfo.nodev))
		return 1;

	/* Try to clean the AUC buffer */
	usb_buffer_clear(avalon10);
	err = usb_read(avalon10, (char *)rbuf, AVA10_AUC_P_SIZE, &rlen, C_AVA10_READ);
	applog(LOG_DEBUG, "%s-%d: AUC usb_read %d, %d!", avalon10->drv->name, avalon10->device_id, err, rlen);
	hexdump(rbuf, AVA10_AUC_P_SIZE);

	/* Reset */
	iic_info.iic_op = AVA10_IIC_RESET;
	rlen = 0;
	avalon10_auc_init_pkg(wbuf, &iic_info, NULL, 0, rlen);

	memset(rbuf, 0, AVA10_AUC_P_SIZE);
	err = avalon10_auc_xfer(avalon10, wbuf, AVA10_AUC_P_SIZE, &wlen, rbuf, rlen, &rlen);
	if (err) {
		applog(LOG_ERR, "%s-%d: Failed to reset Avalon USB2IIC Converter", avalon10->drv->name, avalon10->device_id);
		return 1;
	}

	/* Deinit */
	iic_info.iic_op = AVA10_IIC_DEINIT;
	rlen = 0;
	avalon10_auc_init_pkg(wbuf, &iic_info, NULL, 0, rlen);

	memset(rbuf, 0, AVA10_AUC_P_SIZE);
	err = avalon10_auc_xfer(avalon10, wbuf, AVA10_AUC_P_SIZE, &wlen, rbuf, rlen, &rlen);
	if (err) {
		applog(LOG_ERR, "%s-%d: Failed to deinit Avalon USB2IIC Converter", avalon10->drv->name, avalon10->device_id);
		return 1;
	}

	/* Init */
	iic_info.iic_op = AVA10_IIC_INIT;
	iic_info.iic_param.aucParam[0] = opt_avalon10_aucspeed;
	iic_info.iic_param.aucParam[1] = opt_avalon10_aucxdelay;
	rlen = AVA10_AUC_VER_LEN;
	avalon10_auc_init_pkg(wbuf, &iic_info, NULL, 0, rlen);

	memset(rbuf, 0, AVA10_AUC_P_SIZE);
	err = avalon10_auc_xfer(avalon10, wbuf, AVA10_AUC_P_SIZE, &wlen, rbuf, rlen, &rlen);
	if (err) {
		applog(LOG_ERR, "%s-%d: Failed to init Avalon USB2IIC Converter", avalon10->drv->name, avalon10->device_id);
		return 1;
	}

	hexdump(rbuf, AVA10_AUC_P_SIZE);

	memcpy(ver, rbuf + 4, AVA10_AUC_VER_LEN);
	ver[AVA10_AUC_VER_LEN] = '\0';

	applog(LOG_DEBUG, "%s-%d: USB2IIC Converter version: %s!", avalon10->drv->name, avalon10->device_id, ver);

	return 0;
}

static int avalon10_auc_getinfo(struct cgpu_info *avalon10)
{
	struct avalon10_iic_info iic_info;
	int err, wlen, rlen;
	uint8_t wbuf[AVA10_AUC_P_SIZE];
	uint8_t rbuf[AVA10_AUC_P_SIZE];
	uint8_t *pdata = rbuf + 4;
	uint16_t adc_val;
	struct avalon10_info *info = avalon10->device_data;

	iic_info.iic_op = AVA10_IIC_INFO;
	/*
	 * Device info: (9 bytes)
	 * tempadc(2), reqRdIndex, reqWrIndex,
	 * respRdIndex, respWrIndex, tx_flags, state
	 */
	rlen = 7;
	avalon10_auc_init_pkg(wbuf, &iic_info, NULL, 0, rlen);

	memset(rbuf, 0, AVA10_AUC_P_SIZE);
	err = avalon10_auc_xfer(avalon10, wbuf, AVA10_AUC_P_SIZE, &wlen, rbuf, rlen, &rlen);
	if (err) {
		applog(LOG_ERR, "%s-%d: AUC Failed to get info ", avalon10->drv->name, avalon10->device_id);
		return 1;
	}

	applog(LOG_DEBUG, "%s-%d: AUC tempADC(%03d), reqcnt(%d), respcnt(%d), txflag(%d), state(%d)",
			avalon10->drv->name, avalon10->device_id,
			pdata[1] << 8 | pdata[0],
			pdata[2],
			pdata[3],
			pdata[5] << 8 | pdata[4],
			pdata[6]);

	adc_val = pdata[1] << 8 | pdata[0];

	info->auc_sensor = 3.3 * adc_val * 10000 / 1023;

	return 0;
}

static int avalon10_init_pkg(struct avalon10_pkg *pkg, uint8_t type, uint8_t idx, uint8_t cnt)
{
	unsigned short crc;

	pkg->head[0] = AVA10_H1;
	pkg->head[1] = AVA10_H2;

	pkg->type = type;
	pkg->opt = 0;
	pkg->idx = idx;
	pkg->cnt = cnt;

	crc = crc16(pkg->data, AVA10_P_DATA_LEN);

	pkg->crc[0] = (crc & 0xff00) >> 8;
	pkg->crc[1] = crc & 0xff;

	return 0;
}

static int avalon10_iic_xfer_pkg(struct cgpu_info *avalon10, uint8_t slave_addr,
				const struct avalon10_pkg *pkg, struct avalon10_ret *ret)
{
	struct avalon10_iic_info iic_info;
	int err, wcnt, rcnt, rlen = 0;
	uint8_t wbuf[AVA10_AUC_P_SIZE];
	uint8_t rbuf[AVA10_AUC_P_SIZE];

	struct avalon10_info *info = avalon10->device_data;

	if (ret)
		rlen = AVA10_READ_SIZE;

	if (info->connecter == AVA10_CONNECTER_AUC) {
		if (unlikely(avalon10->usbinfo.nodev))
			return AVA10_SEND_ERROR;

		iic_info.iic_op = AVA10_IIC_XFER;
		iic_info.iic_param.slave_addr = slave_addr;

		avalon10_auc_init_pkg(wbuf, &iic_info, (uint8_t *)pkg, AVA10_WRITE_SIZE, rlen);
		err = avalon10_auc_xfer(avalon10, wbuf, wbuf[0], &wcnt, rbuf, rlen, &rcnt);
		if ((pkg->type != AVA10_P_DETECT) && err == -7 && !rcnt && rlen) {
			avalon10_auc_init_pkg(wbuf, &iic_info, NULL, 0, rlen);
			err = avalon10_auc_xfer(avalon10, wbuf, wbuf[0], &wcnt, rbuf, rlen, &rcnt);
			applog(LOG_DEBUG, "%s-%d-%d: AUC read again!(type:0x%x, err:%d)", avalon10->drv->name, avalon10->device_id, slave_addr, pkg->type, err);
		}
		if (err || rcnt != rlen) {
			if (info->xfer_err_cnt++ == 100) {
				applog(LOG_DEBUG, "%s-%d-%d: AUC xfer_err_cnt reach err = %d, rcnt = %d, rlen = %d",
						avalon10->drv->name, avalon10->device_id, slave_addr,
						err, rcnt, rlen);

				cgsleep_ms(5 * 1000); /* Wait MM reset */
				if (avalon10_auc_init(avalon10, info->auc_version)) {
					applog(LOG_WARNING, "%s-%d: Failed to re-init auc, unplugging for new hotplug",
					       avalon10->drv->name, avalon10->device_id);
					usb_nodev(avalon10);
				}
			}
			return AVA10_SEND_ERROR;
		}

		if (ret)
			memcpy((char *)ret, rbuf + 4, AVA10_READ_SIZE);

		info->xfer_err_cnt = 0;
	}

	return AVA10_SEND_OK;
}

static int avalon10_send_bc_pkgs(struct cgpu_info *avalon10, const struct avalon10_pkg *pkg)
{
	int ret;

	do {
		ret = avalon10_iic_xfer_pkg(avalon10, AVA10_MODULE_BROADCAST, pkg, NULL);
	} while (ret != AVA10_SEND_OK);

	return 0;
}

static void copy_pool_stratum(struct pool *pool_stratum, struct pool *pool)
{
	int i;
	int merkles = pool->merkles, job_id_len;
	size_t coinbase_len = pool->coinbase_len;
	unsigned short crc;

	if (!pool->swork.job_id)
		return;

	if (pool_stratum->swork.job_id) {
		job_id_len = strlen(pool->swork.job_id);
		crc = crc16((unsigned char *)pool->swork.job_id, job_id_len);
		job_id_len = strlen(pool_stratum->swork.job_id);

		if (crc16((unsigned char *)pool_stratum->swork.job_id, job_id_len) == crc)
			return;
	}

	cg_wlock(&pool_stratum->data_lock);
	free(pool_stratum->swork.job_id);
	free(pool_stratum->nonce1);
	free(pool_stratum->coinbase);

	pool_stratum->coinbase = cgcalloc(coinbase_len, 1);
	memcpy(pool_stratum->coinbase, pool->coinbase, coinbase_len);

	for (i = 0; i < pool_stratum->merkles; i++)
		free(pool_stratum->swork.merkle_bin[i]);
	if (merkles) {
		pool_stratum->swork.merkle_bin = cgrealloc(pool_stratum->swork.merkle_bin,
							   sizeof(char *) * merkles + 1);
		for (i = 0; i < merkles; i++) {
			pool_stratum->swork.merkle_bin[i] = cgmalloc(32);
			memcpy(pool_stratum->swork.merkle_bin[i], pool->swork.merkle_bin[i], 32);
		}
	}

	pool_stratum->sdiff = pool->sdiff;
	pool_stratum->coinbase_len = pool->coinbase_len;
	pool_stratum->nonce2_offset = pool->nonce2_offset;
	pool_stratum->n2size = pool->n2size;
	pool_stratum->merkles = pool->merkles;
	pool_stratum->swork.job_id = strdup(pool->swork.job_id);
	pool_stratum->nonce1 = strdup(pool->nonce1);

	memcpy(pool_stratum->ntime, pool->ntime, sizeof(pool_stratum->ntime));
	memcpy(pool_stratum->header_bin, pool->header_bin, sizeof(pool_stratum->header_bin));
	cg_wunlock(&pool_stratum->data_lock);
}

static void avalon10_stratum_pkgs(struct cgpu_info *avalon10, struct pool *pool)
{
	struct avalon10_info *info = avalon10->device_data;
	const int merkle_offset = 36;
	struct avalon10_pkg pkg;
	int i, a, b;
	uint32_t tmp;
	unsigned char target[32];
	int job_id_len, n2size;
	unsigned short crc;
	int coinbase_len_posthash, coinbase_len_prehash;
	uint8_t coinbase_prehash[32];
	uint32_t range, start;

	/* Send out the first stratum message STATIC */
	applog(LOG_DEBUG, "%s-%d: Pool stratum message STATIC: %d, %d, %d, %d, %d",
	       avalon10->drv->name, avalon10->device_id,
	       pool->coinbase_len,
	       pool->nonce2_offset,
	       pool->n2size,
	       merkle_offset,
	       pool->merkles);

	memset(pkg.data, 0, AVA10_P_DATA_LEN);
	tmp = be32toh(pool->coinbase_len);
	memcpy(pkg.data, &tmp, 4);

	tmp = be32toh(pool->nonce2_offset);
	memcpy(pkg.data + 4, &tmp, 4);

	n2size = pool->n2size >= 4 ? 4 : pool->n2size;
	tmp = be32toh(n2size);
	memcpy(pkg.data + 8, &tmp, 4);

	tmp = be32toh(merkle_offset);
	memcpy(pkg.data + 12, &tmp, 4);

	tmp = be32toh(pool->merkles);
	memcpy(pkg.data + 16, &tmp, 4);

	if (pool->n2size == 3)
		range = 0xffffff / (total_devices ? total_devices : 1);
	else
		range = 0xffffffff / (total_devices ? total_devices : 1);
	start = range * avalon10->device_id;

	tmp = be32toh(start);
	memcpy(pkg.data + 20, &tmp, 4);

	tmp = be32toh(range);
	memcpy(pkg.data + 24, &tmp, 4);

	if (info->work_restart) {
		info->work_restart = false;
		tmp = be32toh(0x1);
		memcpy(pkg.data + 28, &tmp, 4);
	}

	avalon10_init_pkg(&pkg, AVA10_P_STATIC, 1, 1);
	if (avalon10_send_bc_pkgs(avalon10, &pkg))
		return;

	memset(pkg.data, 0, AVA10_P_DATA_LEN);

	memcpy(pkg.data, &pool->vmask_001[0], 4);
	memcpy(pkg.data + 4, &pool->vmask_001[2], 4);
	memcpy(pkg.data + 8, &pool->vmask_001[4], 4);
	memcpy(pkg.data + 12, &pool->vmask_001[8], 4);

	avalon10_init_pkg(&pkg, AVA10_P_VMASK, 1, 1);
	if (avalon10_send_bc_pkgs(avalon10, &pkg))
		return;

	if (pool->sdiff <= opt_avalon10_target_diff) {
		set_target(target, pool->sdiff);
		opt_avalon10_target_diff = pool->sdiff;
	} else {
		set_target(target, opt_avalon10_target_diff);
	}

	memcpy(pkg.data, target, 32);
	if (opt_debug) {
		char *target_str;
		target_str = bin2hex(target, 32);
		applog(LOG_DEBUG, "%s-%d: Pool stratum target: %s", avalon10->drv->name, avalon10->device_id, target_str);
		free(target_str);
	}
	avalon10_init_pkg(&pkg, AVA10_P_TARGET, 1, 1);
	if (avalon10_send_bc_pkgs(avalon10, &pkg))
		return;

	memset(pkg.data, 0, AVA10_P_DATA_LEN);

	job_id_len = strlen(pool->swork.job_id);
	crc = crc16((unsigned char *)pool->swork.job_id, job_id_len);
	applog(LOG_DEBUG, "%s-%d: Pool stratum message JOBS_ID[%04x]: %s",
	       avalon10->drv->name, avalon10->device_id,
	       crc, pool->swork.job_id);
	tmp = ((crc << 16) | pool->pool_no);
	if (info->last_jobid != tmp) {
		info->last_jobid = tmp;
		pkg.data[0] = (crc & 0xff00) >> 8;
		pkg.data[1] = crc & 0xff;
		pkg.data[2] = pool->pool_no & 0xff;
		pkg.data[3] = (pool->pool_no & 0xff00) >> 8;
		avalon10_init_pkg(&pkg, AVA10_P_JOB_ID, 1, 1);
		if (avalon10_send_bc_pkgs(avalon10, &pkg))
			return;
	}

	coinbase_len_prehash = pool->nonce2_offset - (pool->nonce2_offset % SHA256_BLOCK_SIZE);
	coinbase_len_posthash = pool->coinbase_len - coinbase_len_prehash;
	sha256_prehash(pool->coinbase, coinbase_len_prehash, coinbase_prehash);

	a = (coinbase_len_posthash / AVA10_P_DATA_LEN) + 1;
	b = coinbase_len_posthash % AVA10_P_DATA_LEN;
	memcpy(pkg.data, coinbase_prehash, 32);
	avalon10_init_pkg(&pkg, AVA10_P_COINBASE, 1, a + (b ? 1 : 0));
	if (avalon10_send_bc_pkgs(avalon10, &pkg))
		return;

	applog(LOG_DEBUG, "%s-%d: Pool stratum message modified COINBASE: %d %d",
			avalon10->drv->name, avalon10->device_id,
			a, b);
	for (i = 1; i < a; i++) {
		memcpy(pkg.data, pool->coinbase + coinbase_len_prehash + i * 32 - 32, 32);
		avalon10_init_pkg(&pkg, AVA10_P_COINBASE, i + 1, a + (b ? 1 : 0));
		if (avalon10_send_bc_pkgs(avalon10, &pkg))
			return;
	}
	if (b) {
		memset(pkg.data, 0, AVA10_P_DATA_LEN);
		memcpy(pkg.data, pool->coinbase + coinbase_len_prehash + i * 32 - 32, b);
		avalon10_init_pkg(&pkg, AVA10_P_COINBASE, i + 1, i + 1);
		if (avalon10_send_bc_pkgs(avalon10, &pkg))
			return;
	}

	b = pool->merkles;
	applog(LOG_DEBUG, "%s-%d: Pool stratum message MERKLES: %d", avalon10->drv->name, avalon10->device_id, b);
	for (i = 0; i < b; i++) {
		memset(pkg.data, 0, AVA10_P_DATA_LEN);
		memcpy(pkg.data, pool->swork.merkle_bin[i], 32);
		avalon10_init_pkg(&pkg, AVA10_P_MERKLES, i + 1, b);
		if (avalon10_send_bc_pkgs(avalon10, &pkg))
			return;
	}

	applog(LOG_DEBUG, "%s-%d: Pool stratum message HEADER: 4", avalon10->drv->name, avalon10->device_id);
	for (i = 0; i < 4; i++) {
		memset(pkg.data, 0, AVA10_P_DATA_LEN);
		memcpy(pkg.data, pool->header_bin + i * 32, 32);
		avalon10_init_pkg(&pkg, AVA10_P_HEADER, i + 1, 4);
		if (avalon10_send_bc_pkgs(avalon10, &pkg))
			return;
	}

	if (info->connecter == AVA10_CONNECTER_AUC)
		avalon10_auc_getinfo(avalon10);
}

static void avalon10_stratum_finish(struct cgpu_info *avalon10)
{
	struct avalon10_pkg send_pkg;

	memset(send_pkg.data, 0, AVA10_P_DATA_LEN);
	avalon10_init_pkg(&send_pkg, AVA10_P_JOB_FIN, 1, 1);
	avalon10_send_bc_pkgs(avalon10, &send_pkg);
}

static void avalon10_init_setting(struct cgpu_info *avalon10, int addr)
{
	struct avalon10_pkg send_pkg;
	uint32_t tmp;

	memset(send_pkg.data, 0, AVA10_P_DATA_LEN);

	tmp = be32toh(opt_avalon10_freq_sel);
	memcpy(send_pkg.data + 4, &tmp, 4);

	tmp = 1;
	if (!opt_avalon10_smart_speed)
		tmp = 0;
	tmp |= (opt_avalon10_nonce_check << 1);
	tmp |= (opt_avalon10_roll_enable << 2);
	tmp |= (opt_avalon10_core_clk_sel << 3);
	send_pkg.data[8] = tmp & 0xff;
	send_pkg.data[9] = opt_avalon10_nonce_mask & 0xff;

	tmp = be32toh(opt_avalon10_mux_l2h);
	memcpy(send_pkg.data + 10, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set mux l2h %u",
			avalon10->drv->name, avalon10->device_id, addr,
			opt_avalon10_mux_l2h);

	tmp = be32toh(opt_avalon10_mux_h2l);
	memcpy(send_pkg.data + 14, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set mux h2l %u",
			avalon10->drv->name, avalon10->device_id, addr,
			opt_avalon10_mux_h2l);

	tmp = be32toh(opt_avalon10_h2ltime0_spd);
	memcpy(send_pkg.data + 18, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set h2ltime0 spd %u",
			avalon10->drv->name, avalon10->device_id, addr,
			opt_avalon10_h2ltime0_spd);

	tmp = be32toh(opt_avalon10_spdlow);
	memcpy(send_pkg.data + 22, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set spdlow %u",
			avalon10->drv->name, avalon10->device_id, addr,
			opt_avalon10_spdlow);

	tmp = be32toh(opt_avalon10_spdhigh);
	memcpy(send_pkg.data + 26, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set spdhigh %u",
			avalon10->drv->name, avalon10->device_id, addr,
			opt_avalon10_spdhigh);

	send_pkg.data[30] = opt_avalon10_tbase & 0xff;
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set tbase %u",
			avalon10->drv->name, avalon10->device_id, addr,
			opt_avalon10_tbase);

	/* Package the data */
	avalon10_init_pkg(&send_pkg, AVA10_P_SET, 1, 1);
	if (addr == AVA10_MODULE_BROADCAST)
		avalon10_send_bc_pkgs(avalon10, &send_pkg);
	else
		avalon10_iic_xfer_pkg(avalon10, addr, &send_pkg, NULL);
}

static void avalon10_set_voltage_level(struct cgpu_info *avalon10, int addr, unsigned int voltage[])
{
	struct avalon10_info *info = avalon10->device_data;
	struct avalon10_pkg send_pkg;
	uint32_t tmp;
	uint8_t i;

	memset(send_pkg.data, 0, AVA10_P_DATA_LEN);

	/* NOTE: miner_count should <= 8 */
	for (i = 0; i < info->miner_count[addr]; i++) {
		tmp = be32toh(encode_voltage(voltage[i] +
				opt_avalon10_voltage_level_offset));
		memcpy(send_pkg.data + i * 4, &tmp, 4);
	}
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set voltage miner %d, (%d-%d)",
			avalon10->drv->name, avalon10->device_id, addr,
			i, voltage[0], voltage[info->miner_count[addr] - 1]);

	tmp = be32toh(opt_avalon10_adjust_voltage);
	memcpy(send_pkg.data + 24, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set adjust voltage %u",
			avalon10->drv->name, avalon10->device_id, addr,
			opt_avalon10_adjust_voltage);

	/* Package the data */
	avalon10_init_pkg(&send_pkg, AVA10_P_SET_VOLT, 1, 1);
	if (addr == AVA10_MODULE_BROADCAST)
		avalon10_send_bc_pkgs(avalon10, &send_pkg);
	else
		avalon10_iic_xfer_pkg(avalon10, addr, &send_pkg, NULL);
}

static void avalon10_set_freq(struct cgpu_info *avalon10, int addr, int miner_id, int asic_id, unsigned int freq[])
{
	struct avalon10_info *info = avalon10->device_data;
	struct avalon10_pkg send_pkg;
	uint32_t tmp, f;
	uint8_t i;

	memset(send_pkg.data, 0, AVA10_P_DATA_LEN);
	for (i = 0; i < AVA10_DEFAULT_PLL_CNT; i++) {
		tmp = be32toh(api_get_cpm(freq[i]));
		memcpy(send_pkg.data + i * 4, &tmp, 4);
	}

	f = freq[0];
	for (i = 1; i < AVA10_DEFAULT_PLL_CNT; i++)
		f = f > freq[i] ? f : freq[i];

	f = f ? f : 1;

	/* TODO: adjust it according to frequency */
	tmp = 100;
	tmp = be32toh(tmp);
	memcpy(send_pkg.data + AVA10_DEFAULT_PLL_CNT * 4, &tmp, 4);

	tmp = AVA10_ASIC_TIMEOUT_CONST / f * 83 / 100;
	tmp = be32toh(tmp);
	memcpy(send_pkg.data + AVA10_DEFAULT_PLL_CNT * 4 + 4, &tmp, 4);

	tmp = miner_id;
	tmp = be32toh(tmp);
	memcpy(send_pkg.data + AVA10_DEFAULT_PLL_CNT * 4 + 8, &tmp, 4);

	tmp = asic_id;
	tmp = be32toh(tmp);
	memcpy(send_pkg.data + AVA10_DEFAULT_PLL_CNT * 4 + 12, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set freq miner %x-%x",
			avalon10->drv->name, avalon10->device_id, addr,
			miner_id, be32toh(tmp));

	/* Package the data */
	if (asic_id == 0xff)
		avalon10_init_pkg(&send_pkg, AVA10_P_SET_PLL, miner_id + 1, info->miner_count[addr]);
	else
		avalon10_init_pkg(&send_pkg, AVA10_P_SET_PLL, miner_id * info->asic_count[addr] + asic_id + 1, info->miner_count[addr] * info->asic_count[addr]);

	if (addr == AVA10_MODULE_BROADCAST)
		avalon10_send_bc_pkgs(avalon10, &send_pkg);
	else
		avalon10_iic_xfer_pkg(avalon10, addr, &send_pkg, NULL);
}

static void avalon10_set_factory_info(struct cgpu_info *avalon10, int addr, uint8_t value[])
{
	struct avalon10_pkg send_pkg;
	uint8_t i;

	memset(send_pkg.data, 0, AVA10_P_DATA_LEN);

	for (i = 0; i < AVA10_DEFAULT_FACTORY_INFO_CNT; i++)
		send_pkg.data[i] = value[i];

	/* Package the data */
	avalon10_init_pkg(&send_pkg, AVA10_P_SET_FAC, 1, 1);
	if (addr == AVA10_MODULE_BROADCAST)
		avalon10_send_bc_pkgs(avalon10, &send_pkg);
	else
		avalon10_iic_xfer_pkg(avalon10, addr, &send_pkg, NULL);
}

static void avalon10_set_ss_param(struct cgpu_info *avalon10, int addr)
{
	struct avalon10_pkg send_pkg;
	uint32_t tmp;

	if (!opt_avalon10_smart_speed)
		return;

	memset(send_pkg.data, 0, AVA10_P_DATA_LEN);

	tmp = (opt_avalon10_th_pass << 16) | opt_avalon10_th_fail;
	tmp = be32toh(tmp);
	memcpy(send_pkg.data, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th pass %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_th_pass);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th fail %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_th_fail);

	tmp = (opt_avalon10_th_mssel << 16) | opt_avalon10_th_init;
	tmp = be32toh(tmp);
	memcpy(send_pkg.data + 4, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th mssel %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_th_mssel);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th init %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_th_init);

	tmp = be32toh(opt_avalon10_th_timeout);
	memcpy(send_pkg.data + 8, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th timeout %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_th_timeout);

	tmp = (opt_avalon10_lv2_th_msadd << 31) | (opt_avalon10_lv2_th_ms << 16) |
	      (opt_avalon10_lv1_th_msadd << 15) |  opt_avalon10_lv1_th_ms;
	tmp = be32toh(tmp);
	memcpy(send_pkg.data + 12, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th lv1 msadd %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_lv1_th_msadd);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th lv1 ms %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_lv1_th_ms);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th lv2 msadd %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_lv2_th_msadd);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th lv2 ms %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_lv2_th_ms);

	tmp = (opt_avalon10_lv4_th_msadd << 31) | (opt_avalon10_lv4_th_ms << 16) |
	      (opt_avalon10_lv3_th_msadd << 15) |  opt_avalon10_lv3_th_ms;
	tmp = be32toh(tmp);
	memcpy(send_pkg.data + 16, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th lv4 msadd %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_lv4_th_msadd);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th lv4 ms %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_lv4_th_ms);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th lv3 msadd %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_lv3_th_msadd);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set th lv3 ms %u",
			avalon10->drv->name, avalon10->device_id, addr, opt_avalon10_lv3_th_ms);

	/* Package the data */
	avalon10_init_pkg(&send_pkg, AVA10_P_SET_SS, 1, 1);

	if (addr == AVA10_MODULE_BROADCAST)
		avalon10_send_bc_pkgs(avalon10, &send_pkg);
	else
		avalon10_iic_xfer_pkg(avalon10, addr, &send_pkg, NULL);
}

static void avalon10_set_adjust_voltage_option(struct cgpu_info *avalon10, int addr, int32_t up_init, uint32_t up_factor, uint32_t up_threshold,
						int32_t down_init, uint32_t down_factor, uint32_t down_threshold, uint32_t time)
{
	struct avalon10_info *info = avalon10->device_data;
	struct avalon10_pkg send_pkg;
	int32_t tmp;

	memset(send_pkg.data, 0, AVA10_P_DATA_LEN);

	tmp = be32toh(up_init);
	memcpy(send_pkg.data + 0, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set up init %d",
			avalon10->drv->name, avalon10->device_id, addr, up_init);

	tmp = be32toh(up_factor);
	memcpy(send_pkg.data + 4, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set up factor %d",
			avalon10->drv->name, avalon10->device_id, addr, up_factor);

	tmp = be32toh(up_threshold);
	memcpy(send_pkg.data + 8, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set up threshold %d",
			avalon10->drv->name, avalon10->device_id, addr, up_threshold);

	tmp = be32toh(down_init);
	memcpy(send_pkg.data + 12, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set down init %d",
			avalon10->drv->name, avalon10->device_id, addr, down_init);

	tmp = be32toh(down_factor);
	memcpy(send_pkg.data + 16, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set down factor %d",
			avalon10->drv->name, avalon10->device_id, addr, down_factor);

	tmp = be32toh(down_threshold);
	memcpy(send_pkg.data + 20, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set down threshold %d",
			avalon10->drv->name, avalon10->device_id, addr, down_threshold);

	tmp = be32toh(time);
	memcpy(send_pkg.data + 24, &tmp, 4);
	applog(LOG_DEBUG, "%s-%d-%d: avalon10 set time %d",
			avalon10->drv->name, avalon10->device_id, addr, time);

	/* Package the data */
	avalon10_init_pkg(&send_pkg, AVA10_P_SET_ADJUST_VOLT, 1, 1);

	if (addr == AVA10_MODULE_BROADCAST)
		avalon10_send_bc_pkgs(avalon10, &send_pkg);
	else
		avalon10_iic_xfer_pkg(avalon10, addr, &send_pkg, NULL);

	return;
}

static void avalon10_set_finish(struct cgpu_info *avalon10, int addr)
{
	struct avalon10_pkg send_pkg;

	memset(send_pkg.data, 0, AVA10_P_DATA_LEN);
	avalon10_init_pkg(&send_pkg, AVA10_P_SET_FIN, 1, 1);
	avalon10_iic_xfer_pkg(avalon10, addr, &send_pkg, NULL);
}

static int check_module_exist(struct cgpu_info *avalon10, uint8_t mm_dna[AVA10_MM_DNA_LEN])
{
	struct avalon10_info *info = avalon10->device_data;
	int i;

	for (i = 0; i < AVA10_DEFAULT_MODULARS; i++) {
		/* last byte is \0 */
		if (info->enable[i] && !memcmp(info->mm_dna[i], mm_dna, AVA10_MM_DNA_LEN))
			return 1;
	}

	return 0;
}

static void detect_modules(struct cgpu_info *avalon10)
{
	struct avalon10_info *info = avalon10->device_data;
	struct avalon10_pkg send_pkg;
	struct avalon10_ret ret_pkg;
	uint32_t tmp;
	int i, j, k, err, rlen;
	uint8_t dev_index;
	uint8_t rbuf[AVA10_AUC_P_SIZE];

	/* Detect new modules here */
	for (i = 1; i < AVA10_DEFAULT_MODULARS + 1; i++) {
		if (info->enable[i])
			continue;

		/* Send out detect pkg */
		applog(LOG_DEBUG, "%s-%d: AVA10_P_DETECT ID[%d]",
		       avalon10->drv->name, avalon10->device_id, i);
		memset(send_pkg.data, 0, AVA10_P_DATA_LEN);
		tmp = be32toh(i); /* ID */
		memcpy(send_pkg.data + 28, &tmp, 4);
		avalon10_init_pkg(&send_pkg, AVA10_P_DETECT, 1, 1);
		err = avalon10_iic_xfer_pkg(avalon10, AVA10_MODULE_BROADCAST, &send_pkg, &ret_pkg);
		if (err == AVA10_SEND_OK) {
			if (decode_pkg(avalon10, &ret_pkg, AVA10_MODULE_BROADCAST)) {
				applog(LOG_DEBUG, "%s-%d: Should be AVA10_P_ACKDETECT(%d), but %d",
				       avalon10->drv->name, avalon10->device_id, AVA10_P_ACKDETECT, ret_pkg.type);
				continue;
			}
		}

		if (err != AVA10_SEND_OK) {
			applog(LOG_DEBUG, "%s-%d: AVA10_P_DETECT: Failed AUC xfer data with err %d",
					avalon10->drv->name, avalon10->device_id, err);
			break;
		}

		applog(LOG_DEBUG, "%s-%d: Module detect ID[%d]: %d",
		       avalon10->drv->name, avalon10->device_id, i, ret_pkg.type);
		if (ret_pkg.type != AVA10_P_ACKDETECT)
			break;

		if (check_module_exist(avalon10, ret_pkg.data))
			continue;

		/* Check count of modulars */
		if (i == AVA10_DEFAULT_MODULARS) {
			applog(LOG_NOTICE, "You have connected more than %d machines. This is discouraged.", (AVA10_DEFAULT_MODULARS - 1));
			info->conn_overloaded = true;
			break;
		} else
			info->conn_overloaded = false;

		memcpy(info->mm_version[i], ret_pkg.data + AVA10_MM_DNA_LEN, AVA10_MM_VER_LEN);
		info->mm_version[i][AVA10_MM_VER_LEN] = '\0';
		for (dev_index = 0; dev_index < (sizeof(avalon10_dev_table) / sizeof(avalon10_dev_table[0])); dev_index++) {
			if (!strncmp((char *)&(info->mm_version[i]), (char *)(avalon10_dev_table[dev_index].dev_id_str), 3)) {
				info->miner_count[i] = avalon10_dev_table[dev_index].miner_count;
				info->asic_count[i] = avalon10_dev_table[dev_index].asic_count;
				break;
			}
		}
		if (dev_index == (sizeof(avalon10_dev_table) / sizeof(avalon10_dev_table[0]))) {
			applog(LOG_NOTICE, "%s-%d: The modular version %s cann't be support",
				       avalon10->drv->name, avalon10->device_id, info->mm_version[i]);
			break;
		}

		info->enable[i] = 1;
		cgtime(&info->elapsed[i]);
		memcpy(info->mm_dna[i], ret_pkg.data, AVA10_MM_DNA_LEN);
		memcpy(&tmp, ret_pkg.data + AVA10_MM_DNA_LEN + AVA10_MM_VER_LEN, 4);
		tmp = be32toh(tmp);
		info->total_asics[i] = tmp;
		info->temp_overheat[i] = AVA10_DEFAULT_TEMP_OVERHEAT;
		info->temp_target[i] = opt_avalon10_temp_target;
		info->fan_pct[i] = opt_avalon10_fan_min;
		for (j = 0; j < info->miner_count[i]; j++) {
			if (opt_avalon10_voltage_level == AVA10_INVALID_VOLTAGE_LEVEL)
				info->set_voltage_level[i][j] = avalon10_dev_table[dev_index].set_voltage_level;
			else
				info->set_voltage_level[i][j] = opt_avalon10_voltage_level;

			for (k = 0; k < info->asic_count[i]; k++)
				info->temp[i][j][k] = -273;

			for (k = 0; k < AVA10_DEFAULT_PLL_CNT; k++)
				info->set_frequency[i][j][k] = avalon10_dev_table[dev_index].set_freq[k];
		}
		info->get_voltage[i][0] = 0;

		info->freq_mode[i] = AVA10_FREQ_INIT_MODE;
		memset(info->get_pll[i], 0, sizeof(uint32_t) * info->miner_count[i] * AVA10_DEFAULT_PLL_CNT);

		info->led_indicator[i] = 0;
		info->fan_cpm[i][0] = 0;
		info->fan_cpm[i][1] = 0;
		info->temp_mm[i] = -273;
		info->local_works[i] = 0;
		info->hw_works[i] = 0;

		/*PID controller*/
		info->pid_u[i] = opt_avalon10_fan_min;
		info->pid_p[i] = opt_avalon10_pid_p;
		info->pid_i[i] = opt_avalon10_pid_i;
		info->pid_d[i] = opt_avalon10_pid_d;
		info->pid_e[i][0] = 0;
		info->pid_e[i][1] = 0;
		info->pid_e[i][2] = 0;
		info->pid_0[i] = 0;

		for (j = 0; j < info->miner_count[i]; j++) {
			memset(info->chip_matching_work[i][j], 0, sizeof(uint64_t) * info->asic_count[i]);
			info->local_works_i[i][j] = 0;
			info->hw_works_i[i][j] = 0;
			info->error_code[i][j] = 0;
			info->error_crc[i][j] = 0;
			info->diff1[i][j] = 0;
		}
		info->error_code[i][j] = 0;
		info->error_polling_cnt[i] = 0;

		applog(LOG_NOTICE, "%s-%d: New module detected! ID[%d-%x]",
		       avalon10->drv->name, avalon10->device_id, i, info->mm_dna[i][AVA10_MM_DNA_LEN - 1]);

		/* Tell MM, it has been detected */
		memset(send_pkg.data, 0, AVA10_P_DATA_LEN);
		memcpy(send_pkg.data, info->mm_dna[i],  AVA10_MM_DNA_LEN);
		avalon10_init_pkg(&send_pkg, AVA10_P_SYNC, 1, 1);
		avalon10_iic_xfer_pkg(avalon10, i, &send_pkg, &ret_pkg);
		/* Keep the usb buffer is empty */
		usb_buffer_clear(avalon10);
		usb_read(avalon10, (char *)rbuf, AVA10_AUC_P_SIZE, &rlen, C_AVA10_READ);

		for (j = 0; j < info->miner_count[i]; j++) {
			for (k = 0; k < AVA10_DEFAULT_PLL_CNT; k++) {
				if (opt_avalon10_freq[k] != AVA10_DEFAULT_FREQUENCY)
					info->set_frequency[i][j][k] = opt_avalon10_freq[k];
			}
		}

		avalon10_init_setting(avalon10, i);

		avalon10_set_voltage_level(avalon10, i, info->set_voltage_level[i]);

		for (j = 0; j < info->miner_count[i]; j++)
			avalon10_set_freq(avalon10, i, j, 0xff, info->set_frequency[i][j]);

		if (opt_avalon10_smart_speed)
			avalon10_set_ss_param(avalon10, i);

		avalon10_set_finish(avalon10, i);
	}
}

static void detach_module(struct cgpu_info *avalon10, int addr)
{
	struct avalon10_info *info = avalon10->device_data;

	info->enable[addr] = 0;
	applog(LOG_NOTICE, "%s-%d: Module detached! ID[%d]",
		avalon10->drv->name, avalon10->device_id, addr);
}

static int polling(struct cgpu_info *avalon10)
{
	struct avalon10_info *info = avalon10->device_data;
	struct avalon10_pkg send_pkg;
	struct avalon10_ret ar;
	int i, tmp, ret, decode_err = 0;
	struct timeval current_fan;
	int do_adjust_fan = 0;
	uint32_t fan_pwm;
	double device_tdiff;

	cgtime(&current_fan);
	device_tdiff = tdiff(&current_fan, &(info->last_fan_adj));
	if (device_tdiff > 2.0 || device_tdiff < 0) {
		cgtime(&info->last_fan_adj);
		do_adjust_fan = 1;
	}

	for (i = 1; i < AVA10_DEFAULT_MODULARS; i++) {
		if (!info->enable[i])
			continue;

		cgsleep_ms(opt_avalon10_polling_delay);

		memset(send_pkg.data, 0, AVA10_P_DATA_LEN);

		/* White led */
		tmp = be32toh(info->led_indicator[i]);
		memcpy(send_pkg.data, &tmp, 4);

		/* Reboot */
		if (info->reboot[i]) {
			info->reboot[i] = false;

			tmp = be32toh(0x1);
			memcpy(send_pkg.data + 4, &tmp, 4);
		}

		/* Adjust fan */
		if (do_adjust_fan) {
			fan_pwm = adjust_fan(info, i);
			fan_pwm |= 0x80000000;
			tmp = be32toh(fan_pwm);
			memcpy(send_pkg.data + 8, &tmp, 4);

			fan_pwm = adjust_fan(info, i);
			fan_pwm |= 0x80000000;
			tmp = be32toh(fan_pwm);
			memcpy(send_pkg.data + 12, &tmp, 4);

			fan_pwm = adjust_fan(info, i);
			fan_pwm |= 0x80000000;
			tmp = be32toh(fan_pwm);
			memcpy(send_pkg.data + 16, &tmp, 4);

			fan_pwm = adjust_fan(info, i);
			fan_pwm |= 0x80000000;
			tmp = be32toh(fan_pwm);
			memcpy(send_pkg.data + 20, &tmp, 4);
		}

		avalon10_init_pkg(&send_pkg, AVA10_P_POLLING, 1, 1);
		ret = avalon10_iic_xfer_pkg(avalon10, i, &send_pkg, &ar);
		if (ret == AVA10_SEND_OK)
			decode_err = decode_pkg(avalon10, &ar, i);

		if (ret != AVA10_SEND_OK || decode_err) {
			info->error_polling_cnt[i]++;
			memset(send_pkg.data, 0, AVA10_P_DATA_LEN);
			avalon10_init_pkg(&send_pkg, AVA10_P_RSTMMTX, 1, 1);
			avalon10_iic_xfer_pkg(avalon10, i, &send_pkg, NULL);
			if (info->error_polling_cnt[i] >= 10)
				detach_module(avalon10, i);
		}

		if (ret == AVA10_SEND_OK && !decode_err) {
			info->error_polling_cnt[i] = 0;

			if ((ar.opt == AVA10_P_STATUS) &&
				(info->mm_dna[i][AVA10_MM_DNA_LEN - 1] != ar.opt)) {
				applog(LOG_ERR, "%s-%d-%d: Dup address found %d-%d",
						avalon10->drv->name, avalon10->device_id, i,
						info->mm_dna[i][AVA10_MM_DNA_LEN - 1], ar.opt);
				hexdump((uint8_t *)&ar, sizeof(ar));
				detach_module(avalon10, i);
			}
		}
	}

	return 0;
}

static float avalon10_hash_cal(struct cgpu_info *avalon10, int modular_id)
{
	struct avalon10_info *info = avalon10->device_data;
	uint32_t tmp_freq[AVA10_DEFAULT_PLL_CNT];
	unsigned int i, j, k;
	float mhsmm;

	mhsmm = 0;
	for (i = 0; i < info->miner_count[modular_id]; i++) {
		for (j = 0; j < info->asic_count[modular_id]; j++) {
			for (k = 0; k < AVA10_DEFAULT_PLL_CNT; k++)
				mhsmm += (info->get_asic[modular_id][i][j][2 + k] * info->get_frequency[modular_id][i][j][k] * 4);
		}
	}

	return mhsmm;
}

static struct api_data *avalon10_api_stats(struct cgpu_info *avalon10)
{
	struct api_data *root = NULL;
	struct avalon10_info *info = avalon10->device_data;
	int i, j, k, m;
	char buf[256];
	char *statbuf = NULL;
	struct timeval current;
	float mhsmm, auc_temp = 0.0;
	double a, b, dh, diff1;

	cgtime(&current);
	if (opt_debug)
		statbuf = cgcalloc(STATBUFLEN_WITH_DBG, 1);
	else
		statbuf = cgcalloc(STATBUFLEN_WITHOUT_DBG, 1);

	for (i = 1; i < AVA10_DEFAULT_MODULARS; i++) {
		if (!info->enable[i])
			continue;

		sprintf(buf, "Ver[%s]", info->mm_version[i]);
		strcpy(statbuf, buf);

		sprintf(buf, " DNA[%02x%02x%02x%02x%02x%02x%02x%02x]",
				info->mm_dna[i][0],
				info->mm_dna[i][1],
				info->mm_dna[i][2],
				info->mm_dna[i][3],
				info->mm_dna[i][4],
				info->mm_dna[i][5],
				info->mm_dna[i][6],
				info->mm_dna[i][7]);
		strcat(statbuf, buf);

		sprintf(buf, " Elapsed[%.0f]", tdiff(&current, &(info->elapsed[i])));
		strcat(statbuf, buf);

		strcat(statbuf, " MW[");
		info->local_works[i] = 0;
		for (j = 0; j < info->miner_count[i]; j++) {
			info->local_works[i] += info->local_works_i[i][j];
			sprintf(buf, "%"PRIu64" ", info->local_works_i[i][j]);
			strcat(statbuf, buf);
		}
		statbuf[strlen(statbuf) - 1] = ']';

		sprintf(buf, " LW[%"PRIu64"]", info->local_works[i]);
		strcat(statbuf, buf);

		strcat(statbuf, " MH[");
		info->hw_works[i]  = 0;
		for (j = 0; j < info->miner_count[i]; j++) {
			info->hw_works[i] += info->hw_works_i[i][j];
			sprintf(buf, "%"PRIu64" ", info->hw_works_i[i][j]);
			strcat(statbuf, buf);
		}
		statbuf[strlen(statbuf) - 1] = ']';

		sprintf(buf, " HW[%"PRIu64"]", info->hw_works[i]);
		strcat(statbuf, buf);

		a = 0;
		b = 0;
		for (j = 0; j < info->miner_count[i]; j++) {
			for (k = 0; k < info->asic_count[i]; k++) {
				a += info->get_asic[i][j][k][0];
				b += info->get_asic[i][j][k][1];
			}
		}
		dh = b ? (b / (a + b)) * 100 : 0;
		sprintf(buf, " DH[%.3f%%]", dh);
		strcat(statbuf, buf);

		sprintf(buf, " Temp[%d]", info->temp_mm[i]);
		strcat(statbuf, buf);

		sprintf(buf, " TMax[%d]", get_temp_max(info, i));
		strcat(statbuf, buf);

		sprintf(buf, " TAvg[%d]", get_temp_average(info, i));
		strcat(statbuf, buf);

		sprintf(buf, " Fan1[%d]", info->fan_cpm[i][0]);
		strcat(statbuf, buf);

		sprintf(buf, " Fan2[%d]", info->fan_cpm[i][1]);
		strcat(statbuf, buf);

		sprintf(buf, " FanR[%d%%]", info->fan_pct[i]);
		strcat(statbuf, buf);

		sprintf(buf, " Vo[%d]", info->get_voltage[i][0]);
		strcat(statbuf, buf);

		sprintf(buf, " PS[");
		strcat(statbuf, buf);
		for (j = 0; j < AVA10_DEFAULT_POWER_INFO_CNT; j++) {
			sprintf(buf, "%d ", info->power_info[i][j]);
			strcat(statbuf, buf);
		}
		statbuf[strlen(statbuf) - 1] = ']';

		if (opt_debug) {
			for (j = 0; j < info->miner_count[i]; j++) {
				sprintf(buf, " PLL%d[", j);
				strcat(statbuf, buf);
				for (k = 0; k < AVA10_DEFAULT_PLL_CNT; k++) {
					sprintf(buf, "%d ", info->get_pll[i][j][k]);
					strcat(statbuf, buf);
				}
				statbuf[strlen(statbuf) - 1] = ']';
			}
		}

		diff1 = 0;
		for (j = 0; j < info->miner_count[i]; j++)
			diff1 += info->diff1[i][j];

		mhsmm = avalon10_hash_cal(avalon10, i);
		sprintf(buf, " GHSmm[%.2f] GHSavg[%.2f] WU[%.2f] Freq[%.2f]", (float)mhsmm / 1000,
					diff1 / tdiff(&current, &(info->elapsed[i])) * 4.294967296,
					diff1 / tdiff(&current, &(info->elapsed[i])) * 60.0,
					(float)mhsmm / (info->asic_count[i] * info->miner_count[i] * 236));
		strcat(statbuf, buf);

		sprintf(buf, " Led[%d]", info->led_indicator[i]);
		strcat(statbuf, buf);

		strcat(statbuf, " MGHS[");
		for (j = 0; j < info->miner_count[i]; j++) {
			sprintf(buf, "%.2f ", info->diff1[i][j] / tdiff(&current, &(info->elapsed[i])) * 4.294967296);
			strcat(statbuf, buf);
		}
		statbuf[strlen(statbuf) - 1] = ']';

		strcat(statbuf, " MTmax[");
		for (j = 0; j < info->miner_count[i]; j++) {
			sprintf(buf, "%d ", get_miner_temp_max(info, i, j));
			strcat(statbuf, buf);
		}
		statbuf[strlen(statbuf) - 1] = ']';

		strcat(statbuf, " MTavg[");
		for (j = 0; j < info->miner_count[i]; j++) {
			sprintf(buf, "%d ", get_miner_temp_avg(info, i, j));
			strcat(statbuf, buf);
		}
		statbuf[strlen(statbuf) - 1] = ']';

		for (j = 0; j < info->miner_count[i]; j++) {
			sprintf(buf, " MW%d[", j);
			strcat(statbuf, buf);
			for (k = 0; k < info->asic_count[i]; k++) {
				sprintf(buf, "%"PRIu64" ", info->chip_matching_work[i][j][k]);
				strcat(statbuf, buf);
			}

			statbuf[strlen(statbuf) - 1] = ']';
		}

		sprintf(buf, " TA[%d]", info->total_asics[i]);
		strcat(statbuf, buf);

		strcat(statbuf, " ECHU[");
		for (j = 0; j < info->miner_count[i]; j++) {
			sprintf(buf, "%d ", info->error_code[i][j]);
			strcat(statbuf, buf);
		}
		statbuf[strlen(statbuf) - 1] = ']';

		sprintf(buf, " ECMM[%d]", info->error_code[i][j]);
		strcat(statbuf, buf);

		if (opt_debug) {
			strcat(statbuf, " FAC0[");
			sprintf(buf, "%d ", info->factory_info[i][0]);
			strcat(statbuf, buf);
			sprintf(buf, "%d ",info->factory_info[i][AVA10_DEFAULT_FACTORY_INFO_CNT]);
			strcat(statbuf, buf);
			statbuf[strlen(statbuf) - 1] = ']';

			for (j = 0; j < info->miner_count[i]; j++) {
				sprintf(buf, " SF%d[", j);
				strcat(statbuf, buf);
				for (k = 0; k < AVA10_DEFAULT_PLL_CNT; k++) {
					sprintf(buf, "%d ", info->set_frequency[i][j][k]);
					strcat(statbuf, buf);
				}

				statbuf[strlen(statbuf) - 1] = ']';
			}

			for (j = 0; j < info->miner_count[i]; j++) {
				sprintf(buf, " PVT_T%d[", j);
				strcat(statbuf, buf);
				for (k = 0; k < info->asic_count[i]; k++) {
					sprintf(buf, "%3d ", info->temp[i][j][k]);
					strcat(statbuf, buf);
				}

				statbuf[strlen(statbuf) - 1] = ']';
				statbuf[strlen(statbuf)] = '\0';
			}

			for (j = 0; j < info->miner_count[i]; j++) {
				sprintf(buf, " PVT_V%d[", j);
				strcat(statbuf, buf);
				for (k = 0; k < info->asic_count[i]; k++) {
					sprintf(buf, "%d ", info->core_volt[i][j][k][0]);
					strcat(statbuf, buf);
				}

				statbuf[strlen(statbuf) - 1] = ']';
				statbuf[strlen(statbuf)] = '\0';
			}

			int l;
			/* i: modular, j: miner, k: asic, l: value */
			for (j = 0; j < info->miner_count[i]; j++) {
				for (l = 0; l < AVA10_DEFAULT_PLL_CNT; l++) {
					sprintf(buf, " CF%d_%d[", j, l);
					strcat(statbuf, buf);
					for (k = 0; k < info->asic_count[i]; k++) {
						sprintf(buf, "%3d ", info->get_frequency[i][j][k][l]);
						strcat(statbuf, buf);
					}

					statbuf[strlen(statbuf) - 1] = ']';
					statbuf[strlen(statbuf)] = '\0';
				}
			}

			for (j = 0; j < info->miner_count[i]; j++) {
				for (l = 0; l < AVA10_DEFAULT_PLL_CNT; l++) {
					sprintf(buf, " PLLCNT%d_%d[", j, l);
					strcat(statbuf, buf);
					for (k = 0; k < info->asic_count[i]; k++) {
						sprintf(buf, "%3d ", info->get_asic[i][j][k][2 + l]);
						strcat(statbuf, buf);
					}

					statbuf[strlen(statbuf) - 1] = ']';
					statbuf[strlen(statbuf)] = '\0';
				}
			}

			for (j = 0; j < info->miner_count[i]; j++) {
				sprintf(buf, " ERATIO%d[", j);
				strcat(statbuf, buf);
				for (k = 0; k < info->asic_count[i]; k++) {
					if (info->get_asic[i][j][k][0])
						sprintf(buf, "%6.2f%% ", (double)(info->get_asic[i][j][k][1] * 100.0 / (info->get_asic[i][j][k][0] + info->get_asic[i][j][k][1])));
					else
						sprintf(buf, "%6.2f%% ", 0.0);
					strcat(statbuf, buf);
				}

				statbuf[strlen(statbuf) - 1] = ']';
			}

			/* i: modular, j: miner, k: asic, l: value */
			for (l = 0; l < 2; l++) {
				for (j = 0; j < info->miner_count[i]; j++) {
					sprintf(buf, " C_%02d_%02d[", j, l);
					strcat(statbuf, buf);
					for (k = 0; k < info->asic_count[i]; k++) {
						sprintf(buf, "%7d ", info->get_asic[i][j][k][l]);
						strcat(statbuf, buf);
					}

					statbuf[strlen(statbuf) - 1] = ']';
				}
			}

			for (j = 0; j < info->miner_count[i]; j++) {
				sprintf(buf, " GHSmm%02d[", j);
				strcat(statbuf, buf);
				for (k = 0; k < info->asic_count[i]; k++) {
					mhsmm = 0;
					for (l = 2; l < 6; l++) {
						mhsmm += (info->get_asic[i][j][k][l] * info->get_frequency[i][j][k][l - 2]);
					}
					sprintf(buf, "%7.2f ", mhsmm / 1000);
					strcat(statbuf, buf);
				}
				statbuf[strlen(statbuf) - 1] = ']';
			}
		}

		strcat(statbuf, " CRC[");
		for (j = 0; j < info->miner_count[i]; j++) {
			sprintf(buf, "%d ", info->error_crc[i][j]);
			strcat(statbuf, buf);
		}
		statbuf[strlen(statbuf) - 1] = ']';

		sprintf(buf, "MM ID%d", i);
		root = api_add_string(root, buf, statbuf, true);
	}
	free(statbuf);

	root = api_add_int(root, "MM Count", &(info->mm_count), true);
	root = api_add_int(root, "Smart Speed", &opt_avalon10_smart_speed, true);

	if (info->connecter == AVA10_CONNECTER_AUC) {
		root = api_add_string(root, "Connecter", "AUC", true);
		root = api_add_string(root, "AUC VER", info->auc_version, false);
		root = api_add_int(root, "AUC I2C Speed", &(info->auc_speed), true);
		root = api_add_int(root, "AUC I2C XDelay", &(info->auc_xdelay), true);
		root = api_add_int(root, "AUC Sensor", &(info->auc_sensor), true);
		auc_temp = decode_auc_temp(info->auc_sensor);
		root = api_add_temp(root, "AUC Temperature", &auc_temp, true);
	}

	root = api_add_bool(root, "Connection Overloaded", &info->conn_overloaded, true);
	root = api_add_int(root, "Voltage Level Offset", &opt_avalon10_voltage_level_offset, true);
	root = api_add_uint32(root, "Nonce Mask", &opt_avalon10_nonce_mask, true);

	return root;
}

/* format: voltage[-addr[-miner]]
 * addr[0, AVA10_DEFAULT_MODULARS - 1], 0 means all modulars
 * miner[0, miner_count], 0 means all miners
 */
char *set_avalon10_device_voltage_level(struct cgpu_info *avalon10, char *arg)
{
	struct avalon10_info *info = avalon10->device_data;
	int val;
	unsigned int addr = 0, i, j;
	uint32_t miner_id = 0;

	if (!(*arg))
		return NULL;

	sscanf(arg, "%d-%d-%d", &val, &addr, &miner_id);

	if (val < AVA10_DEFAULT_VOLTAGE_LEVEL_MIN || val > AVA10_DEFAULT_VOLTAGE_LEVEL_MAX)
		return "Invalid value passed to set_avalon10_device_voltage_level";

	if (addr >= AVA10_DEFAULT_MODULARS) {
		applog(LOG_ERR, "invalid modular index: %d, valid range 0-%d", addr, (AVA10_DEFAULT_MODULARS - 1));
		return "Invalid modular index to set_avalon10_device_voltage_level";
	}

	if (!addr) {
		for (i = 1; i < AVA10_DEFAULT_MODULARS; i++) {
			if (!info->enable[i])
				continue;

			if (miner_id > info->miner_count[i]) {
				applog(LOG_ERR, "invalid miner index: %d, valid range 0-%d", miner_id, info->miner_count[i]);
				return "Invalid miner index to set_avalon10_device_voltage_level";
			}

			if (miner_id)
				info->set_voltage_level[i][miner_id - 1] = val;
			else {
				for (j = 0; j < info->miner_count[i]; j++)
					info->set_voltage_level[i][j] = val;
			}
			avalon10_set_voltage_level(avalon10, i, info->set_voltage_level[i]);
		}
	} else {
		if (!info->enable[addr]) {
			applog(LOG_ERR, "Disabled modular:%d", addr);
			return "Disabled modular to set_avalon10_device_voltage_level";
		}

		if (miner_id > info->miner_count[addr]) {
			applog(LOG_ERR, "invalid miner index: %d, valid range 0-%d", miner_id, info->miner_count[addr]);
			return "Invalid miner index to set_avalon10_device_voltage_level";
		}

		if (miner_id)
			info->set_voltage_level[addr][miner_id - 1] = val;
		else {
			for (j = 0; j < info->miner_count[addr]; j++)
				info->set_voltage_level[addr][j] = val;
		}
		avalon10_set_voltage_level(avalon10, addr, info->set_voltage_level[addr]);
	}

	applog(LOG_NOTICE, "%s-%d: Update voltage-level to %d", avalon10->drv->name, avalon10->device_id, val);

	return NULL;
}

/*
 * format: freq[-addr[-miner]]
 * addr[0, AVA10_DEFAULT_MODULARS - 1], 0 means all modulars
 * miner[0, miner_count], 0 means all miners
 */
char *set_avalon10_device_freq(struct cgpu_info *avalon10, char *arg)
{
	struct avalon10_info *info = avalon10->device_data;
	unsigned int val[AVA10_DEFAULT_PLL_CNT], addr = 0, i, j, k;
	uint32_t miner_id = 0;
	uint32_t asic_id = 0;

	if (!(*arg))
		return NULL;

	sscanf(arg, "%d:%d:%d:%d-%d-%d-%d", &val[0], &val[1], &val[2], &val[3], &addr, &miner_id, &asic_id);

	if (val[AVA10_DEFAULT_PLL_CNT - 1] > AVA10_DEFAULT_FREQUENCY_MAX)
		return "Invalid value passed to set_avalon10_device_freq";

	if (addr >= AVA10_DEFAULT_MODULARS) {
		applog(LOG_ERR, "invalid modular index: %d, valid range 0-%d", addr, (AVA10_DEFAULT_MODULARS - 1));
		return "Invalid modular index to set_avalon10_device_freq";
	}

	if (miner_id > AVA10_DEFAULT_MINER_CNT)
		return "Invalid miner id passed to set_avalon10_device_freq";

	if (asic_id > AVA10_DEFAULT_ASIC_MAX)
		return "Invalid asic id passed to set_avalon10_device_freq";

	if (!addr) {
		for (i = 0; i < AVA10_DEFAULT_MODULARS; i++) {
			if (!info->enable[i])
				continue;

			if (miner_id > info->miner_count[i]) {
				applog(LOG_ERR, "invalid miner index: %d, valid range 0-%d", miner_id, info->miner_count[i]);
				return "Invalid miner index to set_avalon10_device_freq";
			}

			if (miner_id) {
				for (k = 0; k < AVA10_DEFAULT_PLL_CNT; k++)
					info->set_frequency[i][miner_id - 1][k] = val[k];

				if (!asic_id)
					avalon10_set_freq(avalon10, i, miner_id - 1, AVA10_ASIC_ID_BROADCAST, info->set_frequency[i][miner_id - 1]);
				else
					avalon10_set_freq(avalon10, i, miner_id - 1, asic_id - 1, info->set_frequency[i][miner_id - 1]);
			} else {
				for (j = 0; j < info->miner_count[i]; j++) {
					for (k = 0; k < AVA10_DEFAULT_PLL_CNT; k++)
						info->set_frequency[i][j][k] = val[k];

					if (!asic_id)
						avalon10_set_freq(avalon10, i, j, AVA10_ASIC_ID_BROADCAST, info->set_frequency[i][j]);
					else
						avalon10_set_freq(avalon10, i, j, asic_id - 1, info->set_frequency[i][j]);
				}
			}
		}
	} else {
		if (!info->enable[addr]) {
			applog(LOG_ERR, "Disabled modular:%d", addr);
			return "Disabled modular to set_avalon10_device_freq";
		}

		if (miner_id > info->miner_count[addr]) {
			applog(LOG_ERR, "invalid miner index: %d, valid range 0-%d", miner_id, info->miner_count[addr]);
			return "Invalid miner index to set_avalon10_device_freq";
		}

		if (miner_id) {
			for (k = 0; k < AVA10_DEFAULT_PLL_CNT; k++)
				info->set_frequency[addr][miner_id - 1][k] = val[k];

			if (!asic_id)
				avalon10_set_freq(avalon10, addr, miner_id - 1, AVA10_ASIC_ID_BROADCAST, info->set_frequency[addr][miner_id - 1]);
			else
				avalon10_set_freq(avalon10, addr, miner_id - 1, asic_id - 1, info->set_frequency[addr][miner_id - 1]);
		} else {
			for (j = 0; j < info->miner_count[addr]; j++) {
				for (k = 0; k < AVA10_DEFAULT_PLL_CNT; k++)
					info->set_frequency[addr][j][k] = val[k];

				if (!asic_id)
					avalon10_set_freq(avalon10, addr, j, AVA10_ASIC_ID_BROADCAST, info->set_frequency[addr][j]);
				else
					avalon10_set_freq(avalon10, addr, j, asic_id - 1, info->set_frequency[addr][j]);
			}
		}
	}

	applog(LOG_NOTICE, "%s-%d: Update frequency to %d:%d:%d:%d",
		avalon10->drv->name, avalon10->device_id, val[0], val[1], val[2], val[3]);

	return NULL;
}

char *set_avalon10_factory_info(struct cgpu_info *avalon10, char *arg)
{
	struct avalon10_info *info = avalon10->device_data;
	char type[AVA10_DEFAULT_FACTORY_INFO_1_CNT];
	int val, i;

	if (!(*arg))
		return NULL;

	memset(type, 0, AVA10_DEFAULT_FACTORY_INFO_1_CNT);

	sscanf(arg, "%d-%s", &val, type);

	if ((val != AVA10_DEFAULT_FACTORY_INFO_0_IGNORE) &&
				(val < AVA10_DEFAULT_FACTORY_INFO_0_MIN || val > AVA10_DEFAULT_FACTORY_INFO_0_MAX))
		return "Invalid value passed to set_avalon10_factory_info";

	for (i = 1; i < AVA10_DEFAULT_MODULARS; i++) {
		if (!info->enable[i])
			continue;

		info->factory_info[i][0] = val;

		memcpy(&info->factory_info[i][1], type, AVA10_DEFAULT_FACTORY_INFO_1_CNT);

		avalon10_set_factory_info(avalon10, i, (uint8_t *)info->factory_info[i]);
	}

	applog(LOG_NOTICE, "%s-%d: Update factory info %d",
		avalon10->drv->name, avalon10->device_id, val);

	return NULL;
}

char *set_avalon10_adjust_voltage_info(struct cgpu_info *avalon10, char *arg)
{
	struct avalon10_info *info = avalon10->device_data;
	int up_init, up_factor, up_threshold, down_init, down_factor, down_threshold, time;

	if (!(*arg))
		return NULL;

	sscanf(arg, "%d-%d-%d-%d-%d-%d-%d", &up_init, &up_factor, &up_threshold, &down_init, &down_factor, &down_threshold, &time);

	avalon10_set_adjust_voltage_option(avalon10, 0, up_init, up_factor, up_threshold, down_init, down_factor, down_threshold, time);

	applog(LOG_NOTICE, "%s-%d: Update adjust voltage info: [%d, %d, %d, %d, %d, %d, %d]",
		avalon10->drv->name, avalon10->device_id, up_init, up_factor, up_threshold,
		down_init, down_factor, up_threshold, time);

	return NULL;
}

char *set_avalon10_target_temp_info(struct cgpu_info *avalon10, char *arg)
{
	struct avalon10_info *info = avalon10->device_data;
	int i, val;

	if (!(*arg))
		return NULL;

	sscanf(arg, "%d", &val);

	if (val < AVA10_DEFAULT_TEMP_MIN || val > AVA10_DEFAULT_TEMP_MAX)
		return "Invalid temperature value to set_avalon10_target_temp_info";

	for (i = 1; i < AVA10_DEFAULT_MODULARS; i++)
		info->temp_target[i] = val;

	applog(LOG_NOTICE, "%s-%d: Update temperature info: %d",
		avalon10->drv->name, avalon10->device_id, val);

	return NULL;
}

static char *avalon10_set_device(struct cgpu_info *avalon10, char *option, char *setting, char *replybuf)
{
	unsigned int val;
	struct avalon10_info *info = avalon10->device_data;

	if (strcasecmp(option, "help") == 0) {
		sprintf(replybuf, "pdelay|fan|frequency|led|voltage");
		return replybuf;
	}

	if (strcasecmp(option, "pdelay") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing polling delay setting");
			return replybuf;
		}

		val = (unsigned int)atoi(setting);
		if (val < 1 || val > 65535) {
			sprintf(replybuf, "invalid polling delay: %d, valid range 1-65535", val);
			return replybuf;
		}

		opt_avalon10_polling_delay = val;

		applog(LOG_NOTICE, "%s-%d: Update polling delay to: %d",
		       avalon10->drv->name, avalon10->device_id, val);

		return NULL;
	}

	if (strcasecmp(option, "fan") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing fan value");
			return replybuf;
		}

		if (set_avalon10_fan(setting)) {
			sprintf(replybuf, "invalid fan value, valid range 0-100");
			return replybuf;
		}

		applog(LOG_NOTICE, "%s-%d: Update fan to %d-%d",
		       avalon10->drv->name, avalon10->device_id,
		       opt_avalon10_fan_min, opt_avalon10_fan_max);

		return NULL;
	}

	if (strcasecmp(option, "frequency") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing frequency value");
			return replybuf;
		}

		return set_avalon10_device_freq(avalon10, setting);
	}

	if (strcasecmp(option, "led") == 0) {
		int val_led = -1;

		if (!setting || !*setting) {
			sprintf(replybuf, "missing module_id setting");
			return replybuf;
		}

		sscanf(setting, "%d-%d", &val, &val_led);
		if (val < 1 || val >= AVA10_DEFAULT_MODULARS) {
			sprintf(replybuf, "invalid module_id: %d, valid range 1-%d", val, AVA10_DEFAULT_MODULARS);
			return replybuf;
		}

		if (!info->enable[val]) {
			sprintf(replybuf, "the current module was disabled %d", val);
			return replybuf;
		}

		if (val_led == -1)
			info->led_indicator[val] = !info->led_indicator[val];
		else {
			if (val_led < 0 || val_led > 1) {
				sprintf(replybuf, "invalid LED status: %d, valid value 0|1", val_led);
				return replybuf;
			}

			if (val_led != info->led_indicator[val])
				info->led_indicator[val] = val_led;
		}

		applog(LOG_NOTICE, "%s-%d: Module:%d, LED: %s",
				avalon10->drv->name, avalon10->device_id,
				val, info->led_indicator[val] ? "on" : "off");

		return NULL;
	}

	if (strcasecmp(option, "voltage-level") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing voltage-level value");
			return replybuf;
		}

		return set_avalon10_device_voltage_level(avalon10, setting);
	}

	if (strcasecmp(option, "factory") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing factory info");
			return replybuf;
		}

		return set_avalon10_factory_info(avalon10, setting);
	}

	if (strcasecmp(option, "reboot") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing reboot value");
			return replybuf;
		}

		sscanf(setting, "%d", &val);
		if (val < 1 || val >= AVA10_DEFAULT_MODULARS) {
			sprintf(replybuf, "invalid module_id: %d, valid range 1-%d", val, AVA10_DEFAULT_MODULARS);
			return replybuf;
		}

		info->reboot[val] = true;

		return NULL;
	}

	if (strcasecmp(option, "adjust-voltage") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing adjust-voltage info");
			return replybuf;
		}

		return set_avalon10_adjust_voltage_info(avalon10, setting);
	}

	if (strcasecmp(option, "target-temp") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing target temperature info");
			return replybuf;
		}

		return set_avalon10_target_temp_info(avalon10, setting);
	}

	sprintf(replybuf, "Unknown option: %s", option);
	return replybuf;
}

static void avalon10_statline_before(char *buf, size_t bufsiz, struct cgpu_info *avalon10)
{
	struct avalon10_info *info = avalon10->device_data;
	int temp = -273;
	int fanmin = AVA10_DEFAULT_FAN_MAX;
	int i, j, k;
	uint32_t frequency = 0;
	float ghs_sum = 0, mhsmm = 0;
	double pass_num = 0.0, fail_num = 0.0;

	for (i = 1; i < AVA10_DEFAULT_MODULARS; i++) {
		if (!info->enable[i])
			continue;

		if (fanmin >= info->fan_pct[i])
			fanmin = info->fan_pct[i];

		if (temp < get_temp_max(info, i))
			temp = get_temp_max(info, i);

		mhsmm = avalon10_hash_cal(avalon10, i);
		frequency += (mhsmm / (info->asic_count[i] * info->miner_count[i] * 236));
		ghs_sum += (mhsmm / 1000);

		for (j = 0; j < info->miner_count[i]; j++) {
			for (k = 0; k < info->asic_count[i]; k++) {
				pass_num += info->get_asic[i][j][k][0];
				fail_num += info->get_asic[i][j][k][1];
			}
		}
	}

	if (info->mm_count)
		frequency /= info->mm_count;

	tailsprintf(buf, bufsiz, "%4dMhz %.2fGHS %2dC %.2f%% %3d%%", frequency, ghs_sum, temp,
				(fail_num + pass_num) ? fail_num * 100.0 / (fail_num + pass_num) : 0, fanmin);
}

static struct cgpu_info *avalon10_auc_detect(struct libusb_device *dev, struct usb_find_devices *found)
{
	int i, modules = 0;
	struct avalon10_info *info;
	struct cgpu_info *avalon10 = usb_alloc_cgpu(&avalon10_drv, 1);
	char auc_ver[AVA10_AUC_VER_LEN];

	if (!usb_init(avalon10, dev, found)) {
		applog(LOG_ERR, "avalon10 failed usb_init");
		avalon10 = usb_free_cgpu(avalon10);
		return NULL;
	}

	/* avalon10 prefers not to use zero length packets */
	avalon10->nozlp = true;

	/* We try twice on AUC init */
	if (avalon10_auc_init(avalon10, auc_ver) && avalon10_auc_init(avalon10, auc_ver))
		return NULL;

	applog(LOG_INFO, "%s-%d: Found at %s", avalon10->drv->name, avalon10->device_id,
	       avalon10->device_path);

	avalon10->device_data = cgcalloc(sizeof(struct avalon10_info), 1);
	memset(avalon10->device_data, 0, sizeof(struct avalon10_info));
	info = avalon10->device_data;
	memcpy(info->auc_version, auc_ver, AVA10_AUC_VER_LEN);
	info->auc_version[AVA10_AUC_VER_LEN] = '\0';
	info->auc_speed = opt_avalon10_aucspeed;
	info->auc_xdelay = opt_avalon10_aucxdelay;

	for (i = 0; i < AVA10_DEFAULT_MODULARS; i++)
		info->enable[i] = 0;

	info->connecter = AVA10_CONNECTER_AUC;

	detect_modules(avalon10);
	for (i = 0; i < AVA10_DEFAULT_MODULARS; i++)
		modules += info->enable[i];

	if (!modules) {
		applog(LOG_INFO, "avalon10 found but no modules initialised");
		free(info);
		avalon10 = usb_free_cgpu(avalon10);
		return NULL;
	}

	/* We have an avalon10 AUC connected */
	avalon10->threads = 1;
	avalon10->drv->max_diff = opt_avalon10_target_diff;
	add_cgpu(avalon10);

	update_usb_stats(avalon10);

	return avalon10;
}

static inline void avalon10_detect(bool __maybe_unused hotplug)
{
	usb_detect(&avalon10_drv, avalon10_auc_detect);
}

static bool avalon10_prepare(struct thr_info *thr)
{
	struct cgpu_info *avalon10 = thr->cgpu;
	struct avalon10_info *info = avalon10->device_data;

	info->last_diff1 = 0;
	info->pending_diff1 = 0;
	info->last_rej = 0;
	info->mm_count = 0;
	info->xfer_err_cnt = 0;
	info->pool_no = 0;

	memset(&(info->firsthash), 0, sizeof(info->firsthash));
	cgtime(&(info->last_fan_adj));
	cgtime(&info->last_stratum);
	cgtime(&info->last_detect);

	cglock_init(&info->update_lock);
	cglock_init(&info->pool0.data_lock);
	cglock_init(&info->pool1.data_lock);
	cglock_init(&info->pool2.data_lock);

	return true;
}

static void avalon10_sswork_flush(struct cgpu_info *avalon10)
{
	struct avalon10_info *info = avalon10->device_data;
	struct thr_info *thr = avalon10->thr[0];
	struct pool *pool;
	int coinbase_len_posthash, coinbase_len_prehash;

	applog(LOG_NOTICE, "%s-%d: Flush stratum: restart: %d, update: %d",
	avalon10->drv->name, avalon10->device_id,
	thr->work_restart, thr->work_update);

	if (thr->work_restart)
		info->work_restart = true;

	if (!thr->work_update)
		return;

	thr->work_update = false;

	cgtime(&info->last_stratum);

	pool = current_pool();
	if (!pool->has_stratum)
		quit(1, "%s-%d: MM has to use stratum pools", avalon10->drv->name, avalon10->device_id);

	coinbase_len_prehash = pool->nonce2_offset - (pool->nonce2_offset % SHA256_BLOCK_SIZE);
	coinbase_len_posthash = pool->coinbase_len - coinbase_len_prehash;

	if (coinbase_len_posthash + SHA256_BLOCK_SIZE > AVA10_P_COINBASE_SIZE) {
		applog(LOG_ERR, "%s-%d: MM pool modified coinbase length(%d) is more than %d", avalon10->drv->name, avalon10->device_id,
									coinbase_len_posthash + SHA256_BLOCK_SIZE, AVA10_P_COINBASE_SIZE);
		return;
	}

	if (pool->merkles > AVA10_P_MERKLES_COUNT) {
		applog(LOG_ERR, "%s-%d: MM merkles has to be less then %d", avalon10->drv->name, avalon10->device_id, AVA10_P_MERKLES_COUNT);
		return;
	}

	if (pool->n2size < 3) {
		applog(LOG_ERR, "%s-%d: MM nonce2 size has to be >= 3 (%d)", avalon10->drv->name, avalon10->device_id, pool->n2size);
		return;
	}

	cg_wlock(&info->update_lock);

	cg_rlock(&pool->data_lock);
	info->pool_no = pool->pool_no;
	copy_pool_stratum(&info->pool2, &info->pool1);
	copy_pool_stratum(&info->pool1, &info->pool0);
	copy_pool_stratum(&info->pool0, pool);
	avalon10_stratum_pkgs(avalon10, pool);
	cg_runlock(&pool->data_lock);

	avalon10_stratum_finish(avalon10);

	cg_wunlock(&info->update_lock);
}

static void avalon10_sswork_update(struct cgpu_info *avalon10)
{
	struct avalon10_info *info = avalon10->device_data;
	struct thr_info *thr = avalon10->thr[0];
	struct pool *pool;
	int coinbase_len_posthash, coinbase_len_prehash;

	cgtime(&info->last_stratum);

	applog(LOG_NOTICE, "%s-%d: New stratum: restart: %d, update: %d", avalon10->drv->name, avalon10->device_id,
										thr->work_restart, thr->work_update);

	pool = current_pool();
	if (!pool->has_stratum)
		quit(1, "%s-%d: MM has to use stratum pools", avalon10->drv->name, avalon10->device_id);

	coinbase_len_prehash = pool->nonce2_offset - (pool->nonce2_offset % SHA256_BLOCK_SIZE);
	coinbase_len_posthash = pool->coinbase_len - coinbase_len_prehash;

	if (coinbase_len_posthash + SHA256_BLOCK_SIZE > AVA10_P_COINBASE_SIZE) {
		applog(LOG_ERR, "%s-%d: MM pool modified coinbase length(%d) is more than %d", avalon10->drv->name, avalon10->device_id,
									coinbase_len_posthash + SHA256_BLOCK_SIZE, AVA10_P_COINBASE_SIZE);
		return;
	}

	if (pool->merkles > AVA10_P_MERKLES_COUNT) {
		applog(LOG_ERR, "%s-%d: MM merkles has to be less then %d", avalon10->drv->name, avalon10->device_id, AVA10_P_MERKLES_COUNT);
		return;
	}

	if (pool->n2size < 3) {
		applog(LOG_ERR, "%s-%d: MM nonce2 size has to be >= 3 (%d)", avalon10->drv->name, avalon10->device_id, pool->n2size);
		return;
	}

	cg_wlock(&info->update_lock);

	cg_rlock(&pool->data_lock);
	info->pool_no = pool->pool_no;
	copy_pool_stratum(&info->pool2, &info->pool1);
	copy_pool_stratum(&info->pool1, &info->pool0);
	copy_pool_stratum(&info->pool0, pool);
	avalon10_stratum_pkgs(avalon10, pool);
	cg_runlock(&pool->data_lock);

	avalon10_stratum_finish(avalon10);
	cg_wunlock(&info->update_lock);
}

static int64_t avalon10_scanhash(struct thr_info *thr)
{
	struct cgpu_info *avalon10 = thr->cgpu;
	struct avalon10_info *info = avalon10->device_data;
	struct timeval current;
	int i, j, k, count = 0;
	int temp_max;
	int64_t ret;
	bool update_settings = false;

	if ((info->connecter == AVA10_CONNECTER_AUC) &&
		(unlikely(avalon10->usbinfo.nodev))) {
		applog(LOG_ERR, "%s-%d: Device disappeared, shutting down thread",
				avalon10->drv->name, avalon10->device_id);
		return -1;
	}

	cgtime(&current);
	if (tdiff(&current, &(info->last_stratum)) > 180.0) {
		for (i = 1; i < AVA10_DEFAULT_MODULARS; i++) {
			if (!info->enable[i])
				continue;
			detach_module(avalon10, i);
		}
		info->mm_count = 0;
		return 0;
	}

	if ((tdiff(&current, &(info->last_detect)) > AVA10_MODULE_DETECT_INTERVAL) ||
		!info->mm_count) {
		cgtime(&info->last_detect);
		detect_modules(avalon10);
	}

	cg_rlock(&info->update_lock);
	polling(avalon10);
	cg_runlock(&info->update_lock);

	for (i = 1; i < AVA10_DEFAULT_MODULARS; i++) {
		if (info->enable[i])
			count++;
	}
	info->mm_count = count;

	/* Calculate hashes. Use the diff1 value which is scaled by
	 * device diff and is usually lower than pool diff which will give a
	 * more stable result, but remove diff rejected shares to more closely
	 * approximate diff accepted values. */
	info->pending_diff1 += avalon10->diff1 - info->last_diff1;
	info->last_diff1 = avalon10->diff1;
	info->pending_diff1 -= avalon10->diff_rejected - info->last_rej;
	info->last_rej = avalon10->diff_rejected;
	if (info->pending_diff1 && !info->firsthash.tv_sec) {
		cgtime(&info->firsthash);
		copy_time(&(avalon10->dev_start_tv), &(info->firsthash));
	}

	if (info->pending_diff1 <= 0)
		ret = 0;
	else {
		ret = info->pending_diff1;
		info->pending_diff1 = 0;
	}

	return ret * 0x100000000ull;
}

struct device_drv avalon10_drv = {
	.drv_id = DRIVER_avalon10,
	.dname = "avalon10",
	.name = "AV9",
	.set_device = avalon10_set_device,
	.get_api_stats = avalon10_api_stats,
	.get_statline_before = avalon10_statline_before,
	.drv_detect = avalon10_detect,
	.thread_prepare = avalon10_prepare,
	.hash_work = hash_driver_work,
	.flush_work = avalon10_sswork_flush,
	.update_work = avalon10_sswork_update,
	.scanwork = avalon10_scanhash,
	.max_diff = AVA10_DRV_DIFFMAX,
	.genwork = true,
};
