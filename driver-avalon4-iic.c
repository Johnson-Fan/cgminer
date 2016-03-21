#include <stdio.h>
#include <stdint.h>
#include <linux/i2c-dev.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "driver-avalon4-iic.h"

static int g_i2cfd;
static uint8_t curslave_addr = 0;

static int rpi_i2c_open(char *dev)
{
	if ((g_i2cfd = open(dev, O_RDWR)) < 0)
		return 1;

	return 0;
}

static int rpi_i2c_close()
{
	close(g_i2cfd);
	g_i2cfd = -1;
	return 0;
}

int rpi_i2c_device_detect(void)
{
	if (rpi_i2c_open(I2C_DEV))
		return 1;

	if (rpi_i2c_write(I2C_DEVICE_DETECT_ADDR, "DETECT", 6))
		return 1;

	return 0;
}

int rpi_i2c_write(unsigned int addr, unsigned char *wbuf, unsigned int wlen)
{
	int ret;

	curslave_addr = addr;
	if (ioctl(g_i2cfd, I2C_SLAVE, addr) < 0)
		return 1;

	ret = write(g_i2cfd, wbuf, wlen);
	if (ret != wlen) {
		if (ret < 0)
			return -1;

		return 1;
	}
	return 0;
}

int rpi_i2c_read(unsigned int addr, unsigned char *rbuf, unsigned int rlen)
{
	int ret;

	curslave_addr = addr;
	if (ioctl(g_i2cfd, I2C_SLAVE, addr) < 0)
		return 1;

	ret = read(g_i2cfd, rbuf, rlen);
	if (ret != rlen) {
		if (ret < 0)
			return -1;

		return 1;
	}

	return 0;
}
