#ifndef __IIC_H__
#define __IIC_H__

#define I2C_DEV                "/dev/i2c-1"
#define I2C_DEVICE_DETECT_ADDR 0x40

#define AVA4_RPI_VER      "RPi-20160301"
#define AVA4_RPI_VER_LEN  12

int rpi_i2c_device_detect(void);
int rpi_i2c_write(unsigned int addr, unsigned char *wbuf, unsigned int wlen);
int rpi_i2c_read(unsigned int addr, unsigned char *rbuf, unsigned int rlen);

#endif /* __IIC_H__ */
