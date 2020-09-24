# IAR Port of MQTT-C

This repository is an IAR port of [MQTT-C library](https://github.com/LiamBindle/MQTT-C) and is verified on [Realtek AmebaZ2](https://github.com/ambiot/ambz2_sdk) evaluation board.

[MQTT-C library](https://github.com/LiamBindle/MQTT-C) is a lightweight MQTT library written in C.  It abstracts the transport layer with just few APIs, and it makes porting very easy.  I use MbedTLS as its transport layer in this repository.  With TLS as transport layer, I write a sample code and run it on AmebaZ2 evaluation board.  In the sample code, it connects to [AWS IoT core](https://aws.amazon.com/iot-core), subscribes MQTT topic, publishes MQTT message, and receives MQTT messages.

# How to apply this example

There is a folder named `patch` , you need to apply it to AmebaZ2's repository.  I suggest you to use file comparing tool to apply patch because you need to take care of IAR project files, MbedTLS config file, and project option file.

For demonstration purpose, you can apply this patch as following commands:

```bash
$ git clone https://github.com/ambiot/ambz2_sdk.git
$ cd ambz2_sdk && git reset --hard f5985eb50cd7690a2006e1bfb24b5371f5bdcb84 && cd ..
$ git clone https://github.com/williamlai/MQTT-C-IAR.git
$ cp -rf MQTT-C-IAR/patch/* ambz2_sdk/
$ cd ambz2_sdk
```

Then you need to configure settings in `component/common/example/mqttc/example_mqttc.c`  based on your AWS IoT thing's setting:

```c
#define SERVER_HOST    "xxxxxxxxxxxxxx-ats.iot.us-east-1.amazonaws.com"

static const char *root_certificate =
......

static const char *x509certificate =
......

static const char *x509privatekey =
......
```

Open AmebaZ2's IAR project file, build project, download application, and reset AmebaZ2 to free run.  After device connected to WiFi, got an IP address, the sample code will subscribe MQTT topic, publish MQTT message, and receive MQTT message.  You can monitor the running status on test console in [console.aws.amazon.com/iot](https://us-east-1.console.aws.amazon.com/iot/).

# Porting Guide of MQTT-C

## IAR port for MQTT-C

In file "[patch/component/common/application/MQTT-C/include/mqtt_pal.h](patch/component/common/application/MQTT-C/include/mqtt_pal.h)", there is a port implementation in section `#elif defined(__ICCARM__)`.  Here are function references:

*   MQTT-C's time reference:  FreeRTOS system tick.
*   MQTT-C's mutex:  FreeRTOS mutex
*   MQTT-C's host & net short convert:  lwip's htons & ntohs
*   MQTT-C's socket_handle:  MbedTLS's SSL contex

In file "[patch/component/common/application/MQTT-C/src/mqtt_pal.c](patch/component/common/application/MQTT-C/src/mqtt_pal.c)", I treat `MBEDTLS_ERR_SSL_TIMEOUT` not to be an error while doing ssl read and recv.  It's because I use receiving timeout instead of using select to do non-block recv.

## MbedTLS configuration

In file "[patch/component/common/network/ssl/mbedtls-2.4.0/include/mbedtls/config_rsa.h](patch/component/common/network/ssl/mbedtls-2.4.0/include/mbedtls/config_rsa.h)", I enlarge `MBEDTLS_SSL_MAX_CONTENT_LEN` to 6000 because the max frame while doing SSL handshake is nearly 6000, and SSL handshake would fail without enlarging this setting.

## IAR project setting

I just put sources and headers in this repository.  Nothing spececial.

# License

MQTT-C-IAR is a derived work from [MQTT-C library](https://github.com/LiamBindle/MQTT-C) and [Realtek AmebaZ2](https://github.com/ambiot/ambz2_sdk).

Files imported from [MQTT-C library](https://github.com/LiamBindle/MQTT-C) in this repository are under MQTT-C's license disclaimer which is the MIT License.

Files imported from [Realtek AmebaZ2](https://github.com/ambiot/ambz2_sdk) in this repository are under Realtek's license disclaimer.

Files that are not imported from [MQTT-C library](https://github.com/LiamBindle/MQTT-C) or [Realtek AmebaZ2](https://github.com/ambiot/ambz2_sdk) are under the [MIT License](https://opensource.org/licenses/MIT).  See the `"LICENSE"` file for more details.  

# Author

MQTT-C-IAR is a work in spare time and was developed by **William Lai**.