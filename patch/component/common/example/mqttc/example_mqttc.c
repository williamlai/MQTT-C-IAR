/*
MIT License

Copyright(c) 2020 William Lai

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files(the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions :

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "platform_opts.h"

#if CONFIG_EXAMPLE_MQTTC
#include "example_mqttc.h"

#include "FreeRTOS.h"
#include "task.h"

#include "wifi_conf.h"

#include <mbedTLS/config.h>
#include <mbedTLS/platform.h>
#include <mbedtls/net_sockets.h>
#include <mbedTLS/ssl.h>

#include "mqtt.h"

#define SERVER_HOST    "xxxxxxxxxxxxxx-ats.iot.us-east-1.amazonaws.com"
#define SERVER_PORT    "8883"

static const char *root_certificate =
"-----BEGIN CERTIFICATE-----\n" \
"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n" \
"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n" \
"...... Amazon root certificate ......\n" \
"5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n" \
"rqXRfboQnoZsG4q5WTP468SQvvG5\n" \
"-----END CERTIFICATE-----\n";

static const char *x509certificate =
"-----BEGIN CERTIFICATE-----\n" \
"MIIDWTCCAkGgAwIBAgIUZP61YEBIX39hSfrJiQqGTFMxD3swDQYJKoZIhvcNAQEL\n" \
"BQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g\n" \
"...... Your thing's x509 certificate ......\n" \
"46AkA1Pt0ruBM8a1G5OhkfOhB1Sqz2XoQ1H78M2g8FUNRTCaOrJDc5aZmKmKXXDG\n" \
"UkrEQnvV0ppDNb8WEUifPx/NtSFiohiCtJ+NgBY/yOA6Sd2OIbtiBH13DDI+\n" \
"-----END CERTIFICATE-----\n";

static const char *x509privatekey =
"-----BEGIN RSA PRIVATE KEY-----\n" \
"MIIEowIBAAKCAQEAo+fdFEZfySiQDqVzC37/PSsdUznPn8PUdDx5xqM9eaWhQMpH\n" \
"jEXw8urjmygO6p8OvPwYnpwQgmm0nmHjj1a3uZLNx3hmUPuZ65EIUDK1NrkCFbxJ\n" \
"...... Your thing's x509 privatekey ......\n" \
"z+F8Pl8KO/d6Y80SbWIGCAGtTgTT4r8tywNCtxJOUrNJVZv5TyB/qsYRZlgzQth5\n" \
"tzthwuAKlmwmutrApRJ56cGfTjQpC4DGHlg4YCFmdEUA8al2L3Vg\n" \
"-----END RSA PRIVATE KEY-----\n";

#define MY_CLIENT_ID "my_client_id"

#define SUBSCRIBE_TOPIC "hi"
#define PUBLISH_TOPIC   "hi"
#define PUBLISH_MESSAGE "hello"

#define MQTT_SENDBUF_SIZE 1024
#define MQTT_RECVBUF_SIZE 1024

static mbedtls_net_context server_fd;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;

static mbedtls_x509_crt rootCA;
static mbedtls_x509_crt x509cert;
static mbedtls_pk_context privkey;

struct mqtt_client client;
static uint8_t mqtt_sendbuf[ MQTT_SENDBUF_SIZE ];
static uint8_t mqtt_recvbuf[ MQTT_RECVBUF_SIZE ];

extern void *pvPortCalloc( size_t xWantedCnt, size_t xWantedSize );
extern void vPortFree( void *pv );

static int my_random( void *p_rng, unsigned char *output, size_t output_len )
{
    rtw_get_random_bytes( output, output_len );
    return 0;
}

static void publish_callback( void** unused, struct mqtt_response_publish *published )
{
    char *topic = NULL;
    char *msg = NULL;

    do
    {
        topic = (char *) malloc( published->topic_name_size + 1 );
        if ( topic == NULL )
        {
            printf( "mem error\n" );
            break;
        }

        msg = (char *) malloc( published->application_message_size + 1 );
        if ( msg == NULL )
        {
            printf("mem error\n");
            break;
        }

        snprintf( topic, published->topic_name_size + 1 , "%s", published->topic_name );
        snprintf( msg, published->application_message_size + 1 , "%s", published->application_message );

        printf( "recv topic:%s msg:%s\n", topic, msg );
    } while ( 0 );

    if ( topic != NULL )
    {
        free( topic );
        topic = NULL;
    }
    if ( msg != NULL )
    {
        free( msg );
        msg = NULL;
    }
}

static void mqttc_task( void *param )
{
    int ret;
    enum MQTTErrors err;

    while( wifi_is_ready_to_transceive( RTW_STA_INTERFACE ) != RTW_SUCCESS )
    {
        vTaskDelay( 1000 / portTICK_PERIOD_MS );
    }
    printf( "wifi connected\r\n" );

    mbedtls_platform_set_calloc_free( pvPortCalloc, vPortFree );

    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );

    mbedtls_x509_crt_init( &rootCA );
    mbedtls_x509_crt_init( &x509cert );
    mbedtls_pk_init( &privkey );

    do
    {
        if( ( ret = mbedtls_net_connect( &server_fd, SERVER_HOST, SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
        {
            printf( "ERROR: mbedtls_net_connect ret(%d)\n", ret );
            break;
        }

        mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );

        if( (ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0)
        {
            printf( "ERRPR: mbedtls_ssl_config_defaults ret(%d)\n", ret );
            break;
        }

        mbedtls_ssl_conf_rng( &conf, my_random, NULL );

        if( (ret = mbedtls_x509_crt_parse( &x509cert, x509certificate, strlen( x509certificate ) + 1 ) ) != 0 )
        {
            printf( "ERROR: mbedtls_x509_crt_parse cert %d\n", ret );
            break;
        }

        if( (ret = mbedtls_pk_parse_key( &privkey, x509privatekey, strlen( x509privatekey ) + 1, NULL, 0) ) != 0 )
        {
            printf( "ERROR: mbedtls_pk_parse_key %d\n", ret );
            break;
        }

        if( (ret = mbedtls_ssl_conf_own_cert( &conf, &x509cert, &privkey) ) != 0)
        {
            printf( "ERROR: mbedtls_ssl_conf_own_cert %d\n", ret );
            break;
        }

        if( (ret = mbedtls_x509_crt_parse(&rootCA, root_certificate, strlen(root_certificate) + 1)) != 0 )
        {
            printf( "ERROR: mbedtls_x509_crt_parse rootCA %d\n", ret );
            break;
        }

        mbedtls_ssl_conf_ca_chain( &conf, &rootCA, NULL );
        mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_REQUIRED );

        if( (ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
        {
            printf( "ERRPR: mbedtls_ssl_setup ret(%d)\n", ret );
            break;
        }

        if( (ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
        {
            printf( "ERROR: mbedtls_ssl_handshake ret(-0x%x)", -ret );
            break;
        }

        printf( "connected to %s\r\n", SERVER_HOST );
        
        mqtt_init( &client, &ssl, mqtt_sendbuf, sizeof( mqtt_sendbuf ), mqtt_recvbuf, sizeof( mqtt_recvbuf ), publish_callback );

        uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
        mqtt_connect( &client, MY_CLIENT_ID, NULL, NULL, 0, NULL, NULL, connect_flags, 400 );

        if ( client.error != MQTT_OK ) {
            printf( "error: %s\n", mqtt_error_str( client.error ) );
            break;
        }

        mbedtls_ssl_conf_read_timeout( &conf, 20 );

        mqtt_subscribe( &client, SUBSCRIBE_TOPIC, 0 );
        mqtt_sync( &client );
        vTaskDelay( 200 );

        printf( "publishing...\n" );
        mqtt_publish( &client, PUBLISH_TOPIC, PUBLISH_MESSAGE, strlen(PUBLISH_MESSAGE), MQTT_PUBLISH_QOS_1 );

        while( 1 )
        {
            err = mqtt_sync( &client );
            if ( err != MQTT_OK )
            {
                printf( "mqtt error:%s\r\n", mqtt_error_str( err ) );
            }
            vTaskDelay( 200 / portTICK_PERIOD_MS );
        }
    } while(0);

    printf( "close connection.\n" );

    vTaskDelete( NULL );
}

void example_mqttc( void )
{
    if( xTaskCreate( mqttc_task, (char const *)"mqttc_task", 1024, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS )
    {
        printf( "[%s] Create update task failed\r\n", __FUNCTION__ );
    }
}

#endif