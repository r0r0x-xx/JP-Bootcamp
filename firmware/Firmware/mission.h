/*  - mission.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_MISSION_H
#define FIRMWARE_MISSION_H
#include <Arduino.h>

/* Radio off unless a build explicitly asks otherwise. The rationale is in
 * radio_off.h; this copy is here because the files that test the macro do not
 * all include that header. */
#ifndef FLATSAT_NO_RADIO
#define FLATSAT_NO_RADIO 1
#endif


/* v1.0.5. Up to v1.0.3 these three were left at 1.0.0, so the board
 * reported a version it had not been for two releases: SEND_FW answered
 * 1.0.0 while the firmware was 1.0.3. Fixed here, and worth knowing if you
 * are comparing captures taken before this release. */
#define FIRMWARE_PATCH 5
#define FIRMWARE_MINOR 0
#define FIRMWARE_MAJOR 1

/* The ISM band this firmware is allowed to transmit in. BROADCAST_MSG takes
 * its frequency from the telecommand (that is attack 02's relay); v1.0.5
 * keeps the relay and refuses anything outside these bounds. */
#define BROADCAST_FREQ_MIN_MHZ (902)
#define BROADCAST_FREQ_MAX_MHZ (928)

#define MAX_PAYLOAD_CHUNK 128
#define SPACECRAFT_ID 0x01

#define SC_TM_ID_ACCE_X 0x01
#define SC_TM_ID_ACCE_Y 0x02
#define SC_TM_ID_ACCE_Z 0x03
#define SC_TM_ID_ACCE_TMP 0x04

#define SC_TM_ID_BME_TEMPERATURE 0x05
#define SC_TM_ID_BME_PRESSURE 0x06
#define SC_TM_ID_BME_ALTITUDE 0x07
#define SC_TM_ID_BME_HUMIDITY 0x08

#define SC_TM_ID_SIM_THRUSTER0 0x09
#define SC_TM_ID_SIM_THRUSTER1 0x0A

#define MISSION_MODE_SAFE 0x00
#define MISSION_MODE_NOMINAL 0x01
#define MISSION_MODE_PAYLOAD 0x02
#define MISSION_MODE_SCIENCE 0x03
#define MISSION_MODE_CONTINGENCY 0x04

#define MISSION_FLAG_BME_OK 0x01
#define MISSION_FLAG_ACC_OK 0x02
#define MISSION_FLAG_GPS_UART_OK 0x04
#define MISSION_FLAG_GPS_FIX 0x08
#define MISSION_FLAG_SECURE_LINK 0x10
#define MISSION_FLAG_PAYLOAD_ARMED 0x20
#define MISSION_FLAG_USB_DEBUG 0x40
#define MISSION_FLAG_GPS_NMEA_ACTIVE 0x80

#define GPS_STATUS_UART_OK 0x01
#define GPS_STATUS_CONNECTED 0x02
#define GPS_STATUS_NMEA_ACTIVE 0x04
#define GPS_STATUS_FIX_VALID 0x08
#define GPS_STATUS_TIME_VALID 0x10

#define GS_STATUS_MODE_ENABLED 0x01
#define GS_STATUS_GPS_VALID 0x02
#define GS_STATUS_WITHIN_RANGE 0x04
#define GS_STATUS_AUTH_ACTIVE 0x08
#define GS_STATUS_HANDSHAKE_PENDING 0x10
#define GS_STATUS_GATE_OPEN 0x20

/* APIDS TC */
// On Board Computer
#define SPP_APID_TC_PING 0x01
#define SPP_APID_TC_RESETC 0x02
#define SPP_APID_TC_SEND_FW 0x03
// EPS
#define SPP_APID_TC_SET_THRUSTER 0x04
// Communications
#define SPP_APID_TC_SET_BEACON_RATE 0x05
#define SPP_APID_TC_BROADCAST_MSG 0x06
#define SPP_APID_TC_FLASH 0x07
#define SPP_APID_TC_AES_CONFIG 0x0A
#define SPP_APID_TC_FLASH_READ 0x0B
#define SPP_APID_TC_GET_STATUS 0x0C
#define SPP_APID_TC_SET_MISSION_MODE 0x0D
#define SPP_APID_TC_GET_NAV 0x0E
#define SPP_APID_TC_GET_PAYLOAD_STATUS 0x0F
#define SPP_APID_TC_DEBUG_CONFIG 0x10
#define SPP_APID_TC_GS_MODE 0x11
#define SPP_APID_TC_GS_ACCESS 0x12
#define SPP_APID_TC_GS_STATUS 0x13

/* Course build only, behind FLATSAT_GPS_OVERRIDE.
 *
 * The real position-spoofing attack is over the air, against the u-blox
 * receiver, and it has no USB equivalent because it attacks a separate piece
 * of hardware. With the radio held in reset there is no way to run it, and the
 * lesson -- a platform that trusts a position nothing authenticates -- is
 * worth more than the delivery mechanism. So the course build accepts the
 * position on the cable instead, at the same trust boundary.
 *
 * Payload, 13 octets, matching the attack scripts already in the repository:
 *   latE7 (i32 LE), lonE7 (i32 LE), altCm (i32 LE), satellites (u8)
 */
#define SPP_APID_TC_GPS_OVERRIDE 0x14
/* APIDS TM */
// On Board Computer
#define SPP_APID_TM_PING 0x01
#define SPP_APID_TM_RESETC 0x02
#define SPP_APID_TM_SEND_FW 0x03
// EPS
#define SPP_APID_TM_SET_THRUSTER 0x04
// Communications
#define SPP_APID_TM_SET_BEACON_RATE 0x05
#define SPP_APID_TM_BROADCAST_MSG 0x06
#define SPP_APID_TM_FLASH 0x07
#define SPP_APID_TM_SEND_TM 0x08
#define SPP_APID_TM_ERROR 0x09
#define SPP_APID_TM_AES_CONFIG 0x0A
#define SPP_APID_TM_FLASH_READ 0x0B
#define SPP_APID_TM_STATUS 0x0C
#define SPP_APID_TM_MISSION_MODE 0x0D
#define SPP_APID_TM_NAV 0x0E
#define SPP_APID_TM_PAYLOAD_STATUS 0x0F
#define SPP_APID_TM_DEBUG_CONFIG 0x10
#define SPP_APID_TM_GS_MODE 0x11
#define SPP_APID_TM_GS_ACCESS 0x12
#define SPP_APID_TM_GS_STATUS 0x13
/* v1.0.5: one event per received frame, for the IDS. Cleartext, USB only,
 * versioned -- see ids_events.h. */
#define SPP_APID_TM_GPS_OVERRIDE 0x14
#define SPP_APID_TM_IDS_EVENT 0x20

#endif // FIRMWARE_MISSION_H
