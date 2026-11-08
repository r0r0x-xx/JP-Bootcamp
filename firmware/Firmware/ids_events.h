/*  - ids_events.h
 *
 * firmware v1.0.5 - event channel for the intrusion detection system.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * One event per frame the board receives, over radio or over USB, emitted
 * on the binary CDC endpoint as an ordinary SPP telemetry packet
 * (SPP_APID_TM_IDS_EVENT). It says what arrived, how it arrived, what the
 * firmware made of it, and whether the command ran.
 *
 * Three decisions worth knowing:
 *
 *  * **Always cleartext.** The event rides beside the telemetry but is never
 *    encrypted: an IDS should not need the spacecraft's key to see that a
 *    frame arrived, and the event carries no payload bytes -- only facts
 *    about the frame.
 *  * **USB only.** Events do not go out on the radio. They would double the
 *    airtime for no reason; the IDS sits on the ground, beside the board.
 *  * **Versioned.** The first byte of the payload is the event format
 *    version. The IDS checks it and refuses formats it does not know,
 *    rather than guessing from the firmware version.
 *
 * The board reports; it does not judge. There is no "attack detected" field
 * here, and there should never be one: detection belongs to the IDS, which
 * can be updated without reflashing a spacecraft.
 */
#ifndef FIRMWARE_IDS_EVENTS_H
#define FIRMWARE_IDS_EVENTS_H
#include <Arduino.h>

#define IDS_EVENT_VERSION 1
#define IDS_EVENT_PAYLOAD_LEN 15

/* Where the frame came from. */
#define IDS_ORIGIN_RADIO 0x00
#define IDS_ORIGIN_USB 0x01
#define IDS_ORIGIN_ISL 0x02 /* reserved for the FlatSat-ISL line */

/* What the firmware made of it. */
#define IDS_RESULT_OK 0x00            /* parsed, accepted, handed to the handler */
#define IDS_RESULT_SPP_ERROR 0x01     /* did not parse as an SPP packet */
#define IDS_RESULT_DECRYPT_FAIL 0x02  /* secure link could not decode the payload */
#define IDS_RESULT_GATE_REJECT 0x03   /* ground-station gate refused the command */
#define IDS_RESULT_UNKNOWN_APID 0x04  /* parsed, but no handler for that APID */
#define IDS_RESULT_PAYLOAD_ERROR 0x05 /* handler refused the payload */
#define IDS_RESULT_SOURCE_REJECT 0x06 /* command not allowed from that source */

/* Flags byte. */
#define IDS_FLAG_EXECUTED 0x01     /* the command ran */
#define IDS_FLAG_ENCRYPTED 0x02    /* secure link was on for this frame */
#define IDS_FLAG_SEC_HEADER 0x04   /* the packet carried a secondary header */
#define IDS_FLAG_CRC_BAD 0x08      /* the radio reported a CRC mismatch */
#define IDS_FLAG_PAYLOAD_ARMED 0x10 /* mission payload was armed at the time */

typedef struct {
  uint8_t origin;
  uint16_t apid;
  uint16_t length;      /* bytes received, before any decoding */
  uint16_t sequence;    /* SPP sequence count, for correlation */
  int16_t rssi_dbm_x10; /* radio only; 0 over USB */
  int16_t snr_db_x10;   /* radio only; 0 over USB */
  uint8_t result;
  uint8_t mission_mode;
  uint8_t flags;
} ids_event_t;

/** @brief Start an event for a frame that just arrived. */
void idsEventBegin(ids_event_t *event, uint8_t origin, const uint8_t *frame,
                   uint16_t frame_len);

/** @brief Emit it. Safe to call once per received frame, at any exit. */
void idsEventEmit(ids_event_t *event, uint8_t result);

/** @brief Emit the event for a command that reached its handler.
 *
 * `refused` is true when the handler answered with an error telemetry --
 * a frequency outside the band, a locked flash window, an unknown thruster.
 * Those commands parsed, passed the gate and were still not carried out,
 * which is a different thing from both "executed" and "rejected at the
 * door", and an IDS wants to tell them apart. */
void idsEventFinish(ids_event_t *event, bool refused);

#endif // FIRMWARE_IDS_EVENTS_H
