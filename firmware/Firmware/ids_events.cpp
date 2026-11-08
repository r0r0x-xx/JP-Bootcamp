/*  - ids_events.cpp
 *
 * firmware v1.0.5 - event channel for the intrusion detection system.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "ids_events.h"
#include "mission.h"
#include "ruplink.h"
#include "spp.h"
#include "usbCDC.h"
#include <Arduino.h>

static inline int16_t to_fixed(float value) {
  return (int16_t)(value * 10.0f);
}

void idsEventBegin(ids_event_t *event, uint8_t origin, const uint8_t *frame,
                   uint16_t frame_len) {
  if (event == NULL) {
    return;
  }
  memset(event, 0, sizeof(ids_event_t));
  event->origin = origin;
  event->length = frame_len;
  event->apid = 0xFFFF;   /* until the header parses */
  event->sequence = 0xFFFF;

  // The SPP primary header is six bytes; read the two fields the IDS needs
  // straight off the wire, so a frame that fails to parse still reports
  // which APID it claimed to be.
  if (frame != NULL && frame_len >= SPP_PRIMARY_HEADER_LEN) {
    const uint16_t identification = ((uint16_t)frame[0] << 8) | frame[1];
    event->apid = identification & 0x7FF;
    event->sequence = (((uint16_t)frame[2] << 8) | frame[3]) & 0x3FFF;
    if ((identification >> 11) & 0x01) {
      event->flags |= IDS_FLAG_SEC_HEADER;
    }
  }

  if (origin == IDS_ORIGIN_RADIO) {
    event->rssi_dbm_x10 = to_fixed(uplinkRadioLastRssi());
    event->snr_db_x10 = to_fixed(uplinkRadioLastSnr());
    if (uplinkRadioLastCrcBad()) {
      event->flags |= IDS_FLAG_CRC_BAD;
    }
  }
}

void idsEventEmit(ids_event_t *event, uint8_t result) {
  if (event == NULL) {
    return;
  }
  event->result = result;

  uint8_t payload[IDS_EVENT_PAYLOAD_LEN];
  payload[0] = IDS_EVENT_VERSION;
  payload[1] = event->origin;
  payload[2] = (uint8_t)(event->apid >> 8);
  payload[3] = (uint8_t)(event->apid & 0xFF);
  payload[4] = (uint8_t)(event->length >> 8);
  payload[5] = (uint8_t)(event->length & 0xFF);
  payload[6] = (uint8_t)(event->sequence >> 8);
  payload[7] = (uint8_t)(event->sequence & 0xFF);
  payload[8] = (uint8_t)((event->rssi_dbm_x10 >> 8) & 0xFF);
  payload[9] = (uint8_t)(event->rssi_dbm_x10 & 0xFF);
  payload[10] = (uint8_t)((event->snr_db_x10 >> 8) & 0xFF);
  payload[11] = (uint8_t)(event->snr_db_x10 & 0xFF);
  payload[12] = event->result;
  payload[13] = event->mission_mode;
  payload[14] = event->flags;

  // Cleartext on purpose: the IDS must not need the spacecraft's key, and
  // nothing here is secret -- it is metadata about a frame that was already
  // on the air.
  space_packet_t packet;
  memset(&packet, 0, sizeof(packet));
  if (spp_tm_build_packet(&packet, SPP_GROUP_FLAG_UNSEGMENTED,
                          SPP_SECHEAD_FLAG_NOPRESENT, 0,
                          SPP_APID_TM_IDS_EVENT, payload,
                          IDS_EVENT_PAYLOAD_LEN) != SPP_ERROR_NONE) {
    return;
  }
  const uint16_t total_len =
      SPP_PRIMARY_HEADER_LEN + (HOST_TO_BE16(packet.header.length) + 1);
  obcUSBTransmitFrame((uint8_t *)&packet, total_len);
}

void idsEventFinish(ids_event_t *event, bool refused) {
  if (event == NULL) {
    return;
  }
  if (refused) {
    idsEventEmit(event, IDS_RESULT_PAYLOAD_ERROR);
    return;
  }
  event->flags |= IDS_FLAG_EXECUTED;
  idsEventEmit(event, IDS_RESULT_OK);
}
