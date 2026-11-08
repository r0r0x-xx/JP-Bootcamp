/*  - rhandler.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_RUPLINK_H
#define FIRMWARE_RUPLINK_H
#include <Arduino.h>

#define UPLINK_FREQ (918)
#define UPLINK_BW (250)
#define UPLINK_SF (7)
#define UPLINK_CR (5)

typedef void (*radioPacketReceivedCb)(uint8_t *buffer, uint16_t buffer_len);

void uplinkRadioConfigure(void);
void uplinkRadioRegisterCb(radioPacketReceivedCb recv_cb);
void uplinkRadioCheckPacketReceived(void);

/* v1.0.5: what the radio measured on the last frame it handed up, for the
 * IDS event channel. Zero until the first frame arrives. */
float uplinkRadioLastRssi(void);
float uplinkRadioLastSnr(void);
bool uplinkRadioLastCrcBad(void);
#endif // FIRMWARE_RUPLINK_H