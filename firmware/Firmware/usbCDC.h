/*  - usbCDC.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_USBCDC_H
#define FIRMWARE_USBCDC_H
#include "ruplink.h"

#define USB_LINK_SYNC_WORD 0xAA

// The per-frame console hexdump. Useful at a bench with one board and
// somebody watching the console; a halt in a classroom where nobody opens
// that interface. Build with -DFLATSAT_USB_HEXDUMP=1 to get it back.
#ifndef FLATSAT_USB_HEXDUMP
#define FLATSAT_USB_HEXDUMP 0
#endif

void obcSetupUSB(void);
void obcConfigureCore0(void);
void obcConfigureCore1(void);

void obcUSBTransmitFrame(uint8_t *buffer, ssize_t buffer_len);

// How many telemetry frames were dropped because the host was not reading.
uint32_t obcUSBDroppedFrames(void);
void obcUSBRecv(void);
void obcUSBPacketRecivedCallback(radioPacketReceivedCb recv_cb);
#endif // FIRMWARE_USBCDC_H
