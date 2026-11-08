/*  - usbCDC.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "mission.h"
#include "usbCDC.h"
#include <Adafruit_TinyUSB.h>
#include <Arduino.h>

#define FRAME_HEADER_1 0xAA
#define FRAME_HEADER_2 0x55
#define HEADER_SIZE 4
#define MAX_FRAME_SIZE 1024

static uint8_t rx_buffer[MAX_FRAME_SIZE];
static size_t rx_len = 0;

#define BOARD_VERSION 0x0020 // Current version board 03/2026

Adafruit_USBD_CDC USBRadioLink;

static radioPacketReceivedCb usb_radio_cb = NULL;

void obcSetupUSB(void) {
  // v1.0.5: one serial per board, derived from the RP2040's own chip id.
  // Up to v1.0.3 every board answered "fsat", so with two of them on one
  // host the operating system gave the name to whichever enumerated first
  // and the other fell back to a generic one -- the port names then swapped
  // on every replug, which is a bad way to lose track of which spacecraft
  // you are commanding. The product string carries the version too, so
  // `system_profiler`/`lsusb` tells you what is on the board without
  // sending it a telecommand.
  static char serial_id[24];
  static char product_id[40];
  snprintf(serial_id, sizeof(serial_id), "fsat-%llX",
           (unsigned long long)rp2040.getChipID());
  snprintf(product_id, sizeof(product_id), "Pwnsat - Flatsat v%d.%d.%d",
           FIRMWARE_MAJOR, FIRMWARE_MINOR, FIRMWARE_PATCH);

  TinyUSBDevice.setID(0x239a, 0xcafe);
  TinyUSBDevice.setManufacturerDescriptor("Pwnsat");
  TinyUSBDevice.setProductDescriptor(product_id);
  TinyUSBDevice.setSerialDescriptor(serial_id);
  TinyUSBDevice.setDeviceVersion(BOARD_VERSION);
}

static void obcResetUSBStack(void) {
  if (TinyUSBDevice.mounted()) {
    TinyUSBDevice.detach();
    delay(10);
    TinyUSBDevice.attach();
  }
}

static void obcWaitConnectionCore0(void) {
  while (!Serial) {
    delay(1000);
  }
}

static void obcWaitConnectionCore1(void) {
  while (!USBRadioLink) {
    delay(1000);
  }
}

void obcConfigureCore0(void) {
  obcSetupUSB();

  Serial.begin(921600);
  obcWaitConnectionCore0();

  if (CFG_TUD_CDC < 2) {
    Serial.printf(
        "[WARNING] CFG_TUD_CDC must be at least 2, current value is %u\r\n",
        CFG_TUD_CDC);
    return;
  }
  Serial.printf("[INFO] USB Device configured successfully\r\n");
}

void obcConfigureCore1(void) {
  obcSetupUSB();
  USBRadioLink.begin(921600);
  obcResetUSBStack();
  obcWaitConnectionCore1();
}

void obcUSBPacketRecivedCallback(radioPacketReceivedCb recv_cb) {
  usb_radio_cb = recv_cb;
}

// Telemetry dropped because the host was not reading. Counted rather than
// hidden: a silent drop and a blocked board look the same from the ground,
// and they need opposite fixes.
static uint32_t usb_tx_dropped = 0;

uint32_t obcUSBDroppedFrames(void) { return usb_tx_dropped; }

void obcUSBTransmitFrame(uint8_t *buffer, ssize_t buffer_len) {
  // Adafruit_USBD_CDC::write spins in `while (remain && connected)` until the
  // FIFO drains. A host that has the port open but is not reading never
  // drains it, so that loop does not end: the board stops servicing obcUSBRecv
  // and goes deaf while still enumerated. Measured 7 Nov 2026, where a
  // FLASH_READ sent to a board whose output nobody was draining never reached
  // the handler and never appeared in the console log.
  //
  // So ask first, and drop the frame when there is no room. A downlink that
  // freezes the flight software because the ground stopped listening is worse
  // than a downlink that loses a packet.
  // Wait a bounded moment for room rather than dropping on the first look.
  // Dropping immediately traded one failure for another: with the host
  // reading normally the FIFO clears in microseconds, but a reply that
  // happened to find it momentarily full was lost and never retried, so
  // commands looked unanswered while telemetry kept flowing.
  //
  // Bounded is the point. Twenty yields is long enough for a host that is
  // reading and short enough that a host that is not cannot park this core.
  const size_t need = 1 + (size_t)buffer_len;
  for (uint8_t spin = 0; spin < 20; spin++) {
    if ((size_t)USBRadioLink.availableForWrite() >= need) {
      break;
    }
    yield();
  }
  if ((size_t)USBRadioLink.availableForWrite() < need) {
    usb_tx_dropped++;
    return;
  }

  USBRadioLink.write(USB_LINK_SYNC_WORD);
  USBRadioLink.write(buffer, buffer_len);
  // Without this the bytes sit in TinyUSB's FIFO until something else fills
  // it. Telemetry packets are 16 to 32 octets, so that took dozens of
  // commands: measured on hardware 7 Nov 2026, where the replies to forty
  // PINGs arrived together as one burst of 81 frames around the fortieth.
  // Every reply was correct and every one was far too late, which from the
  // ground is indistinguishable from a board that answers nothing.
  //
  // Every telemetry packet and every IDS event leaves through here, so this
  // is the one place the flush belongs.
  USBRadioLink.flush();
}

#if FLATSAT_USB_HEXDUMP
static void printHexDump(const uint8_t *data, size_t len) {
  const size_t bytesPerLine = 32;
  char ascii[bytesPerLine + 1];
  ascii[bytesPerLine] = '\0';

  for (size_t i = 0; i < len; i++) {
    if (i % bytesPerLine == 0) {
      if (i != 0) {
        Serial.print("  |");
        Serial.println(ascii);
      }
      Serial.printf("%08X  ", (unsigned int)i);
    }

    Serial.printf("%02X ", data[i]);
    ascii[i % bytesPerLine] = (data[i] >= 32 && data[i] <= 126) ? data[i] : '.';
  }

  size_t remaining = len % bytesPerLine;
  if (remaining > 0) {
    for (size_t i = remaining; i < bytesPerLine; i++) {
      Serial.print("   ");
    }
  }

  Serial.print("  |");
  ascii[remaining == 0 ? bytesPerLine : remaining] = '\0';
  Serial.println(ascii);
}
#endif // FLATSAT_USB_HEXDUMP

void obcUSBRecv(void) {
  if (rx_len >= sizeof(rx_buffer)) {
    rx_len = 0;
  }

  while (USBRadioLink.available()) {
    // Only what has actually arrived. readBytes() asks the Stream for the
    // full remaining buffer and blocks until it either fills it or its
    // one-second timeout expires, so a 26-octet telecommand cost a whole
    // second before it was even parsed. That is where the bench's "the board
    // answers on a 1 Hz tick" behaviour came from: it was not a tick, it was
    // this call waiting for octets that were never coming.
    size_t space = sizeof(rx_buffer) - rx_len;
    size_t avail = (size_t)USBRadioLink.available();
    size_t want = avail < space ? avail : space;
    if (want == 0) {
      break;
    }
    size_t n = USBRadioLink.readBytes(rx_buffer + rx_len, want);
    rx_len += n;

    size_t offset = 0;
    while (rx_len - offset >= HEADER_SIZE) {
      uint8_t *p = &rx_buffer[offset];

      if (p[0] != FRAME_HEADER_1 || p[1] != FRAME_HEADER_2) {
        offset++;
        continue;
      }

      uint16_t len = (p[2] << 8) | p[3];
      size_t total = HEADER_SIZE + len;

      if (len > MAX_FRAME_SIZE || len == 0) {
        offset += 2;
        continue;
      }

      if (rx_len - offset < total) {
        break;
      }

      if (usb_radio_cb) {
        usb_radio_cb(&p[HEADER_SIZE], len);
#if FLATSAT_USB_HEXDUMP
        // One Serial.printf per octet, on every frame the board receives.
        // Adafruit_USBD_CDC::write spins while the interface is connected and
        // its FIFO is full, so a console nobody is draining stops being slow
        // and starts being a halt: the board accepts commands and goes quiet
        // on both interfaces. Off in the course build, where twenty laptops
        // open the binary interface and leave the console shut.
        printHexDump(&p[HEADER_SIZE], len);
#endif
      }
      offset += total;
    }

    if (offset > 0) {
      memmove(rx_buffer, rx_buffer + offset, rx_len - offset);
      rx_len -= offset;
    }
  }
}