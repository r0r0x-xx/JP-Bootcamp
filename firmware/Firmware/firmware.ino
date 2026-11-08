/*  - main.ino
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "led.h"
#include "radio_off.h"
#include "rdownlink.h"
#include "ruplink.h"
#include "sensors.h"
#include "spacecan.h"
#include "usbCDC.h"
#include "worker.h"

typedef struct {
  const unsigned long inverval;
  unsigned long previous;
} timeout_worker_t_t;

static timeout_worker_t_t t_tra = {.inverval = 5000, .previous = 0};

void setup() {
#if FLATSAT_NO_RADIO
  /* First thing, before anything can touch the SPI bus. */
  radioHoldInReset();
#endif
  obcSetupUSB();
  ledConfigure();
  obcConfigureCore0();
  sensorsConfigure();
#if !FLATSAT_NO_RADIO
  uplinkRadioConfigure();
  downlinkRadioConfigure();
  uplinkRadioRegisterCb(commandHandlerRadio);
#endif
  obcUSBPacketRecivedCallback(commandHandlerUSB);
  Serial.printf("[INFO] Radio: %s\r\n", FLATSAT_RADIO_STATE_STR);
  ledTurnWhite();
  delay(500);
  ledTurnOff();
}

void setup1() { obcConfigureCore1(); }

void loop() {
  gpsPoll();
#if !FLATSAT_NO_RADIO
  uplinkRadioCheckPacketReceived();
  downlinkRadioCheckTransmition();
#endif
  /* Still runs with the radio off: it builds the telemetry frames, and
   * transmitPacketRadioUSB() sends them over USB. Only the radio half goes. */
  telemetryRadioWorker();
  if (consoleSensorModeActive()) {
    telemetryDashboardWorker();
  }
  consoleWorker();
}

void loop1() { obcUSBRecv(); }
