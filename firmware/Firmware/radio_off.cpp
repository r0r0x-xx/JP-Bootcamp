/*  - radio_off.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "radio_off.h"

#if FLATSAT_NO_RADIO
#include "pins.h"
#include <Arduino.h>

void radioHoldInReset(void) {
  /* RESET low, and keep it low. The SX1262 stays in reset while the board is
   * powered, so neither module can transmit or receive. */
  pinMode(PIN_RADIO0_RST, OUTPUT);
  digitalWrite(PIN_RADIO0_RST, LOW);
  pinMode(PIN_RADIO1_RST, OUTPUT);
  digitalWrite(PIN_RADIO1_RST, LOW);

  /* Antenna switches off as well. Belt and braces: even a module that somehow
   * came out of reset would not reach the antenna. */
  pinMode(PIN_RADIO0_ANT_SW, OUTPUT);
  digitalWrite(PIN_RADIO0_ANT_SW, LOW);
  pinMode(PIN_RADIO1_ANT_SW, OUTPUT);
  digitalWrite(PIN_RADIO1_ANT_SW, LOW);

  /* Chip selects high (deselected), so nothing on the shared SPI bus talks to
   * a radio by accident. */
  pinMode(PIN_RADIO0_NSS, OUTPUT);
  digitalWrite(PIN_RADIO0_NSS, HIGH);
  pinMode(PIN_RADIO1_NSS, OUTPUT);
  digitalWrite(PIN_RADIO1_NSS, HIGH);
}

#if FLATSAT_NO_RADIO_LIB
/* The IDS event builder reads these three when a frame's origin is radio.
 * On this build that cannot happen, so the values are never used; they exist
 * because ruplink.cpp is not compiled in and the linker still wants them.
 *
 * Keeping the signatures here is what lets the radio driver be left out of
 * the binary entirely rather than merely left uncalled. */
float uplinkRadioLastRssi(void) { return 0.0f; }
float uplinkRadioLastSnr(void) { return 0.0f; }
bool uplinkRadioLastCrcBad(void) { return false; }
#endif /* FLATSAT_NO_RADIO_LIB */

#endif /* FLATSAT_NO_RADIO */
