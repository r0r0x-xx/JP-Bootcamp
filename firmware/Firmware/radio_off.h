/*  - radio_off.h
 *
 * Course build: the two SX1262 modules are held in reset and never configured.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_RADIO_OFF_H
#define FIRMWARE_RADIO_OFF_H

/* The radio default is OFF, which is a safety decision rather than a style one.
 *
 * `#if FLATSAT_NO_RADIO` treats an undefined macro as 0, so a build that
 * forgets the flag would otherwise produce a binary able to key both SX1262.
 * Day 2 of the course has students edit this source and rebuild, and a bare
 * `pio run` is what they type.
 *
 *   pio run                        course build, radio off
 *   pio run -e pico_tinyusb        radio on, and only because that
 *                                  environment passes -DFLATSAT_NO_RADIO=0
 *
 * Forgetting a flag fails safe. Enabling the radio takes a deliberate act.
 */
#ifndef FLATSAT_NO_RADIO
#define FLATSAT_NO_RADIO 1
#endif

#if FLATSAT_NO_RADIO

/* Drive both radios into reset and both antenna switches off, before anything
 * else runs. Call it first in setup().
 *
 * Compiling the radio calls out is not enough on its own: the chips would
 * still power up in their default state, and anything that reached RadioLib
 * later could key them. Holding RESET low keeps the SX1262 in reset for as
 * long as the board is powered, so it cannot modulate a carrier whatever the
 * firmware above it does. That is a property somebody can verify with a
 * spectrum analyser, which is the point. */
void radioHoldInReset(void);

/* What the version reply tells the ground, so the state is readable from the
 * console instead of taken on trust. */
#define FLATSAT_RADIO_STATE_STR "disabled (held in reset, course build)"

#else
#define FLATSAT_RADIO_STATE_STR "enabled"
#endif /* FLATSAT_NO_RADIO */

#endif // FIRMWARE_RADIO_OFF_H
