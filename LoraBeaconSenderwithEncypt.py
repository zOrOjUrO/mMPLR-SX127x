#!/usr/bin/env python

""" A beacon transmitter class to send 255-byte message in regular time intervals. """
"""
# Copyright 2015 Mayer Analytics Ltd.
#
# This file is part of pySX127x.
#
# pySX127x is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
# License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# pySX127x is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You can be released from the requirements of the license by obtaining a commercial license. Such a license is
# mandatory as soon as you develop commercial activities involving pySX127x without disclosing the source code of your
# own applications, or shipping pySX127x with a closed source product.
#
# You should have received a copy of the GNU General Public License along with pySX127.  If not, see
# <http://www.gnu.org/licenses/>.

# usage:
# python p2p_send.py -f 433 -b BW125 -s 12
"""

import sys 
from time import sleep
sys.path.insert(0, '../../pySX127x')        
from SX127x.LoRa import *
from SX127x.LoRaArgumentParser import LoRaArgumentParser
from SX127x.board_config import BOARD
from SecurePass import *



class LoRaBeacon(LoRa):

    tx_counter = 0
    PAYLD_SIZE = 200
    Password = '2bckr0w3'

    def __init__(self, verbose=False):
        super(LoRaBeacon, self).__init__(verbose)
        self.set_mode(MODE.SLEEP)
        self.set_dio_mapping([1,0,0,0,0,0])

    def on_rx_done(self):
        print("\nRxDone")
        print(self.get_irq_flags())
        print(map(hex, self.read_payload(nocheck=True)))
        self.set_mode(MODE.SLEEP)
        self.reset_ptr_rx()
        self.set_mode(MODE.RXCONT)
    
    def sendData(self, raw):
        data = [int(hex(ord(c)), 0) for c in raw]
        self.write_payload(data)
        BOARD.led_on()
        self.set_mode(MODE.TX)
        sleep(1)

    def chopNsendData(self, data):
        leng = len(data)
        i = 0
        for i in range(leng//self.PAYLD_SIZE):
            rawInput = data[i*self.PAYLD_SIZE: (i*self.PAYLD_SIZE)+self.PAYLD_SIZE]
            self.sendData(rawInput)

        if leng%self.PAYLD_SIZE != 0:
            rawInput = data[(leng//self.PAYLD_SIZE) * self.PAYLD_SIZE:]
            self.sendData(rawInput)
    
    def chopNsendEncryptedData(self, data):
        encryptedData = encrypt(data, self.Password)
        print(data + "\n" + encryptedData) #+"\n"decrypt(encryptedData,self.Password))
        self.chopNsendData(encryptedData)
        
    def on_tx_done(self):
        global args
        self.set_mode(MODE.STDBY)
        self.clear_irq_flags(TxDone=1)
        sys.stdout.flush()
        self.tx_counter += 1
        sys.stdout.write("\rtx #%d" % self.tx_counter)
        if args.single:
            print
            sys.exit(0)
        BOARD.led_off()
        sleep(args.wait)
        rawinput = input(">>> ")
        self.chopNsendEncryptedData(rawinput)
        """data = [int(hex(ord(c)), 0) for c in rawinput]
        #self.write_payload([0x0f])
        self.write_payload(data)
        BOARD.led_on()
        self.set_mode(MODE.TX)"""

    def on_cad_done(self):
        print("\non_CadDone")
        print(self.get_irq_flags())

    def on_rx_timeout(self):
        print("\non_RxTimeout")
        print(self.get_irq_flags())

    def on_valid_header(self):
        print("\non_ValidHeader")
        print(self.get_irq_flags())

    def on_payload_crc_error(self):
        print("\non_PayloadCrcError")
        print(self.get_irq_flags())

    def on_fhss_change_channel(self):
        print("\non_FhssChangeChannel")
        print(self.get_irq_flags())

    def set_payload_size(self, payloadSize: int):
        self.PAYLD_SIZE = payloadSize

    def start(self):
        global args
        sys.stdout.write("\rstart")
        self.tx_counter = 0
        BOARD.led_on()
        self.set_payload_size(200)
        self.write_payload([0x0f])
        #self.write_payload([0x0f, 0x65, 0x6c, 0x70])
        self.set_mode(MODE.TX)
        while True:
            sleep(1)

def getArgParser():
    parser = LoRaArgumentParser("A simple LoRa beacon")
    parser.add_argument('--single', '-S', dest='single', default=False, action="store_true", help="Single transmission")
    parser.add_argument('--wait', '-w', dest='wait', default=1, action="store", type=float, help="Waiting time between transmissions (default is 0s)")
    return parser

if __name__=="__main__":
    BOARD.setup()


    lora = LoRaBeacon(verbose=False)
    args = getArgParser().parse_args(lora)

    lora.set_pa_config(pa_select=1)
    lora.set_spreading_factor(7)
    lora.set_rx_crc(True)
    #lora.set_agc_auto_on(True)
    #lora.set_lna_gain(GAIN.NOT_USED)
    #lora.set_coding_rate(CODING_RATE.CR4_6)
    #lora.set_implicit_header_mode(False)
    #lora.set_pa_config(max_power=0x04, output_power=0x0F)
    #lora.set_pa_config(max_power=0x04, output_power=0b01000000)
    #lora.set_low_data_rate_optim(True)
    #lora.set_pa_ramp(PA_RAMP.RAMP_50_us)


    print(lora)
    #assert(lora.get_lna()['lna_gain'] == GAIN.NOT_USED)
    assert(lora.get_agc_auto_on() == 1)

    print("Beacon config:")
    print("  Wait %f s" % args.wait)
    print("  Single tx = %s" % args.single)
    print("")
    try: input("Press enter to start...")
    except: pass

    try:
        lora.start()
    except KeyboardInterrupt:
        sys.stdout.flush()
        print("")
        sys.stderr.write("KeyboardInterrupt\n")
    finally:
        sys.stdout.flush()
        print("")
        lora.set_mode(MODE.SLEEP)
        print(lora)
        BOARD.teardown()