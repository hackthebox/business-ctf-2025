#!/usr/bin/python3

import ScapySMS
from sys import argv
from time import sleep


m = ScapySMS.Modem(argv[1])

m.readMSGS()

sleep(1)


message = "Payload intercepted, HTB{d33p_1n_5m5} They're using it to bypass detection. More soon."

sms = ScapySMS.SMSSubmit()
sms.TP_RP = 0
sms.TP_UDHI = 0
sms.TP_SRR = 0
sms.TP_VPF = 10
sms.TP_RD = 0
sms.TP_MTI = 1
sms.TP_MR = 0

myaddr = ScapySMS.Address()
myaddr.Type_of_number = 1 # International format, includes country code
myaddr.Digits = '13333333337'
sms.TP_DA = myaddr

sms.TP_PID = 0
sms.TP_DCS = 8 # UTF-16
sms.TP_VP = b'\x00' # 5 minutes
sms.TP_UD = message.encode('utf-16be')
sms.show2()

print('PDU hex: {}'.format(bytes(sms).hex()))

m.sendPDU(sms)